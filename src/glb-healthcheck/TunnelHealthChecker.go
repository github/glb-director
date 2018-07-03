/*
 * BSD 3-Clause License
 *
 * Copyright (c) 2018 GitHub.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * * Neither the name of the copyright holder nor the names of its
 *   contributors may be used to endorse or promote products derived from
 *   this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package main

import (
	"expvar"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/rs/xid"
	log "github.com/sirupsen/logrus"
	"net"
	"sync"
	"time"
)

var (
	gueCounters = expvar.NewMap("TunnelHealthChecker")
)

type TunnelHealthChecker struct {
	checkTimeout time.Duration

	sync.Mutex
	pendingChecks map[string]HealthResultStream
}

func (g *TunnelHealthChecker) Initialize(checkTimeout time.Duration) error {
	g.pendingChecks = make(map[string]HealthResultStream)
	g.checkTimeout = checkTimeout

	// IPv4 socket that only returns ICMP packets, but not further filtered unfortunately.
	icmp, err := net.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return err
	}

	// handle packet reception in the backround transparently
	go g.icmpReceiveLoop(icmp)

	return nil
}

// our response ICMP echo replies come directly to us via DSR, no encapsulation.
// we need to make sure we only listen to packets we sent (`ping` etc could be running)
// and we need to match that up to something we sent at most once.
// duplicate replies, unknown replies, or replies after a timeout are intentionally dropped.
func (g *TunnelHealthChecker) icmpReceiveLoop(icmp net.PacketConn) {
	logContext := log.WithFields(log.Fields{
		"checker": "gue",
	})

	logContext.Debug("Listening for ICMP packets")

	buf := make([]byte, 1024)
	for {
		n, addr, err := icmp.ReadFrom(buf)
		packetLogContext := logContext.WithFields(log.Fields{
			"icmpBytes":      n,
			"icmpRemoteAddr": addr,
			"icmpError":      err,
		})

		packetLogContext.Debug("Received ICMP packet")
		gueCounters.Add("PacketsReceived", 1)

		if err != nil {
			continue
		}

		packet := gopacket.NewPacket(buf[0:n], layers.LayerTypeICMPv4, gopacket.Default)
		if icmpLayer := packet.Layer(layers.LayerTypeICMPv4); icmpLayer != nil {
			icmp, _ := icmpLayer.(*layers.ICMPv4)

			if icmp.TypeCode.Type() != layers.ICMPv4TypeEchoReply {
				gueCounters.Add("PacketsNotEchoReply", 1)
				continue // not a packet we care about
			}

			gueCounters.Add("PacketsReceivedEchoReply", 1)

			// conveniently we shoved our unique identifier as the entire payload
			checkIdentifier := string(icmp.Payload)

			// guaranteed to only return once, to the first caller, so if we get a channel
			// we know we're meant to send to it.
			resultChannel := g.getCheckCompletionChannel(checkIdentifier)
			if resultChannel == nil {
				packetLogContext.WithFields(log.Fields{
					"checkIdentifier": checkIdentifier,
					"wasPending":      false,
				}).Debug("Got ICMP echo reply, but check was already completed / timed out")

				gueCounters.Add("PacketsReceivedTooLate", 1)

				continue
			}

			result := HealthResult{
				Healthy: true,
				Failure: "",
			}

			packetLogContext.WithFields(log.Fields{
				"checkIdentifier": checkIdentifier,
				"wasPending":      true,
				"result":          result,
			}).Debug("Got ICMP echo reply, passing on result")

			gueCounters.Add("PacketsReceivedSuccess", 1)

			// run this async so we don't block this loop on downstream,
			// since this is in the packet flow path for all ICMP reply targets.
			go func() {
				resultChannel <- result
			}()
		}
	}
}

// send out our encapsulated ICMP ping. tunnel it inside a GUE packet
func (g *TunnelHealthChecker) CheckTarget(resultChannel HealthResultStream, target HealthCheckTarget) {
	logContext := log.WithFields(log.Fields{
		"checker":    "gue",
		"checkType":  target.CheckType,
		"targetIp":   target.Ip,
		"targetPort": target.Port,
	})

	logContext.Debug("Sending ICMP echo request over GUE tunnel")

	addr, err := net.ResolveUDPAddr("udp4", fmt.Sprintf("%s:%d", target.Ip, target.Port))
	if err != nil {
		gueCounters.Add("ResolveFailure", 1)
		resultChannel <- HealthResult{
			Healthy: false,
			Failure: err.Error(),
		}
		return
	}

	udp, err := net.DialUDP("udp4", nil, addr)
	if err != nil {
		gueCounters.Add("DialFailure", 1)
		resultChannel <- HealthResult{
			Healthy: false,
			Failure: err.Error(),
		}
		return
	}
	defer udp.Close()

	// mark this check as pending, and give us a unique identifier to map back with
	checkIdentifier := g.createPendingCheck(resultChannel)

	logContext = logContext.WithFields(log.Fields{
		"checkIdentifier": checkIdentifier,
	})

	// linux will do the work on the outer UDP/IP part of the packet,
	// but inside that we'll need to create the ICMP/IP/(GUE|GRE) part.
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	gopacket.SerializeLayers(buf, opts,
		&layers.IPv4{
			Version:  4,
			TTL:      255,
			Id:       0,
			Protocol: layers.IPProtocolICMPv4,
			Flags:    layers.IPv4DontFragment,
			SrcIP:    udp.LocalAddr().(*net.UDPAddr).IP,
			DstIP:    addr.IP,
		},
		&layers.ICMPv4{
			TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0),
		},
		gopacket.Payload([]byte(checkIdentifier)))

	encapHeader, err := buf.PrependBytes(8)
	if err != nil {
		gueCounters.Add("PrependFailure", 1)
		resultChannel := g.getCheckCompletionChannel(checkIdentifier)
		resultChannel <- HealthResult{
			// this is an internal error in healthchecking, so fail-open
			// since this essentially means we can't test this proxy via tunnel.
			Healthy: true,
			Failure: err.Error(),
		}
		return
	}

	if target.CheckType == "fou" {
		// legacy FOU with GRE inside
		encapHeader[0] = 0x20 // key present (where we encode the IP)
		encapHeader[1] = 0x00
		encapHeader[2] = 0x08 // ether protocol (0x8000 - IPv4)
		encapHeader[3] = 0x00
		encapHeader[4] = 0x00 // alternate service IP, unused in health checks
		encapHeader[5] = 0x00
		encapHeader[6] = 0x00
		encapHeader[7] = 0x00
	} else {
		// new implementation using GUE and private data.
		encapHeader[0] = 1 // VVCHHHHH - version=0, control_msg=0, hlen=1
		encapHeader[1] = 4 // IP protocol - IPv4
		encapHeader[2] = 0 // flags
		encapHeader[3] = 0 // flags
		encapHeader[4] = 0 // GLB Private Data, type = 0
		encapHeader[5] = 0 //
		encapHeader[6] = 0 // next hop idx
		encapHeader[7] = 0 // hop count
	}

	packetData := buf.Bytes()

	// run a timeout routine, if the ping happens before this timeout
	// the resultChannel will be nil and we just complete quietly.
	go func() {
		time.Sleep(g.checkTimeout)

		resultChannel := g.getCheckCompletionChannel(checkIdentifier)
		if resultChannel != nil {
			gueCounters.Add("Timeouts", 1)
			resultChannel <- HealthResult{
				Healthy: false,
				Failure: "No response received within timeout window",
			}
		}
	}()

	// actually send the ICMP echo request
	_, err = udp.Write(packetData)
	if err == nil {
		gueCounters.Add("PacketsSent", 1)
	} else {
		gueCounters.Add("PacketsSendFailure", 1)
	}
}

// stores the result stream (channel) along with a unique ID that we'll use to keep track
func (g *TunnelHealthChecker) createPendingCheck(resultChannel HealthResultStream) string {
	checkIdentifier := "glbhc_" + xid.New().String()

	g.Lock()
	g.pendingChecks[checkIdentifier] = resultChannel
	g.Unlock()

	return checkIdentifier
}

// given the check ID (from above), returns the result stream to exactly the first caller.
// every other caller will get nil, and no storage is used after the first call completes.
func (g *TunnelHealthChecker) getCheckCompletionChannel(checkIdentifier string) HealthResultStream {
	g.Lock()
	defer g.Unlock()

	if completionCh, ok := g.pendingChecks[checkIdentifier]; ok {
		// mark the check as completed
		delete(g.pendingChecks, checkIdentifier)
		return completionCh
	}

	return nil
}
