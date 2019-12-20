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
	"context"
	"errors"
	"expvar"
	"fmt"
	"github.com/golang/protobuf/ptypes"
	"github.com/golang/protobuf/ptypes/any"
	gobgpapi "github.com/osrg/gobgp/api"
	"github.com/osrg/gobgp/pkg/packet/bgp"
	"github.com/sirupsen/logrus"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"io"
	"net"
	"regexp"
	"strconv"
	"sync"
	"time"
)

var (
	// announceCounters counters specific to the health check announce
	announceCounters = expvar.NewMap("HealthCheckerAnnounce")
	// regexpCommunity
	regexpCommunity = regexp.MustCompile(`(\d+):(\d+)`)
)


const (
	// AnnounceMaxReconnectDelay maximum reconnect delay for gRPC back off, prevents long wait times to reconnect
	AnnounceMaxReconnectDelay = time.Millisecond * 100
)

// GoBGPConfig configuration to connect to GoBGP
type GoBGPConfig struct {
	Address     string `json:"address"`       // Address and port for connecting to GoBGP
	NextHop     string `json:"nexthop"`       // next hop IP address to use for routes
	NextHopIPv6 string `json:"nexthop_ipv6"`  // next hop address for IPv6
	Communities []string `json:"communities"` // communities used to export routes
}

// Binds map of binds with useful metadata that describes more information about the bind/vips
type Binds map[string]*BindMeta

// BindMeta bind metadata to simplify usage of binds/vip to calculated data
type BindMeta struct {
	BindIP    string // BindIP the IP address of the Bind/VIP
	IPVersion int    // IP protocol version supported
	BitMask   string // The bitmask length to announce
	Path      string // Path path or host route to announce
	NextHop   string // Next hop associated with the bind
}

// NewBindMeta creates an initialized bind meta
func NewBindMeta(ipAddr string) (bm *BindMeta, err error) {

	bm = &BindMeta{BindIP: ipAddr}

	bm.IPVersion, err = ipVersion(ipAddr)
	if err != nil {
		return bm, err
	}

	// set to announce host routes for the VIP
	// this could be configurable in the future
	switch bm.IPVersion {
	case 4:
		bm.BitMask = "32"
	case 6:
		bm.BitMask = "128"
	}

	// calculate the path/prefix that will be announced
	bm.Path = fmt.Sprintf("%s/%s", bm.BindIP, bm.BitMask)

	return bm, nil
}

// AnnounceRuntime used to measure the run time of an announce step
// created to be compatible with the expvar.Var interface
type AnnounceRuntime struct {
	value time.Duration
}

// NewAnnounceRuntime create new announce runtime
func NewAnnounceRuntime(runTime time.Duration) *AnnounceRuntime {
	return &AnnounceRuntime{value: runTime}
}

// String return the string value of the runtime duration
func (ar *AnnounceRuntime) String() string {
	return fmt.Sprintf("%s", strconv.FormatInt(ar.value.Nanoseconds(), 10))
}

// HealthCheckerAnnounce allows for announcing the status of a VIP as a BGP route
type HealthCheckerAnnounce struct {
	clientOpt  []grpc.DialOption  // clientOpt gRPC client options to communicate with the local GoBGP daemon
	logContext *logrus.Entry      // Logging context for logging output
	config     *GoBGPConfig       // Config elements required to configure interaction with GoBGP
	activeRoutes map[string]Binds // Keeping track of actively announced binds by table, useful for revoking removed binds

	sync.Mutex                    // locking used to prevent multiple instances of the route update loop from running at once
	enabled bool                  // enabled a simple bool to determine if the announce feature is configured to run
}

// NewHealthCheckerAnnounce creates a new instance of HealthCheckerAnnounce
func NewHealthCheckerAnnounce(config *GoBGPConfig, log *logrus.Entry) (*HealthCheckerAnnounce, error) {
	hca := &HealthCheckerAnnounce{logContext: log,
		config: config,
		activeRoutes: make(map[string]Binds)}

	if hca.config.Address == "" {
		hca.logContext.Errorf("Address for BGP client is not defined, disabling feature")

		hca.enabled = false

		return hca, nil
	} else {
		hca.enabled = true
	}

	// Create base gRPC connection options
	hca.clientOpt = []grpc.DialOption{grpc.WithBlock()}

	// set max back off delay
	hca.clientOpt = append(hca.clientOpt, grpc.WithBackoffMaxDelay(AnnounceMaxReconnectDelay))

	// Connect without TLS, TLS to GoBGP is only really useful between hosts
	hca.clientOpt = append(hca.clientOpt, grpc.WithInsecure())

	// Specify TLS isn't enable to the local GoBGP daemon
	announceCounters.Add("TLSDisabled", 1)
	// Specify the config has been successfully loaded
	announceCounters.Add("ConfigLoaded", 1)

	return hca, nil
}

// gobgpConnect connect to the local GoBGP daemon
func (hca *HealthCheckerAnnounce) gobgpConnect() (gobgpapi.GobgpApiClient, *grpc.ClientConn ,error) {

	cc, _ := context.WithTimeout(context.Background(), time.Second)
	conn, err := grpc.DialContext(cc, hca.config.Address, hca.clientOpt...)
	if err != nil {
		return nil, conn, err
	}

	// initialize client
	client := gobgpapi.NewGobgpApiClient(conn)

	return client, conn, err
}

// Announce announce healthy paths via GoBGP
func (hca *HealthCheckerAnnounce) Announce(ft *GLBTableConfig, targetResults map[HealthCheckTarget]HealthResult) error {

	// Time execution of announce loop to ensure we aren't stuck or hitting errors
	startTime := time.Now()
	defer func() {
		announceCounters.Set("LastAnnounceExecTime", NewAnnounceRuntime(time.Since(startTime)))
	}()

	// Lock to limit to once announce running at a time
	hca.Lock()
	defer hca.Unlock()

	// Track all binds across tables
	globalBinds := make(map[string]Binds)

	// process each table and check the current health check results of its binds
	for _, table := range ft.Tables {

		// track the health state for a table
		tableNumHealthy := 0
		tableNumUnhealthy := 0

		// create a map of binds for a table
		bindList := make(Binds)

		// get all of the binds for a table and calculate their next hop that we would announce
		// these will be announced if all the backends for a bind are healthy
		for _, bind := range table.Binds {

			// create new metadata based upon the bind
			newBindMeta, err := NewBindMeta(bind.Ip)
			if err != nil {
				hca.logContext.WithFields(log.Fields{
					"bind": bind.Ip,
				}).Errorf("Error generating bind metadata: %s", err)

				announceCounters.Add("BindIPParseError", 1)

				// something is wrong with the bind address, skip announcing it
				continue
			}

			// calculate the bind next hop
			newBindMeta.NextHop, err = hca.getNextHop(newBindMeta.IPVersion)
			if err != nil {
				hca.logContext.WithFields(log.Fields{
					"bind": bind.Ip,
					"table": table.Name,
				}).Errorf("Error determining bind next hop: %s", err)

				announceCounters.Add("PathNextHopResolveError", 1)

				// error determining next hop, skip
				continue
			}

			// record bind we want to announce
			bindList[bind.Ip] = newBindMeta

			// record global bind so we can track if the bind gets removed and we need to reap the route
			if _, ok := globalBinds[table.Name]; !ok {
				globalBinds[table.Name] = make(Binds)
			}
			globalBinds[table.Name][bind.Ip] = newBindMeta

		}

		// get all of the backends and determine if the bind is healthy or not based upon the state of its backends
		for _, backend := range table.Backends {

			// if a backend state is marked as inactive lets consider it removed, in GLB director it will still process
			// a bind where all backends are set to inactive. This allows us to withdraw a path when all backends in a
			// table are set to inactive.
			if backend.State == "inactive" {
				continue
			}

			// count all the healthy backends to determine if the table is healthy or not
			successes := 0
			failures := 0
			for _, target := range backend.HealthTargets() {
				if targetResults[target].Healthy {
					successes++
				} else {
					failures++
				}
			}

			healthy := failures == 0

			if healthy {
				tableNumHealthy += 1
			} else {
				tableNumUnhealthy += 1
			}
		}

		// take actions based on the state of the bind's backends
		if tableNumHealthy == 0 {
			// withdraw route for unhealthy binds
			for k := range bindList {

				// delete the annouced path from GoBGP daemon
				if err := hca.DeletePath(bindList[k].Path, bindList[k].NextHop); err != nil {
					hca.logContext.WithFields(log.Fields{
						"bind":    k,
						"nextHop": bindList[k].NextHop,
						"table": table.Name,
					}).Errorf("Error removing route: %s", err)

					// error deleting bind, skip
					continue
				}

				// remove route from active routes
				if _, ok := hca.activeRoutes[table.Name]; !ok {
					hca.activeRoutes[table.Name] = make(Binds)
				} else {
					delete(hca.activeRoutes[table.Name], k)
				}

				hca.logContext.WithFields(log.Fields{
					"bind":    k,
					"nextHop": bindList[k].NextHop,
					"table": table.Name,
					"action": "delete",
				}).Debug("Removed path for bind")

			}

		} else {
			// inject route for healthy are partially healthy binds
			for k := range bindList {

				// announce path to the GoBGP daemon
				if _, err := hca.AddPath(bindList[k].Path, bindList[k].NextHop); err != nil {
					hca.logContext.WithFields(log.Fields{
						"bind":    k,
						"nextHop": bindList[k].NextHop,
						"table": table.Name,
					}).Errorf("Error announcing route: %s", err)

					// error announcing bind, skip
					continue
				}

				// store active route in the event it is removed from the table
				if _, ok := hca.activeRoutes[table.Name]; !ok {
					hca.activeRoutes[table.Name] = make(Binds)
				}
				hca.activeRoutes[table.Name][bindList[k].BindIP] = bindList[k]

				hca.logContext.WithFields(log.Fields{
					"bind":    k,
					"nextHop": bindList[k].NextHop,
					"table": table.Name,
					"action": "add",
				}).Debug("Announced path for bind")

			}
		}
	}

	// delete any old routes with binds that are no longer in the config
	// TODO: Can we query GoBGP and reap any non-configured paths? Today we allow users to configure routes independently so this is not currently configured
	for tableName, binds := range hca.activeRoutes {
		for k, v := range binds {
			// bind with active route no longer part of global binds
			if _, ok := globalBinds[tableName][k]; !ok {

				// If we find that a previous bind is no longer found the path is deleted
				if err := hca.DeletePath(v.Path, v.NextHop); err != nil {
					hca.logContext.WithFields(log.Fields{
						"bind":    k,
						"nextHop": v.NextHop,
						"table": tableName,
					}).Errorf("Error removing route: %s", err)

					// error deleting bind, skip
					continue
				}

				// remove route from active routes
				delete(hca.activeRoutes[tableName], k)

				hca.logContext.WithFields(log.Fields{
					"bind":    k,
					"nextHop": v.NextHop,
					"table": tableName,
					"action": "delete",
				}).Debug("Bind removed from forwarding table, deleting route")
			}
		}
	}

	return nil
}

// ListPaths list paths for a specific address family
func (hca *HealthCheckerAnnounce) ListPaths(ipVersion int) ([]*gobgpapi.Destination, error) {

	client, conn, err := hca.gobgpConnect()
	if err != nil {
		return nil, err
	}
	defer func () {
		err := conn.Close()
		if err != nil {
			hca.logContext.WithFields(log.Fields{
				"gobgp":    "connection error",
			}).Debug(err)
		}
	}()

	// determine which route announcement type we want to look up
	var afi gobgpapi.Family_Afi
	switch ipVersion {
	case 4:
		afi = gobgpapi.Family_AFI_IP
	case 6:
		afi = gobgpapi.Family_AFI_IP6
	}

	// only request unicast safis
	stream, err := client.ListPath(context.Background(), &gobgpapi.ListPathRequest{
		Family: &gobgpapi.Family{
			Afi:  afi,
			Safi: gobgpapi.Family_SAFI_UNICAST,
		},
	})
	if err != nil {
		return nil, err
	}

	l := make([]*gobgpapi.Destination, 0, 1024)
	for {
		r, err := stream.Recv()
		if err == io.EOF {
			break
		} else if err != nil {
			return l, err
		}
		l = append(l, r.Destination)
	}

	return l, err
}

// AddPath add a new path to the route table
func (hca *HealthCheckerAnnounce) AddPath(prefix, nextHop string) ([]byte, error) {

	client, conn, err := hca.gobgpConnect()
	if err != nil {
		return nil, err
	}
	defer func () {
		err := conn.Close()
		if err != nil {
			hca.logContext.WithFields(log.Fields{
				"gobgp":    "connection error",
			}).Debug(err)
		}
	}()

	// create the path struct with all of the correct settings
	path, err := hca.generatePath(prefix, nextHop, 1)
	if err != nil {
		announceCounters.Add("RouteAddError", 1)
		return []byte{}, err
	}

	// define the path request we will send to the GoBGP daemon
	pathRequest := &gobgpapi.AddPathRequest{
		TableType: gobgpapi.TableType_GLOBAL, // use the default global table
		VrfId:     "",                        // TODO: do not use a VRF, may be enabled in the future
		Path:      path,
	}

	stream, err := client.AddPath(context.Background(), pathRequest)
	if err != nil {
		announceCounters.Add("RouteAddError", 1)
		return []byte{}, err
	}

	announceCounters.Add("RouteAddSent", 1)
	return stream.GetUuid(), err
}

// DeletePath remove a path from the route table
func (hca *HealthCheckerAnnounce) DeletePath(prefix, nextHop string) error {

	client, conn, err := hca.gobgpConnect()
	if err != nil {
		return err
	}
	defer func () {
		err := conn.Close()
		if err != nil {
			hca.logContext.WithFields(log.Fields{
				"gobgp":    "connection error",
			}).Debug(err)
		}
	}()

	// Generate a path for the delete path request
	path, err := hca.generatePath(prefix, nextHop, 1)
	if err != nil {
		announceCounters.Add("RouteDeleteError", 1)
		return err
	}

	pathRequest := &gobgpapi.DeletePathRequest{
		TableType: gobgpapi.TableType_GLOBAL, // use the default global table
		VrfId:     "",                        // TODO: do not use a VRF, may be enabled in the future
		Path:      path,
	}

	_, err = client.DeletePath(context.Background(), pathRequest)
	if err != nil {
		announceCounters.Add("RouteDeleteError", 1)
		return err
	}

	announceCounters.Add("RouteDeleteSent", 1)
	return nil
}

// ListPeers list BGP neighbors
func (hca *HealthCheckerAnnounce) ListPeers() ([]*gobgpapi.Peer, error) {

	client, conn, err := hca.gobgpConnect()
	if err != nil {
		return nil, err
	}
	defer func () {
		err := conn.Close()
		if err != nil {
			hca.logContext.WithFields(log.Fields{
				"gobgp":    "connection error",
			}).Debug(err)
		}
	}()

	// Fetch all of the currently configured peers/neighbors
	stream, err := client.ListPeer(context.Background(), &gobgpapi.ListPeerRequest{})
	if err != nil {
		return nil, err
	}

	l := make([]*gobgpapi.Peer, 0, 1024)
	for {
		r, err := stream.Recv()
		if err == io.EOF {
			break
		} else if err != nil {
			return l, err
		}
		l = append(l, r.Peer)
	}

	return l, nil
}

// getNextHop returns the correct next hop based upon the provided configuration file
func (hca *HealthCheckerAnnounce) getNextHop(ipVersion int) (string, error) {
	switch ipVersion {
	case 4:
		if  hca.config.NextHop != "" {
			return hca.config.NextHop, nil
		}
	case 6:
		if hca.config.NextHopIPv6 != "" {
			return hca.config.NextHopIPv6, nil
		}
	}

	// If the next hop isn't configured in the daemon return an error
	return "", errors.New("unable to determine next hop IP version")
}

// generatePath generates a gobgp path
// IPv6 paths can incorrectly allow IPv4 next hops, https://github.com/cloudnativelabs/kube-router/issues/605, this is prevented
func (hca *HealthCheckerAnnounce) generatePath(prefix, nextHop string, identifier uint32) (*gobgpapi.Path, error) {

	// Parse the prefix so we can determine more details about the IP Prefix
	ipAddr, ipNet, err := net.ParseCIDR(prefix)
	if err != nil {
		return nil, err
	}

	// Parse the next hop
	nextHopIpAddr := net.ParseIP(nextHop)

	// Determine the route family we want to announce
	var routeFamily uint16
	if isV4(ipAddr) {
		routeFamily = uint16(gobgpapi.Family_AFI_IP)
	} else if isV6(ipAddr) {
		routeFamily = uint16(gobgpapi.Family_AFI_IP6)
	} else {
		return nil, errors.New("unable to determine IP protocol Version")
	}

	// Create NLRI
	var newNLRI *any.Any
	maskLen, _ := ipNet.Mask.Size()
	newNLRI, _ = ptypes.MarshalAny(&gobgpapi.IPAddressPrefix{
		Prefix:    ipAddr.String(),
		PrefixLen: uint32(maskLen),
	})

	// Create attribute slice
	pattrs := make([]*any.Any,0)

	// Create the correct NextHopAttr based on route protocol
	var nextHopAttr *any.Any
	// generate IPv6 NRLIs
	if isV6(nextHopIpAddr) {
		if routeFamily != uint16(gobgpapi.Family_AFI_IP6) {
			return nil, errors.New("unable to set IPv6 next hop for IPv4 prefix")
		}

		// create a IPv6 multi-protocol NRLI
		nextHopAttr, _ = ptypes.MarshalAny(&gobgpapi.MpReachNLRIAttribute{
			Family: &gobgpapi.Family{
				Afi:  gobgpapi.Family_Afi(routeFamily),
				Safi: gobgpapi.Family_SAFI_UNICAST,
			},
			NextHops: []string{nextHopIpAddr.String()},
			Nlris:    []*any.Any{newNLRI},
		})

		// add to attributes list
		pattrs = append(pattrs, nextHopAttr)

	// generate IPv4 NRLIs
	} else if isV4(nextHopIpAddr) {
		if routeFamily != uint16(gobgpapi.Family_AFI_IP) {
			return nil, errors.New("unable to set IPv4 next hop for IPv6 prefix")
		}

		nextHopAttr, _ = ptypes.MarshalAny(&gobgpapi.NextHopAttribute{
			NextHop: nextHopIpAddr.String(),
		})

		// add to attributes list
		pattrs = append(pattrs, nextHopAttr)
	} else {
		return nil, errors.New("unable to determine IP protocol for next hop")
	}

	// Create the route origin type
	var originAttr *any.Any
	originAttr, _ = ptypes.MarshalAny(&gobgpapi.OriginAttribute{
		Origin: uint32(bgp.BGP_ORIGIN_ATTR_TYPE_IGP),
	})
	pattrs = append(pattrs, originAttr)

	// Add any required communities to the route
	if len(hca.config.Communities) > 0 {
		comms := make([]uint32, 0, 1)

		for _, v := range hca.config.Communities {
			c, err := hca.parseCommunity(v)
			if err != nil {
				// error parsing community
				hca.logContext.WithFields(log.Fields{
					"community":    v,
				}).Debug(err)

				continue
			}
			comms = append(comms, c)
		}

		commsAttr, _ := ptypes.MarshalAny(&gobgpapi.CommunitiesAttribute{
			Communities: comms,
		})

		pattrs = append(pattrs, commsAttr)
	}

	// Return the correctly generated path
	return &gobgpapi.Path{
		Pattrs: pattrs,
		Nlri:   newNLRI,
		Family: &gobgpapi.Family{
			Afi:  gobgpapi.Family_Afi(routeFamily),
			Safi: gobgpapi.Family_SAFI_UNICAST,
		},
		Identifier: identifier,
	}, nil
}

// parseCommunity parse a community string and return its value as the required uint32
func (hca *HealthCheckerAnnounce) parseCommunity(arg string) (uint32, error) {
	i, err := strconv.ParseUint(arg, 10, 32)
	if err == nil {
		return uint32(i), nil
	}

	elems := regexpCommunity.FindStringSubmatch(arg)
	if len(elems) == 3 {
		fst, _ := strconv.ParseUint(elems[1], 10, 16)
		snd, _ := strconv.ParseUint(elems[2], 10, 16)
		return uint32(fst<<16 | snd), nil
	}
	for i, v := range bgp.WellKnownCommunityNameMap {
		if arg == v {
			return uint32(i), nil
		}
	}
	return 0, errors.New("failed to parse %s as community")
}

// helper functions

// ipVersion return the IP protocol version
func ipVersion(ip string) (int, error) {

	ipAddr := net.ParseIP(ip)

	if isV4(ipAddr) {
		return 4, nil
	} else if isV6(ipAddr) {
		return 6, nil
	} else {
		return 0, errors.New("unable to determine IP protocol Version")
	}
}

// isV4 tests if the IP is IPv4
func isV4(ip net.IP) bool {
	if ip.To4() != nil {
		return true
	}
	return false
}

// isV6 tests if the IP is IPv6
func isV6(ip net.IP) bool {
	if ip.To4() == nil {
		return true
	}
	return false
}