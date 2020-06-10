/*
 * BSD 3-Clause License
 *
 * Copyright (c) 2019 Roblox Corporation.
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
	log "github.com/sirupsen/logrus"
	"net"
	"time"
)

var (
	tcpCounters = expvar.NewMap("TcpHealthChecker")
)

type TcpHealthChecker struct {
	checkTimeout time.Duration
}

func OpenConnection(resultChannel HealthResultStream, ip_port string) HealthResultStream {
	ch := make(HealthResultStream, 1)

	go func() {
		c, err := net.Dial("tcp", ip_port)
		if err != nil {
			ch <- HealthResult{Healthy: false, Failure: err.Error()}
			tcpCounters.Add("CheckFailedStatus", 1)
		} else {
			ch <- HealthResult{Healthy: true, Failure: ""}
			tcpCounters.Add("CheckOK", 1)
			c.Close()
		}
		close(ch)
	}()

	return ch
}

//
// Attempt to open a TCP connection to the specified ip:port.
// If the connection can be opened, the remote endpoint is considered healthy
//
func (t *TcpHealthChecker) Initialize(checkTimeout time.Duration) error {
	t.checkTimeout = checkTimeout

	return nil
}

func (t *TcpHealthChecker) CheckTarget(resultChannel HealthResultStream,
	target HealthCheckTarget) {
	logContext := log.WithFields(log.Fields{
		"checker":    "tcp",
		"checkType":  target.CheckType,
		"targetIp":   target.Ip,
		"targetPort": target.Port,
	})

	go func() {
		logContext.Debug("Sending TCP connection request")
		resultCh := OpenConnection(resultChannel, fmt.Sprintf("%s:%d", target.Ip, target.Port))

		var result HealthResult
		select {
		case r := <-resultCh:
			result = r
		case <-time.After(t.checkTimeout):
			result = HealthResult{Healthy: false, Failure: fmt.Sprintf("No response received within TCP check timeout of %d", t.checkTimeout)}
			tcpCounters.Add("CheckTimeout", 1)
		}

		logContext.WithFields(log.Fields{
			"healthy":       result.Healthy,
			"healthFailure": result.Failure,
		}).Debug("TCP health check result completed")

		// pass on the result directly to the caller's channel
		resultChannel <- result
	}()
}
