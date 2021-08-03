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
	log "github.com/sirupsen/logrus"
	"net/http"
	"time"
)

var (
	httpCounters = expvar.NewMap("HttpHealthChecker")
)

type HttpHealthChecker struct {
	checkTimeout time.Duration
}

// runs an HTTP GET on a given URL and returns a one-shot result stream
// that will be given a HealthResult once completed. the timeouts here are
// from http.Get, the caller will handle the shorter check interval timeout
// for simplicity.
func httpCheckURL(url string, timeoutSec time.Duration) HealthResultStream {
	ch := make(HealthResultStream, 1)

	go func() {
		httpCounters.Add("Checks", 1)
		var httpClient = &http.Client {
			Timeout: timeoutSec,
		}
		resp, err := httpClient.Get(url)
		if err != nil {
			ch <- HealthResult{Healthy: false, Failure: err.Error()}
			close(ch)
			httpCounters.Add("CheckFailedError", 1)
			return
		}

		resp.Body.Close()
		if resp.StatusCode == 200 {
			ch <- HealthResult{Healthy: true, Failure: ""}
			httpCounters.Add("CheckOk", 1)
		} else {
			ch <- HealthResult{Healthy: false, Failure: fmt.Sprintf("HTTP server responded with %d, expecting 200.", resp.StatusCode)}
			httpCounters.Add("CheckFailedStatus", 1)
		}
		close(ch)
	}()

	return ch
}

func (h *HttpHealthChecker) Initialize(checkTimeout time.Duration) error {
	h.checkTimeout = checkTimeout

	return nil
}

func (h *HttpHealthChecker) CheckTarget(resultChannel HealthResultStream, target HealthCheckTarget) {
	logContext := log.WithFields(log.Fields{
		"checker":    "http",
		"checkType":  target.CheckType,
		"targetIp":   target.Ip,
		"targetPort": target.Port,
	})

	go func() {
		logContext.Debug("Sending HTTP request to health check port")
		resultCh := httpCheckURL(fmt.Sprintf("http://%s:%d%s", target.Ip, target.Port, target.Uri), h.checkTimeout)

		// either receive the successful result, or time out and craft an error result.
		var result HealthResult
		select {
		case r := <-resultCh:
			result = r
		case <-time.After(h.checkTimeout):
			result = HealthResult{Healthy: false, Failure: fmt.Sprintf("No response received within HTTP check timeout of %d", h.checkTimeout)}
			httpCounters.Add("CheckTimeout", 1)
		}

		logContext.WithFields(log.Fields{
			"healthy":       result.Healthy,
			"healthFailure": result.Failure,
		}).Debug("HTTP health check result completed")

		// pass on the result directly to the caller's channel
		resultChannel <- result
	}()
}
