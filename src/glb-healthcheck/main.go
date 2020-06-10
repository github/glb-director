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
	"github.com/docopt/docopt-go"
	log "github.com/sirupsen/logrus"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

const (
	// timeout should be < interval
	DefaultHealthCheckTimeout  = 1 * time.Second
	DefaultHealthCheckInterval = 2 * time.Second
)

// Default values for the marking-thresholds for marking backends (un)healthy
const (
	DefaultSuccessesBeforeMarkedHealthy = 3
	DefaultFailuresBeforeMarkedFailed = 3
)

func main() {
	usage := `GLB Director->Proxy Healthcheck Service

Usage:
  glb-healthcheck --config=<config>
  glb-healthcheck -h | --help

Options:
  -h --help            Show this screen.
  --config=<config>    Specify the configuration file for this service
`

	arguments, _ := docopt.Parse(usage, nil, true, "GLB Director->Proxy Healthcheck Service", false)

	log.SetOutput(os.Stdout)
	log.SetLevel(log.DebugLevel)

	ctx := &HealthCheckerAppContext{dirty: true, nextAllowedDirtyClear: time.Now()}
	ctx.logContext = log.WithFields(log.Fields{
		"app": "glb-healthcheck",
	})

	// load the configuration file, and fail hard if we can't
	err := ctx.LoadConfig(arguments["--config"].(string))
	if err != nil {
		ctx.logContext.Fatalf("Could not load configuration file: %s\n", err)
		return
	}

	// load up the forwarding table and register all the check targets
	err = ctx.LoadForwardingTable()
	if err != nil {
		ctx.logContext.Fatalf("Could not load initial forwarding table: %v", err)
		return
	}
	
	healthCheckTimeout := DefaultHealthCheckTimeout
	if ctx.forwardingTableConfig.HealthcheckGlobalCfg != nil &&
		ctx.forwardingTableConfig.HealthcheckGlobalCfg.TimeoutMilliSec != 0 {
		healthCheckTimeout = ctx.forwardingTableConfig.HealthcheckGlobalCfg.TimeoutMilliSec * time.Millisecond
	}

	healthCheckInterval := DefaultHealthCheckInterval
	if ctx.forwardingTableConfig.HealthcheckGlobalCfg != nil &&
		ctx.forwardingTableConfig.HealthcheckGlobalCfg.IntervalMilliSec != 0 {
		healthCheckInterval = ctx.forwardingTableConfig.HealthcheckGlobalCfg.IntervalMilliSec * time.Millisecond
	}

	successesBeforeMarkedHealthy := DefaultSuccessesBeforeMarkedHealthy
	failuresBeforeMarkedFailed := DefaultFailuresBeforeMarkedFailed
	if ctx.forwardingTableConfig.HealthcheckGlobalCfg != nil &&
		ctx.forwardingTableConfig.HealthcheckGlobalCfg.Trigger != 0 {
		successesBeforeMarkedHealthy = ctx.forwardingTableConfig.HealthcheckGlobalCfg.Trigger
		failuresBeforeMarkedFailed   = ctx.forwardingTableConfig.HealthcheckGlobalCfg.Trigger
	}

	// the check manager will run the HC loop and manage most of the HC part of the work
	ctx.checkManager = NewHealthCheckManager(healthCheckTimeout, healthCheckInterval, successesBeforeMarkedHealthy,
		failuresBeforeMarkedFailed)

	err = ctx.SyncBackendsToCheckManager()
	if err != nil {
		ctx.logContext.Fatalf("Could not create targets for backends : %v", err)
		return
	}

	// write out the initial config so it exists, but mark it dirty so we update as soon
	// as we complete our first HC round too.
	ctx.StoreCheckedForwardingTable()
	ctx.dirty = true

	// run the check manager, and let it notify us whenever a HC round completed
	healthRoundComplete := make(chan bool)
	go ctx.checkManager.Run(healthRoundComplete, successesBeforeMarkedHealthy, failuresBeforeMarkedFailed)

	// handle SIGHUP and reload our forwarding table
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGHUP)
	go func() {
		for range sigs {
			ctx.logContext.Info("Received signal, reloading forwarding table.")
			err := ctx.LoadForwardingTable()
			if err != nil {
				ctx.logContext.Errorf("Could not load initial forwarding table: %v", err)
				continue
			}

			ctx.SyncAndMaybeReload()
		}
	}()

	go func() {
		for range healthRoundComplete {
			ctx.logContext.Debug("Health check round completed")
			ctx.SyncAndMaybeReload()
		}
	}()

	// provide an easy-access path to the latest health state results,
	// OOB from the forwarding table/reload machanism.
	http.HandleFunc("/health", ctx.HandleAPIHealth)

	// note that expvar is also implicitly included in this listener.
	ctx.logContext.Fatal(http.ListenAndServe("127.0.0.1:19520", nil))
}
