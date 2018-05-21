package main

import (
	// log "github.com/sirupsen/logrus"
	"expvar"
	"fmt"
	"sync"
	"time"
)

var (
	SuccessesBeforeMarkedHealthy = 3
	FailuresBeforeMarkedFailed   = 3
)

var (
	managerCounters = expvar.NewMap("HealthCheckManager")
)

type HealthCheckMetadata struct {
	rawStream      HealthResultStream
	dampenedStream HealthResultStream
}

type HealthCheckManager struct {
	checkTimeout  time.Duration
	checkInterval time.Duration

	checkers map[string]HealthChecker

	sync.Mutex
	nextTargets []HealthCheckTarget
	results     map[HealthCheckTarget]HealthResult
}

func NewHealthCheckManager(checkTimeout time.Duration, checkInterval time.Duration) *HealthCheckManager {
	tunnelChecker := &TunnelHealthChecker{}
	tunnelChecker.Initialize(checkTimeout)

	httpChecker := &HttpHealthChecker{}
	httpChecker.Initialize(checkTimeout)

	m := &HealthCheckManager{
		checkTimeout:  checkTimeout,
		checkInterval: checkInterval,
		checkers: map[string]HealthChecker{
			"http": httpChecker,
			"gue":  tunnelChecker,
			"fou":  tunnelChecker,
		},
		nextTargets: []HealthCheckTarget{},
		results:     make(map[HealthCheckTarget]HealthResult),
	}

	return m
}

// called to set the complete picture of current targets to check.
// we validate the check types exist, every other value is safe to be wrong (HC will fail)
// we don't ever manipulate this map, we just swap it out wholesale to make this part easier.
func (hhc *HealthCheckManager) SetTargets(targets []HealthCheckTarget) error {
	// pre-validate every target
	for _, target := range targets {
		if _, ok := hhc.checkers[target.CheckType]; !ok {
			managerCounters.Add("InvalidCheckType", 1)
			return fmt.Errorf("Invalid check type: %s", target.CheckType)
		}
	}

	managerCounters.Add("TargetUpdates", 1)

	hhc.Lock()
	hhc.nextTargets = targets
	hhc.Unlock()

	return nil
}

func (hhc *HealthCheckManager) GetResults() map[HealthCheckTarget]HealthResult {
	managerCounters.Add("ResultRequests", 1)

	hhc.Lock()
	defer hhc.Unlock()
	return hhc.results
}

// most of the actual HC target tracking work happens here.
// most importantly, we take a snapshot in time each check interval and use that
// as the source of truth for that round, no mutations. next round we do
// housekeeping like accepting new targets and throwing away ones that are gone.
func (hhc *HealthCheckManager) Run(roundComplete chan bool) {
	activeTargets := make(map[HealthCheckTarget]*HealthCheckMetadata)

	for {
		managerCounters.Add("LoopIterations", 1)

		/// Target update phase
		hhc.Lock()
		targets := hhc.nextTargets
		hhc.Unlock()

		// save our old target map, and reset ourselves to a new one which we'll (re)fill
		lastActive := activeTargets
		activeTargets = make(map[HealthCheckTarget]*HealthCheckMetadata)

		// we have a potentially new list of targets.
		// start by copying or creating metadata, deleting our tracks
		for _, target := range targets {
			if metadata, ok := lastActive[target]; ok {
				// copy our previous metadata, remove it from the previous map
				activeTargets[target] = metadata
				delete(lastActive, target)

				managerCounters.Add("TargetsKept", 1)
			} else {
				// create a new set of metadata/channels
				rawStream := make(HealthResultStream)
				activeTargets[target] = &HealthCheckMetadata{
					rawStream:      rawStream,
					dampenedStream: DampenedResultStream(rawStream, SuccessesBeforeMarkedHealthy, FailuresBeforeMarkedFailed),
				}

				managerCounters.Add("TargetsAdded", 1)
			}
		}

		// our lastActive map is now deprecated, and only contains targets
		// we no longer wish to check. clean those up by closing their HC channel.
		// note that no health check result should be able to write into it by now
		// since we've already collected the latest results.
		for target, metadata := range lastActive {
			managerCounters.Add("TargetsDeleted", 1)
			// this will also have the effect of the DampenedResultStream closing the downstream channel
			close(metadata.rawStream)
			// for good measure, technically this will be GCed anyway
			delete(lastActive, target)
			// to make sure nothing is sitting around waiting, drain the stream too
			go func() {
				managerCounters.Add("TargetSinksStarted", 1)

				for range metadata.dampenedStream {
					// sink items until this is closed
				}

				managerCounters.Add("TargetSinksCompleted", 1)
			}()
		}

		/// Health check phase
		results := hhc.doHealthCheckRound(activeTargets)
		hhc.Lock()
		hhc.results = results
		hhc.Unlock()

		roundComplete <- true
	}
}

// execute 1 round of health checks. for simplicity, we wait for the HC interval here.
// this also is what guarantees we wait at least the HC interval between rounds.
// this actually means we drift slightly (by the overhead of what's executed between intervals)
// but that should be insignificant.
func (hhc *HealthCheckManager) doHealthCheckRound(targets map[HealthCheckTarget]*HealthCheckMetadata) map[HealthCheckTarget]HealthResult {
	managerCounters.Add("HealthCheckRounds", 1)

	// start by sending a check request to each target
	for target, metadata := range targets {
		checker := hhc.checkers[target.CheckType]

		// checks the target and guarantees that a result will come back approximately by the check timeout
		checker.CheckTarget(metadata.rawStream, target)

		managerCounters.Add("HealthCheckInitiated", 1)
	}

	// wait for the check interval, everyone should have completed by then
	time.Sleep(hhc.checkInterval)

	// we now expect that every check will have returned a result.
	// if for some reason the sleep wasn't quite enough time, we'll wait here.
	// this should be acceptable since the checkers always have a hard timeout
	// of checkTimeout which is < checkInterval
	results := make(map[HealthCheckTarget]HealthResult)
	for target, metadata := range targets {
		results[target] = <-metadata.dampenedStream
	}

	return results
}
