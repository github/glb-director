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
)

var (
	dampenerCounters = expvar.NewMap("DampenedResultStream")
)

// takes a HealthResultStream and returns a similar one, except that flapping is dampened.
// essentially at any given point, it takes a certain number of the same HC result before we accept
// that it's accurate and start reporting it - until then we report the old value.
// the values can be different for healthy/failed transitions to allow fast failure or fast return.
// assumes the first result is accurate and immediately starts returning it.
// the goroutine here will run until the source stream is closed, at which point it closes downstream too.
func DampenedResultStream(src HealthResultStream, countBeforeHealthy int, countBeforeFailed int) HealthResultStream {
	dampened := make(HealthResultStream)

	go func() {
		dampenerCounters.Add("StartedStreams", 1)
		dampenerCounters.Add("ActiveStreams", 1)

		// accept the first health state as accurate
		reportedHealth := <-src
		dampened <- reportedHealth

		currentHealth := reportedHealth
		currentHealthCount := 1

		for nextHealth := range src {
			if nextHealth.Healthy == currentHealth.Healthy {
				// if the new value matches the last one, we've seen one more of the same
				currentHealthCount++
				dampenerCounters.Add("HealthUnchanged", 1)
			} else {
				// otherwise, we've changed health state, so reset our count to 1
				currentHealthCount = 1
				currentHealth = nextHealth
				dampenerCounters.Add("HealthChangedWaitStart", 1)
			}

			// once we've seen the required count (or more) of a new value, start reporting it
			if currentHealth.Healthy && !reportedHealth.Healthy && currentHealthCount >= countBeforeHealthy {
				reportedHealth = currentHealth
				dampenerCounters.Add("HealthChangedHealthy", 1)
			} else if !currentHealth.Healthy && reportedHealth.Healthy && currentHealthCount >= countBeforeFailed {
				reportedHealth = currentHealth
				dampenerCounters.Add("HealthChangedUnhealthy", 1)
			}

			// and finally, keep sending out dampened state
			dampened <- reportedHealth
		}

		// pass on the closure of our source channel to the dampened one
		close(dampened)
		dampenerCounters.Add("CompletedStreams", 1)
		dampenerCounters.Add("ActiveStreams", -1)
	}()

	return dampened
}
