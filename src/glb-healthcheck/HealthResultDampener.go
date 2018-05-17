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
