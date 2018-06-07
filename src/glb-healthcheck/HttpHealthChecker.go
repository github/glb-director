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
func httpCheckURL(url string) HealthResultStream {
	ch := make(HealthResultStream, 1)

	go func() {
		httpCounters.Add("Checks", 1)
		resp, err := http.Get(url)
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
		resultCh := httpCheckURL(fmt.Sprintf("http://%s:%d%s", target.Ip, target.Port, target.Uri))

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
