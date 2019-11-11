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
		 	fmt.Println(err)
			ch <- HealthResult{Healthy: false, Failure: err.Error()}
	 	 } else {
			ch <- HealthResult{Healthy: true, Failure: ""}
	        c.Close()
		 }
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
		}

		logContext.WithFields(log.Fields{
			"healthy":       result.Healthy,
			"healthFailure": result.Failure,
		}).Debug("TCP health check result completed")

		// pass on the result directly to the caller's channel
		resultChannel <- result


	}()
}

