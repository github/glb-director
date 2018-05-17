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

var (
	// timeout should be < interval
	HealthCheckTimeout  = 1 * time.Second
	HealthCheckInterval = 2 * time.Second
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

	ctx := &HealthCheckerAppContext{dirty: true}
	ctx.logContext = log.WithFields(log.Fields{
		"app": "glb-healthcheck",
	})

	// load the configuration file, and fail hard if we can't
	err := ctx.LoadConfig(arguments["--config"].(string))
	if err != nil {
		ctx.logContext.Fatalf("Could not load configuration file: %s\n", err)
		return
	}

	// the check manager will run the HC loop and manage most of the HC part of the work
	ctx.checkManager = NewHealthCheckManager(HealthCheckTimeout, HealthCheckInterval)

	// load up the forwarding table and register all the check targets
	err = ctx.LoadForwardingTable()
	if err != nil {
		ctx.logContext.Fatalf("Could not load initial forwarding table: %v", err)
		return
	}

	// write out the initial config so it exists, but mark it dirty so we update as soon
	// as we complete our first HC round too.
	ctx.StoreCheckedForwardingTable()
	ctx.dirty = true

	// run the check manager, and let it notify us whenever a HC round completed
	healthRoundComplete := make(chan bool)
	go ctx.checkManager.Run(healthRoundComplete)

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
