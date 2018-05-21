package main

import (
	"encoding/json"
	"expvar"
	"fmt"
	log "github.com/sirupsen/logrus"
	"io/ioutil"
	"net/http"
	"os/exec"
	"sync"
)

var (
	appCounters = expvar.NewMap("HealthCheckerApp")
)

type HealthCheckConfigFile struct {
	ForwardingTable struct {
		Src string `json:"src"`
		Dst string `json:"dst"`
	} `json:"forwarding_table"`

	ReloadCommand *string `json:"reload_command"`
}

type HealthCheckerAppContext struct {
	logContext   *log.Entry
	config       *HealthCheckConfigFile
	checkManager *HealthCheckManager

	sync.Mutex
	forwardingTableConfig *GLBTableConfig
	dirty                 bool
}

func (ctx *HealthCheckerAppContext) LoadConfig(filename string) error {
	bytes, err := ioutil.ReadFile(filename)
	if err != nil {
		return err
	}

	c := &HealthCheckConfigFile{}
	err = json.Unmarshal(bytes, c)
	if err != nil {
		return err
	}

	ctx.config = c

	return nil
}

// once a `forwardingTableConfig` has been loaded, iterate over it to find every
// unique health check target (ip, port, type). we unique it because the same
// backend may be listed numerous times, we include the port in uniqueness
// so that, for example, GUE is always tested for all occurences of a backend,
// but perhaps one table might use a different HTTP check port for a different
// downstream L7 service.
func (ctx *HealthCheckerAppContext) SyncBackendsToCheckManager() error {
	appCounters.Add("BackendTargetSyncs", 1)

	// find the unique targets by pushing through a map
	uniqueBackends := make(map[HealthCheckTarget]bool)
	for _, table := range ctx.forwardingTableConfig.Tables {
		for _, backend := range table.Backends {
			for _, target := range backend.HealthTargets() {
				uniqueBackends[target] = true
			}
		}
	}

	// extract targets as array
	backends := make([]HealthCheckTarget, len(uniqueBackends))
	i := 0
	for target := range uniqueBackends {
		backends[i] = target
		i++
	}

	return ctx.checkManager.SetTargets(backends)
}

// once we have a set of HC results, merge them together to a true/false
// healthy flag for every backend listed. we require that every HC passes,
// but if a backend has no HC configured then we treat it as healthy.
func (ctx *HealthCheckerAppContext) UpdateTableBackendHealth() {
	appCounters.Add("HealthCheckSyncs", 1)

	ctx.Lock()
	ft := ctx.forwardingTableConfig
	ctx.Unlock()

	targetResults := ctx.checkManager.GetResults()

	for _, table := range ft.Tables {
		for _, backend := range table.Backends {
			logContext := ctx.logContext

			successes := 0
			failures := 0
			for _, target := range backend.HealthTargets() {
				if targetResults[target].Healthy {
					successes++
				} else {
					failures++
				}

				// add in tags for each check type
				logContext = logContext.WithFields(log.Fields{
					target.CheckType: targetResults[target].Healthy,
				})
			}

			healthy := (failures == 0)

			if backend.Healthy != healthy {
				appCounters.Add("BackendHealthChanged", 1)

				ctx.dirty = true

				logContext.WithFields(log.Fields{
					"backendIp": backend.Ip,
					"successes": successes,
					"failures":  failures,
					"oldHealth": backend.Healthy,
					"newHealth": healthy,
				}).Info("Health state changed for backend")
			}

			backend.Healthy = healthy
		}
	}
}

func (ctx *HealthCheckerAppContext) LoadForwardingTable() error {
	appCounters.Add("ForwardingTableReloadAttempts", 1)

	ft, err := LoadGLBTableConfig(ctx.config.ForwardingTable.Src)
	if err != nil {
		appCounters.Add("ForwardingTableReloadFailures", 1)
		return fmt.Errorf("Could not load forwarding table '%s': %s\n", ctx.config.ForwardingTable.Src, err)
	}

	appCounters.Add("ForwardingTableReloads", 1)
	ctx.logContext.WithFields(log.Fields{
		"filename": ctx.config.ForwardingTable.Src,
	}).Info("Loaded forwarding table from disk")

	ctx.Lock()
	ctx.forwardingTableConfig = ft

	// mark dirty, similar to a HC change, in case the underlying tables or backend list changed
	ctx.dirty = true
	ctx.Unlock()

	return ctx.SyncBackendsToCheckManager()
}

func (ctx *HealthCheckerAppContext) SyncAndMaybeReload() {
	// pass through the backend list and update health, if needed.
	// if a health state changes, the dirty flag will also be set.
	ctx.UpdateTableBackendHealth()

	// if needed, write out the new table (with updated `healthy` fields)
	// and call the reload command to create the binary table / signal reload.
	if ctx.CheckAndClearDirty() {
		ctx.StoreCheckedForwardingTable()
		ctx.RunReloadCommand()
	}
}

func (ctx *HealthCheckerAppContext) StoreCheckedForwardingTable() error {
	appCounters.Add("ForwardingTableWrites", 1)

	ctx.Lock()
	ft := ctx.forwardingTableConfig
	ctx.Unlock()

	ctx.logContext.WithFields(log.Fields{
		"filename": ctx.config.ForwardingTable.Dst,
	}).Info("Storing forwarding table to disk")
	err := ft.WriteToFile(ctx.config.ForwardingTable.Dst)
	if err != nil {
		appCounters.Add("ForwardingTableWriteFailures", 1)
		return fmt.Errorf("Could not store forwarding table '%s': %s\n", ctx.config.ForwardingTable.Dst, err)
	}

	return nil
}

func (ctx *HealthCheckerAppContext) RunReloadCommand() {
	if ctx.config.ReloadCommand == nil {
		appCounters.Add("SkippedReloads", 1)

		ctx.logContext.Info("Would have reloaded, but reload command not present in config")
	} else {
		appCounters.Add("ReloadsExecuted", 1)

		ctx.logContext.WithFields(log.Fields{
			"reloadCommand": *ctx.config.ReloadCommand,
		}).Info("Executing reload command")

		// execute in the shell since we trust our config.
		cmd := exec.Command("/bin/sh", "-c", *ctx.config.ReloadCommand)
		err := cmd.Run()
		if err != nil {
			ctx.logContext.WithFields(log.Fields{
				"reloadCommand": *ctx.config.ReloadCommand,
				"err":           err,
			}).Error("Error executing reload command")
		}
	}
}

func (ctx *HealthCheckerAppContext) CheckAndClearDirty() bool {
	ctx.Lock()
	defer ctx.Unlock()

	d := ctx.dirty
	ctx.dirty = false

	return d
}

type HealthSummary struct {
	Results map[HealthCheckTarget]HealthResult
}

func (ctx *HealthCheckerAppContext) HandleAPIHealth(w http.ResponseWriter, r *http.Request) {
	summary := &HealthSummary{
		Results: ctx.checkManager.GetResults(),
	}

	json.NewEncoder(w).Encode(summary)
}
