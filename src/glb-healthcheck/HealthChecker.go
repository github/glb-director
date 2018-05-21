package main

import (
	"time"
)

type HealthCheckTarget struct {
	CheckType string
	Ip        string
	Port      int
}

type HealthResult struct {
	Healthy bool
	Failure string
}

type HealthResultStream chan HealthResult

type HealthChecker interface {
	Initialize(checkTimeout time.Duration) error
	CheckTarget(resultChannel HealthResultStream, target HealthCheckTarget)
}
