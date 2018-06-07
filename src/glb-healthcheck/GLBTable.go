package main

import (
	"encoding/json"
	"io/ioutil"
)

type GLBHealthcheckConfig struct {
	Http *int `json:"http,omitempty"`
	GUE  *int `json:"gue,omitempty"`
}

type GLBBind struct {
	Ip        string `json:"ip"`
	Proto     string `json:"proto"`
	Port      *int16 `json:"port,omitempty"`
	PortStart *int16 `json:"port_start,omitempty"`
	PortEnd   *int16 `json:"port_end,omitempty"`
}

type GLBBackend struct {
	Ip      string `json:"ip"`
	State   string `json:"state"`
	Healthy bool   `json:"healthy"`

	HealthcheckConfig *GLBHealthcheckConfig `json:"healthchecks"`
}

type GLBTable struct {
	HashKey  string        `json:"hash_key"`
	Seed     string        `json:"seed"`
	Binds    []*GLBBind    `json:"binds"`
	Backends []*GLBBackend `json:"backends"`
}

type GLBTableConfig struct {
	Tables []*GLBTable `json:"tables"`
}

func LoadGLBTableConfig(filename string) (*GLBTableConfig, error) {
	bytes, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	c := &GLBTableConfig{}
	err = json.Unmarshal(bytes, c)
	if err != nil {
		return nil, err
	}

	return c, nil
}

func (cfg *GLBTableConfig) WriteToFile(filename string) error {
	bytes, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}

	return ioutil.WriteFile(filename, bytes, 0644)
}

func (backend *GLBBackend) HealthTargets() []HealthCheckTarget {
	targets := make([]HealthCheckTarget, 0, 2)

	if backend.HealthcheckConfig.Http != nil {
		targets = append(targets, HealthCheckTarget{
			CheckType: "http",
			Ip:        backend.Ip,
			Port:      *backend.HealthcheckConfig.Http,
		})
	}

	if backend.HealthcheckConfig.GUE != nil {
		targets = append(targets, HealthCheckTarget{
			CheckType: "gue",
			Ip:        backend.Ip,
			Port:      *backend.HealthcheckConfig.GUE,
		})
	}

	if backend.HealthcheckConfig.FOU != nil {
		targets = append(targets, HealthCheckTarget{
			CheckType: "fou",
			Ip:        backend.Ip,
			Port:      *backend.HealthcheckConfig.FOU,
		})
	}

	return targets
}
