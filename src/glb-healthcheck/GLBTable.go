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
	"encoding/json"
	"io/ioutil"
	"time"
)

type GLBHealthcheckConfig struct {
	Http    *int    `json:"http,omitempty"`
	HttpUri *string `json:"http_uri,omitempty"`
	GUE     *int    `json:"gue,omitempty"`
	FOU     *int    `json:"fou,omitempty"`
	TCP     *int    `json:"tcp,omitempty"`
}

type GLBBind struct {
	Ip        string  `json:"ip"`
	Proto     string  `json:"proto"`
	Port      *uint16 `json:"port,omitempty"`
	PortStart *uint16 `json:"port_start,omitempty"`
	PortEnd   *uint16 `json:"port_end,omitempty"`
}

type GLBBackend struct {
	Ip      string `json:"ip"`
	State   string `json:"state"`
	Healthy bool   `json:"healthy"`

	HealthcheckConfig *GLBHealthcheckConfig `json:"healthchecks"`
}

type GLBTable struct {
	Name     string        `json:"name"`
	HashKey  string        `json:"hash_key"`
	Seed     string        `json:"seed"`
	Binds    []*GLBBind    `json:"binds"`
	Backends []*GLBBackend `json:"backends"`
}

type GLBHealthGlobalConfig struct {
	TimeoutMilliSec  time.Duration `json:"timeout_ms,omitempty"`
	IntervalMilliSec time.Duration `json:"interval_ms,omitempty"`
	Trigger          int           `json:"trigger,omitempty"`
}

type GLBGlobalConfig struct {
	HealthcheckGlobalCfg *GLBHealthGlobalConfig `json:"healthchecks"`
	Tables               []*GLBTable            `json:"tables"`
}

func LoadGLBTableConfig(filename string) (*GLBGlobalConfig, error) {
	bytes, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	c := &GLBGlobalConfig{}
	err = json.Unmarshal(bytes, c)
	if err != nil {
		return nil, err
	}

	return c, nil
}

func (cfg *GLBGlobalConfig) WriteToFile(filename string) error {
	bytes, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}

	return ioutil.WriteFile(filename, bytes, 0644)
}

func (backend *GLBBackend) HealthTargets() []HealthCheckTarget {
	targets := make([]HealthCheckTarget, 0, 2)

	if backend.HealthcheckConfig.Http != nil {
		var uri string = "/"
		if backend.HealthcheckConfig.HttpUri != nil {
			uri = *backend.HealthcheckConfig.HttpUri
		}
		targets = append(targets, HealthCheckTarget{
			CheckType: "http",
			Ip:        backend.Ip,
			Port:      *backend.HealthcheckConfig.Http,
			Uri:       uri,
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

	if backend.HealthcheckConfig.TCP != nil {
		targets = append(targets, HealthCheckTarget{
			CheckType: "tcp",
			Ip:        backend.Ip,
			Port:      *backend.HealthcheckConfig.TCP,
		})
	}

	return targets
}
