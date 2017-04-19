/*
   Copyright 2016 Cesanta Software Ltd.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       https://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

package authz

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"syscall"

	"github.com/cesanta/glog"
)

type ExtAuthzConfig struct {
	Command string   `yaml:"command"`
	Args    []string `yaml:"args"`
}

type ExtAuthzStatus int

const (
	ExtAuthzAllowed ExtAuthzStatus = 0
	ExtAuthzDenied  ExtAuthzStatus = 1
	ExtAuthzError   ExtAuthzStatus = 2
)

func (c *ExtAuthzConfig) Validate() error {
	if c.Command == "" {
		return fmt.Errorf("command is not set")
	}
	if _, err := exec.LookPath(c.Command); err != nil {
		return fmt.Errorf("invalid command %q: %s", c.Command, err)
	}
	return nil
}

type ExtAuthz struct {
	cfg *ExtAuthzConfig
}

func NewExtAuthzAuthorizer(cfg *ExtAuthzConfig) *ExtAuthz {
	glog.Infof("External authorization: %s %s", cfg.Command, strings.Join(cfg.Args, " "))
	return &ExtAuthz{cfg: cfg}
}

func (ea *ExtAuthz) Authorize(ai *AuthRequestInfo) ([]string, error) {
	aiMarshal, err := json.Marshal(ai)
	if err != nil {
		return nil, fmt.Errorf("Unable to json.Marshal AuthRequestInfo: %s", err)
	}

	cmd := exec.Command(ea.cfg.Command, ea.cfg.Args...)
	cmd.Stdin = strings.NewReader(fmt.Sprintf("%s", aiMarshal))
	output, err := cmd.Output()

	es := 0
	et := ""
	if err == nil {
	} else if ee, ok := err.(*exec.ExitError); ok {
		es = ee.Sys().(syscall.WaitStatus).ExitStatus()
		et = string(ee.Stderr)
	} else {
		es = int(ExtAuthzError)
		et = fmt.Sprintf("cmd run error: %s", err)
	}
	glog.V(2).Infof("%s %s -> %d %s", cmd.Path, cmd.Args, es, output)

	switch ExtAuthzStatus(es) {
	case ExtAuthzAllowed:
		return ai.Actions, nil
	case ExtAuthzDenied:
		return []string{}, nil
	default:
		glog.Errorf("Ext command error: %d %s", es, et)
	}
	return nil, fmt.Errorf("bad return code from command: %d", es)
}

func (sua *ExtAuthz) Stop() {
}

func (sua *ExtAuthz) Name() string {
	return "external authz"
}
