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

package authn

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"syscall"

	"github.com/cesanta/glog"
)

type ExtAuthConfig struct {
	Command string   `yaml:"command"`
	Args    []string `yaml:"args"`
}

type ExtAuthStatus int

const (
	ExtAuthAllowed ExtAuthStatus = 0
	ExtAuthDenied  ExtAuthStatus = 1
	ExtAuthNoMatch ExtAuthStatus = 2
	ExtAuthError   ExtAuthStatus = 3
)

type ExtAuthResponse struct {
	Labels Labels `json:"labels,omitempty"`
}

func (c *ExtAuthConfig) Validate() error {
	if c.Command == "" {
		return fmt.Errorf("command is not set")
	}
	if _, err := exec.LookPath(c.Command); err != nil {
		return fmt.Errorf("invalid command %q: %s", c.Command, err)
	}
	return nil
}

type extAuth struct {
	cfg *ExtAuthConfig
}

func NewExtAuth(cfg *ExtAuthConfig) *extAuth {
	glog.Infof("External authenticator: %s %s", cfg.Command, strings.Join(cfg.Args, " "))
	return &extAuth{cfg: cfg}
}

func (ea *extAuth) Authenticate(user string, password PasswordString) (bool, Labels, error) {
	cmd := exec.Command(ea.cfg.Command, ea.cfg.Args...)
	cmd.Stdin = strings.NewReader(fmt.Sprintf("%s %s", user, string(password)))
	output, err := cmd.Output()
	es := 0
	et := ""
	if err == nil {
	} else if ee, ok := err.(*exec.ExitError); ok {
		es = ee.Sys().(syscall.WaitStatus).ExitStatus()
		et = string(ee.Stderr)
	} else {
		es = int(ExtAuthError)
		et = fmt.Sprintf("cmd run error: %s", err)
	}
	glog.V(2).Infof("%s %s -> %d %s", cmd.Path, cmd.Args, es, output)
	switch ExtAuthStatus(es) {
	case ExtAuthAllowed:
		var resp ExtAuthResponse
		if len(output) > 0 {
			if err = json.Unmarshal(output, &resp); err != nil {
				return false, nil, err
			}
		}
		return true, resp.Labels, nil
	case ExtAuthDenied:
		return false, nil, nil
	case ExtAuthNoMatch:
		return false, nil, NoMatch
	default:
		glog.Errorf("Ext command error: %d %s", es, et)
	}
	return false, nil, fmt.Errorf("bad return code from command: %d", es)
}

func (sua *extAuth) Stop() {
}

func (sua *extAuth) Name() string {
	return "external"
}
