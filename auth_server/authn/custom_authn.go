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
	"fmt"
	"github.com/cesanta/glog"
	"plugin"
)

type CustomAuthnConfig struct {
	Configured  string `yaml:"configured"`
	Plugin_path string `yaml:"plugin_path"`
}

func (c *CustomAuthnConfig) Validate() error {
	if c.Configured != "true" {
		return fmt.Errorf("custom_auth should set to true")
	}
	if c.Plugin_path == "" {
		return fmt.Errorf("plugin_path cannot be empty")
	}
	return nil
}

type CustomAuthn struct {
	cfg *CustomAuthnConfig
}

type Authn interface {
	Authenticate(user, password string) (bool, Labels, error)
}

func (c *CustomAuthn) Authenticate(user string, password PasswordString) (bool, Labels, error) {
	// load module
	plug, err := plugin.Open(c.cfg.Plugin_path)
	if err != nil {
		return false, nil, fmt.Errorf("error while loading authn plugin: %v", err)
	}

	// look up for Authn
	symAuthen, err := plug.Lookup("Authn")
	if err != nil {
		return false, nil, fmt.Errorf("error while loading authn exporting the variable: %v", err)
	}

	// assert that loaded symbol is of a desired type
	var authn Authn
	authn, ok := symAuthen.(Authn)
	if !ok {
		return false, nil, fmt.Errorf("unexpected type from module symbol. Unable to cast Authn module")
	}

	// use the plugin
	return authn.Authenticate(user, string(password))
}

func (c *CustomAuthn) Stop() {
}

func (c *CustomAuthn) Name() string {
	return "custom auth"
}

//
func NewCustomAuthn(cfg *CustomAuthnConfig) *CustomAuthn {
	glog.Infof("External custom authenticator: %s", cfg.Configured)
	return &CustomAuthn{cfg: cfg}
}
