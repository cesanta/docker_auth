/*
   Copyright 2019 Cesanta Software Ltd.

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
	"fmt"
	"github.com/cesanta/glog"
	"plugin"
)

type CustomAuthzConfig struct {
	Configured  string `yaml:"configured"`
	Plugin_path string `yaml:"plugin_path"`
}

func (c *CustomAuthzConfig) Validate() error {
	if c.Configured != "true" {
		return fmt.Errorf("custom_authz should set to true")
	}
	if c.Plugin_path == "" {
		return fmt.Errorf("plugin_path cannot be empty")
	}
	return nil
}

type CustomAuthz struct {
	cfg *CustomAuthzConfig
}

func (c *CustomAuthz) Stop() {
}

func (c *CustomAuthz) Name() string {
	return "custom authz"
}

func NewCustomAuthzAuthorizer(cfg *CustomAuthzConfig) *CustomAuthz {
	glog.Infof("External authorization: %s", cfg.Configured)
	return &CustomAuthz{cfg: cfg}
}

type Authz interface {
	Authorize(ai *AuthRequestInfo) ([]string, error)
}

func (c *CustomAuthz) Authorize(ai *AuthRequestInfo) ([]string, error) {
	// load module
	plug, err := plugin.Open(c.cfg.Plugin_path)
	if err != nil {
		return nil, fmt.Errorf("error while loading authz plugin: %v", err)
	}

	// look up for Authz
	symAuthz, err := plug.Lookup("Authz")
	if err != nil {
		return nil, fmt.Errorf("error while loading authz exporting the variable: %v", err)
	}

	// assert that loaded symbol is of a desired type
	var authz Authz
	authz, ok := symAuthz.(Authz)
	if !ok {
		return nil, fmt.Errorf("unexpected type from module symbol. Unable to cast Authz module")
	}

	// use the plugin
	return authz.Authorize(ai)
}
