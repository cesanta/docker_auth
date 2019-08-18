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
	"os"
	"plugin"
)

type PluginAuthzConfig struct {
	PluginPath string `yaml:"plugin_path"`
	Authz      Authorizer
}

func (c *PluginAuthzConfig) Validate() error {
	if c.PluginPath == "" {
		return fmt.Errorf("plugin_path cannot be empty")
	}
	if _, err := os.Stat(c.PluginPath); os.IsNotExist(err) {
		return fmt.Errorf("file does not exists in %s: %v", c.PluginPath, err)
	}
	glog.Infof("Plugin file resolved in: %s", c.PluginPath)
	return nil
}

type PluginAuthz struct {
	cfg *PluginAuthzConfig
}

func (c *PluginAuthz) Stop() {
}

func (c *PluginAuthz) Name() string {
	return "plugin authz"
}

func NewPluginAuthzAuthorizer(cfg *PluginAuthzConfig) (*PluginAuthz, error) {
	glog.Infof("Plugin authorization: %s", cfg)
	// load module
	plug, err := plugin.Open(cfg.PluginPath)
	if err != nil {
		return nil, fmt.Errorf("error while loading authz plugin: %v", err)
	}

	// look up for Authz
	symAuthz, err := plug.Lookup("Authz")
	if err != nil {
		return nil, fmt.Errorf("error while loading authz exporting the variable: %v", err)
	}

	// assert that loaded symbol is of a desired type
	var authz Authorizer
	authz, ok := symAuthz.(Authorizer)
	if !ok {
		return nil, fmt.Errorf("unexpected type from module symbol. Unable to cast Authz module")
	}
	cfg.Authz = authz
	return &PluginAuthz{cfg: cfg}, nil
}

func (c *PluginAuthz) Authorize(ai *AuthRequestInfo) ([]string, error) {
	// use the plugin
	return c.cfg.Authz.Authorize(ai)
}
