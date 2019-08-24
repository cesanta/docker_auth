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
	"plugin"

	"github.com/cesanta/glog"
)

type PluginAuthzConfig struct {
	PluginPath string `yaml:"plugin_path"`
}

func lookupSymbol(cfg *PluginAuthzConfig) (Authorizer, error) {
	// load module
	plug, err := plugin.Open(cfg.PluginPath)
	if err != nil {
		return nil, fmt.Errorf("error while loading authz plugin: %v", err)
	}

	// look up for Authz
	symAuthen, err := plug.Lookup("Authz")
	if err != nil {
		return nil, fmt.Errorf("error while loading authz exporting the variable: %v", err)
	}

	// assert that loaded symbol is of a desired type
	var authz Authorizer
	authz, ok := symAuthen.(Authorizer)
	if !ok {
		return nil, fmt.Errorf("unexpected type from module symbol. Unable to cast Authz module")
	}
	return authz, nil
}

func (c *PluginAuthzConfig) Validate() error {
	_, err := lookupSymbol(c)
	return err
}

type PluginAuthz struct {
	cfg   *PluginAuthzConfig
	Authz Authorizer
}

func (c *PluginAuthz) Stop() {
}

func (c *PluginAuthz) Name() string {
	return "plugin authz"
}

func NewPluginAuthzAuthorizer(cfg *PluginAuthzConfig) (*PluginAuthz, error) {
	glog.Infof("Plugin authorization: %s", cfg)
	authz, err := lookupSymbol(cfg)
	if err != nil {
		return nil, err
	}
	return &PluginAuthz{Authz: authz}, nil
}

func (c *PluginAuthz) Authorize(ai *AuthRequestInfo) ([]string, error) {
	// use the plugin
	return c.Authz.Authorize(ai)
}
