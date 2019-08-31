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

package authn

import (
	"fmt"
	"plugin"

	"github.com/cesanta/glog"

	"github.com/cesanta/docker_auth/auth_server/api"
)

type PluginAuthnConfig struct {
	PluginPath string `yaml:"plugin_path"`
}

func lookupAuthnSymbol(cfg *PluginAuthnConfig) (api.Authenticator, error) {
	// load module
	plug, err := plugin.Open(cfg.PluginPath)
	if err != nil {
		return nil, fmt.Errorf("error while loading authn plugin: %v", err)
	}

	// look up for Authn
	symAuthen, err := plug.Lookup("Authn")
	if err != nil {
		return nil, fmt.Errorf("error while loading authn exporting the variable: %v", err)
	}

	// assert that loaded symbol is of a desired type
	var authn api.Authenticator
	authn, ok := symAuthen.(api.Authenticator)
	if !ok {
		return nil, fmt.Errorf("unexpected type from module symbol. Unable to cast Authn module")
	}
	return authn, nil
}

func (c *PluginAuthnConfig) Validate() error {
	_, err := lookupAuthnSymbol(c)
	return err
}

type PluginAuthn struct {
	cfg   *PluginAuthnConfig
	Authn api.Authenticator
}

func (c *PluginAuthn) Authenticate(user string, password api.PasswordString) (bool, api.Labels, error) {
	// use the plugin
	return c.Authn.Authenticate(user, password)
}

func (c *PluginAuthn) Stop() {
}

func (c *PluginAuthn) Name() string {
	return "plugin auth"
}

func NewPluginAuthn(cfg *PluginAuthnConfig) (*PluginAuthn, error) {
	glog.Infof("Plugin authenticator: %s", cfg)
	authn, err := lookupAuthnSymbol(cfg)
	if err != nil {
		return nil, err
	}
	return &PluginAuthn{Authn: authn}, nil
}
