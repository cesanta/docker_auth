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

package main

import (
	"os"

	hclog "github.com/hashicorp/go-hclog"
	plugin "github.com/hashicorp/go-plugin"

	"github.com/cesanta/docker_auth/auth_server/plugin/authz"
)

func main() {
	hcCfg := &hclog.LoggerOptions{
		Name:       "authorizer",
		Level:      hclog.Debug,
		Output:     os.Stderr,
		JSONFormat: true,
	}
	logger := hclog.New(hcCfg)

	impl := &Authorizer{
		logger: logger,
	}
	pluginMap := map[string]plugin.Plugin{
		authz.PluginNetRPC: authz.NewRPCPlugin(impl),
	}
	pluginCfg := &plugin.ServeConfig{
		HandshakeConfig: authz.Handshake,
		Plugins:         pluginMap,
		Logger:          logger,
	}

	if l := len(os.Args); l > 0 {
		logger.Info("received additional commandline arguments", "args", l)
	}

	plugin.Serve(pluginCfg)
}
