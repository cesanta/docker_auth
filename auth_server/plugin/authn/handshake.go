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
	plugin "github.com/hashicorp/go-plugin"
)

const (
	// PluginNetRPC is the plugin identifier for the net/rpc implementation
	PluginNetRPC = "authenticator"
)

// PluginMap is the map of plugins we can dispense.
var PluginMap = map[string]plugin.Plugin{
	PluginNetRPC: &RPCPlugin{},
}

// Handshake is the plugin contract between the host and its plugins.
var Handshake = plugin.HandshakeConfig{
	ProtocolVersion:  1,
	MagicCookieKey:   "AUTHN_PLUGIN",
	MagicCookieValue: "docker_auth",
}
