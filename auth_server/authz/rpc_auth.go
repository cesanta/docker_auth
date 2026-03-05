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
	"os/exec"

	"github.com/cesanta/glog"
	rpc "github.com/hashicorp/go-plugin"

	"github.com/cesanta/docker_auth/auth_server/api"
	shared "github.com/cesanta/docker_auth/auth_server/plugin"
	plugin "github.com/cesanta/docker_auth/auth_server/plugin/authz"
)

type RPCAuthzConfig struct {
	Command string   `yaml:"command"`
	Args    []string `yaml:"args"`
}

func (c *RPCAuthzConfig) Validate() error {
	if c.Command == "" {
		return fmt.Errorf("command is not set")
	}

	if _, err := exec.LookPath(c.Command); err != nil {
		return fmt.Errorf("no such command: %s: %w", c.Command, err)
	}

	return nil
}

type RPCAuthz struct {
	client *rpc.Client
	impl   plugin.Authorizer
}

func (c *RPCAuthz) Authorize(ai *api.AuthRequestInfo) ([]string, error) {
	req := &plugin.AuthorizeRequest{
		Account: ai.Account,
		Type:    ai.Type,
		Name:    ai.Name,
		Service: ai.Service,
		IP:      ai.IP,
		Actions: ai.Actions,
		Labels:  ai.Labels,
	}
	resp, err := c.impl.Authorize(req)
	switch {
	case err == nil:
		return resp, nil
	case shared.IsError(err, shared.ErrForbidden):
		return []string{}, nil
	case shared.IsError(err, shared.ErrUnacceptable):
		return nil, api.NoMatch
	default:
		return nil, err
	}
}

func (c *RPCAuthz) Stop() {
	if c.client != nil {
		c.client.Kill()
	}
}

func (c *RPCAuthz) Name() string {
	return "rpc"
}

func NewRPCAuthz(cfg *RPCAuthzConfig) (*RPCAuthz, error) {
	glog.Infof("RPC authorizer: %s", cfg)

	conn := &rpc.ClientConfig{
		HandshakeConfig: plugin.Handshake,
		Plugins:         plugin.PluginMap,
		Cmd:             exec.Command(cfg.Command, cfg.Args...),
	}
	client := rpc.NewClient(conn)

	rpcClient, err := client.Client()
	if err != nil {
		client.Kill()
		return nil, err
	}

	raw, err := rpcClient.Dispense(plugin.PluginNetRPC)
	if err != nil {
		client.Kill()
		return nil, err
	}

	impl, ok := raw.(plugin.Authorizer)
	if !ok {
		client.Kill()
		return nil, fmt.Errorf("no authorizer plugin provided: %T", impl)
	}

	result := &RPCAuthz{
		client: client,
		impl:   impl,
	}

	return result, nil
}
