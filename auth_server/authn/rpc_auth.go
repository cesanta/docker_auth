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
	"os/exec"

	"github.com/cesanta/glog"
	rpc "github.com/hashicorp/go-plugin"

	"github.com/cesanta/docker_auth/auth_server/api"
	shared "github.com/cesanta/docker_auth/auth_server/plugin"
	plugin "github.com/cesanta/docker_auth/auth_server/plugin/authn"
)

type RPCAuthnConfig struct {
	Command string   `yaml:"command"`
	Args    []string `yaml:"args"`
}

func (c *RPCAuthnConfig) Validate() error {
	if c.Command == "" {
		return fmt.Errorf("command is not set")
	}

	if _, err := exec.LookPath(c.Command); err != nil {
		return fmt.Errorf("no such command: %s: %w", c.Command, err)
	}

	return nil
}

type RPCAuthn struct {
	client *rpc.Client
	impl   plugin.Authenticator
}

func (c *RPCAuthn) Authenticate(username string, password api.PasswordString) (bool, api.Labels, error) {
	req := &plugin.AuthenticateRequest{
		Username: username,
		Password: string(password),
	}
	resp, err := c.impl.Authenticate(req)
	switch {
	case err == nil:
		return true, api.Labels(resp), nil
	case shared.IsError(err, shared.ErrUnauthorized):
		return false, nil, nil
	case shared.IsError(err, shared.ErrUnacceptable):
		return false, nil, api.NoMatch
	default:
		return false, nil, err
	}
}

func (c *RPCAuthn) Stop() {
	if c.client != nil {
		c.client.Kill()
	}
}

func (c *RPCAuthn) Name() string {
	return "rpc"
}

func NewRPCAuthn(cfg *RPCAuthnConfig) (*RPCAuthn, error) {
	glog.Infof("RPC authenticator: %s", cfg)

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

	impl, ok := raw.(plugin.Authenticator)
	if !ok {
		client.Kill()
		return nil, fmt.Errorf("no authenticator plugin provided: %T", impl)
	}

	result := &RPCAuthn{
		client: client,
		impl:   impl,
	}

	return result, nil
}
