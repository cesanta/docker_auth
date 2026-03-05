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
	"net/rpc"

	plugin "github.com/hashicorp/go-plugin"
)

// RPCPlugin implements [plugin.Plugin]
// using net/rpc as transport implementation.
type RPCPlugin struct {
	impl Authenticator
}

func NewRPCPlugin(a Authenticator) *RPCPlugin {
	result := &RPCPlugin{
		impl: a,
	}

	return result
}

func (p *RPCPlugin) Server(_ *plugin.MuxBroker) (interface{}, error) {
	return NewRPCServer(p.impl), nil
}

func (*RPCPlugin) Client(_ *plugin.MuxBroker, c *rpc.Client) (interface{}, error) {
	return NewRPCClient(c), nil
}

// RPCClient implements [Authenticator] using an [rpc.Client]
// for communication.
type RPCClient struct {
	client *rpc.Client
}

func NewRPCClient(c *rpc.Client) *RPCClient {
	result := &RPCClient{
		client: c,
	}

	return result
}

func (c *RPCClient) Authenticate(req *AuthenticateRequest) (resp AuthenticateResponse, err error) {
	err = c.client.Call("Plugin.Authenticate", req, &resp)

	return
}

// RPCServer is the server side of the communication with RPCClient, conforming to
// the requirements of net/rpc
type RPCServer struct {
	impl Authenticator
}

func NewRPCServer(a Authenticator) *RPCServer {
	result := &RPCServer{
		impl: a,
	}

	return result
}

func (s *RPCServer) Authenticate(req *AuthenticateRequest, resp *AuthenticateResponse) error {
	v, err := s.impl.Authenticate(req)
	*resp = v

	return err
}
