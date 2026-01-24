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
	"errors"
	"strings"

	hclog "github.com/hashicorp/go-hclog"

	"github.com/cesanta/docker_auth/auth_server/plugin"
	"github.com/cesanta/docker_auth/auth_server/plugin/authn"
)

// LabelsGroups is the labels section containing user group information
// for successful authentication attempts
const LabelsGroups = "groups"

// ErrSimulated is an error that is returned for testing the failure handling of the plugin system
var ErrSimulated = errors.New("simulated authentication error")

// Authenticator is an example implementation of an AUTHN plugin
type Authenticator struct {
	logger hclog.Logger
}

// Authenticate performs the authentication logic for this example implementation.
func (a *Authenticator) Authenticate(req *authn.AuthenticateRequest) (authn.AuthenticateResponse, error) {
	a.logger.Debug("processing authentication request", "username", req.Username)

	parts := strings.Split(req.Username, "@")
	if len(parts) != 2 {
		return nil, plugin.ErrUnacceptable
	}

	if parts[1] == "authn.error" {
		return nil, ErrSimulated
	}

	if parts[0] != req.Password {
		return nil, plugin.ErrUnauthorized
	}

	groups := []string{parts[1]}
	resp := map[string][]string{
		LabelsGroups: groups,
	}

	return resp, nil
}
