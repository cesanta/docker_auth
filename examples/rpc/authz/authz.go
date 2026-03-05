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
	"github.com/cesanta/docker_auth/auth_server/plugin/authz"
)

// LabelsGroups is the labels section containing user group information
// used for the authorization logic
const LabelsGroups = "groups"

// ErrSimulated is an error that is returned for testing the failure handling of the plugin system
var ErrSimulated = errors.New("simulated authorization error")

// Authorizer is an example implementation of an AUTHZ plugin
type Authorizer struct {
	logger hclog.Logger
}

// Authorize performs the authorization logic for this example implementation.
func (a *Authorizer) Authorize(req *authz.AuthorizeRequest) (authz.AuthorizeResponse, error) {
	a.logger.Debug("processing authorization request", "account", req.Account, "repo", req.Name)

	labels, ok := req.Labels[LabelsGroups]
	if !ok {
		return nil, plugin.ErrUnacceptable
	}

	for _, l := range labels {
		if l == "authz.error" {
			return nil, ErrSimulated
		} else if strings.Contains(req.Name, l) {
			return req.Actions, nil
		}
	}

	return nil, plugin.ErrForbidden
}
