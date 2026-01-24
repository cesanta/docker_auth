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
	"net"
)

// AuthorizeResponse contains information associated with
// the authorized principal.
type AuthorizeResponse []string

// AuthorizeRequest represents the input query for authorization requests.
type AuthorizeRequest struct {
	Account string
	Type    string
	Name    string
	Service string
	IP      net.IP
	Actions []string
	Labels  map[string][]string
}

// Authorizer is the contract plugin implementations must fulfill
// in order to be used for authorization purposes.
type Authorizer interface {
	Authorize(*AuthorizeRequest) (AuthorizeResponse, error)
}
