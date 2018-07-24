/*
   Copyright 2015 Cesanta Software Ltd.

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

package server

import (
	"fmt"
	"net/http"
	"regexp"

	"github.com/cesanta/docker_auth/auth_server/authn"
	"github.com/cesanta/docker_auth/auth_server/authz"
	. "github.com/cesanta/docker_auth/auth_server/common"
	"github.com/cesanta/glog"

)

var (
	hostPortRegex = regexp.MustCompile(`\[?(.+?)\]?:\d+$`)
)

type AuthServer struct {
	*SimpleServer

	config         *Config
	ga             *authn.GoogleAuth
	gha            *authn.GitHubAuth
}

func NewAuthServer(c *Config) (*AuthServer, error) {
	as := &AuthServer{
		SimpleServer: &SimpleServer{
			Authorizers: []Authorizer{},
			Authenticators: []Authenticator{},
		},
		config: c,
	}
	if c.ACL != nil {
		staticAuthorizer, err := authz.NewACLAuthorizer(c.ACL)
		if err != nil {
			return nil, err
		}
		as.Authorizers = append(as.Authorizers, staticAuthorizer)
	}
	if c.ACLMongo != nil {
		mongoAuthorizer, err := authz.NewACLMongoAuthorizer(c.ACLMongo)
		if err != nil {
			return nil, err
		}
		as.Authorizers = append(as.Authorizers, mongoAuthorizer)
	}
	if c.ExtAuthz != nil {
		extAuthorizer := authz.NewExtAuthzAuthorizer(c.ExtAuthz)
		as.Authorizers = append(as.Authorizers, extAuthorizer)
	}
	if c.Users != nil {
		as.Authenticators = append(as.Authenticators, authn.NewStaticUserAuth(c.Users))
	}
	if c.ExtAuth != nil {
		as.Authenticators = append(as.Authenticators, authn.NewExtAuth(c.ExtAuth))
	}
	if c.GoogleAuth != nil {
		ga, err := authn.NewGoogleAuth(c.GoogleAuth)
		if err != nil {
			return nil, err
		}
		as.Authenticators = append(as.Authenticators, ga)
		as.ga = ga
	}
	if c.GitHubAuth != nil {
		gha, err := authn.NewGitHubAuth(c.GitHubAuth)
		if err != nil {
			return nil, err
		}
		as.Authenticators = append(as.Authenticators, gha)
		as.gha = gha
	}
	if c.LDAPAuth != nil {
		la, err := authn.NewLDAPAuth(c.LDAPAuth)
		if err != nil {
			return nil, err
		}
		as.Authenticators = append(as.Authenticators, la)
	}
	if c.MongoAuth != nil {
		ma, err := authn.NewMongoAuth(c.MongoAuth)
		if err != nil {
			return nil, err
		}
		as.Authenticators = append(as.Authenticators, ma)
	}
	return as, nil
}

// ServeHTTP overrides SimpleServer, adding Github and Google features if enabled.
func (as *AuthServer) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	glog.V(3).Infof("Request: %+v", req)
	path_prefix := as.config.Server.PathPrefix
	switch {
	case req.URL.Path == path_prefix+"/":
		as.DoIndex(rw, req)
	case req.URL.Path == path_prefix+"/auth":
		as.DoAuth(rw, req)
	case req.URL.Path == path_prefix+"/google_auth" && as.ga != nil:
		as.ga.DoGoogleAuth(rw, req)
	case req.URL.Path == path_prefix+"/github_auth" && as.gha != nil:
		as.gha.DoGitHubAuth(rw, req)
	default:
		http.Error(rw, "Not found", http.StatusNotFound)
		return
	}
}

// DoIndex overrides SimpleServer, adding Github and Google features if enabled.
// https://developers.google.com/identity/sign-in/web/server-side-flow
func (as *AuthServer) DoIndex(rw http.ResponseWriter, req *http.Request) {
	switch {
		case as.ga != nil:
			rw.Header().Set("Content-Type", "text/html; charset=utf-8")
			fmt.Fprintf(rw, "<h1>%s</h1>\n", as.config.Token.Issuer)
			fmt.Fprint(rw, `<p><a href="/google_auth">Login with Google account</a></p>`)
		case as.gha != nil:
			url := as.config.Server.PathPrefix + "/github_auth"
			http.Redirect(rw, req, url, 301)
		default:
			rw.Header().Set("Content-Type", "text/html; charset=utf-8")
			fmt.Fprintf(rw, "<h1>%s</h1>\n", as.config.Token.Issuer)
	}
}
