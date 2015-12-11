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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/cesanta/docker_auth/auth_server/authn"
	"github.com/cesanta/docker_auth/auth_server/authz"
	"github.com/docker/distribution/registry/auth/token"
	"github.com/golang/glog"
)

type AuthRequest struct {
	RemoteAddr string
	User       string
	Password   authn.PasswordString
	ai         authz.AuthRequestInfo
}

func (ar AuthRequest) String() string {
	return fmt.Sprintf("{%s:%s@%s %s}", ar.User, ar.Password, ar.RemoteAddr, ar.ai)
}

type AuthServer struct {
	config         *Config
	authenticators []authn.Authenticator
	authorizers    []authz.Authorizer
	ga             *authn.GoogleAuth
}

func NewAuthServer(c *Config) (*AuthServer, error) {
	as := &AuthServer{
		config:      c,
		authorizers: []authz.Authorizer{},
	}
	if c.ACL != nil {
		staticAuthorizer, err := authz.NewACLAuthorizer(c.ACL)
		if err != nil {
			return nil, err
		}
		as.authorizers = append(as.authorizers, staticAuthorizer)
	}
	if c.ACLMongoConf != nil {
		mongoAuthorizer, err := authz.NewACLMongoAuthorizer(*c.ACLMongoConf)
		if err != nil {
			return nil, err
		}
		as.authorizers = append(as.authorizers, mongoAuthorizer)
	}
	if c.Users != nil {
		as.authenticators = append(as.authenticators, authn.NewStaticUserAuth(c.Users))
	}
	if c.GoogleAuth != nil {
		ga, err := authn.NewGoogleAuth(c.GoogleAuth)
		if err != nil {
			return nil, err
		}
		as.authenticators = append(as.authenticators, ga)
		as.ga = ga
	}
	if c.LDAPAuth != nil {
		la, err := authn.NewLDAPAuth(c.LDAPAuth)
		if err != nil {
			return nil, err
		}
		as.authenticators = append(as.authenticators, la)
	}
	if c.MongoAuth != nil {
		ma, err := authn.NewMongoAuth(c.MongoAuth)
		if err != nil {
			return nil, err
		}
		as.authenticators = append(as.authenticators, ma)
	}
	return as, nil
}

func parseRemoteAddr(ra string) net.IP {
	colonIndex := strings.LastIndex(ra, ":")
	if colonIndex == -1 {
		return nil
	}
	ra = ra[:colonIndex]
	if ra[0] == '[' && ra[len(ra)-1] == ']' { // IPv6
		ra = ra[1 : len(ra)-1]
	}
	res := net.ParseIP(ra)
	return res
}

func (as *AuthServer) ParseRequest(req *http.Request) (*AuthRequest, error) {
	ar := &AuthRequest{RemoteAddr: req.RemoteAddr}
	ar.ai.IP = parseRemoteAddr(req.RemoteAddr)
	if ar.ai.IP == nil {
		return nil, fmt.Errorf("unable to parse remote addr %s", req.RemoteAddr)
	}
	user, password, haveBasicAuth := req.BasicAuth()
	if haveBasicAuth {
		ar.User = user
		ar.Password = authn.PasswordString(password)
	}
	ar.ai.Account = req.FormValue("account")
	if ar.ai.Account == "" {
		ar.ai.Account = ar.User
	} else if haveBasicAuth && ar.ai.Account != ar.User {
		return nil, fmt.Errorf("user and account are not the same (%q vs %q)", ar.User, ar.ai.Account)
	}
	ar.ai.Service = req.FormValue("service")
	scope := req.FormValue("scope")
	if scope != "" {
		parts := strings.Split(scope, ":")
		if len(parts) != 3 {
			return nil, fmt.Errorf("invalid scope: %q", scope)
		}
		ar.ai.Type = parts[0]
		ar.ai.Name = parts[1]
		ar.ai.Actions = strings.Split(parts[2], ",")
		sort.Strings(ar.ai.Actions)
	}
	return ar, nil
}

func (as *AuthServer) Authenticate(ar *AuthRequest) (bool, error) {
	for i, a := range as.authenticators {
		result, err := a.Authenticate(ar.ai.Account, ar.Password)
		glog.V(2).Infof("Authn %s %s -> %t, %s", a.Name(), ar.ai.Account, result, err)
		if err != nil {
			if err == authn.NoMatch {
				continue
			}
			err = fmt.Errorf("authn #%d returned error: %s", i+1, err)
			glog.Errorf("%s: %s", ar, err)
			return false, err
		}
		return result, nil
	}
	// Deny by default.
	glog.Warningf("%s did not match any authn rule", ar.ai)
	return false, nil
}

func (as *AuthServer) Authorize(ar *AuthRequest) ([]string, error) {
	for i, a := range as.authorizers {
		result, err := a.Authorize(&ar.ai)
		glog.V(2).Infof("Authz %s %s -> %s, %s", a.Name(), ar.ai, result, err)
		if err != nil {
			if err == authz.NoMatch {
				continue
			}
			err = fmt.Errorf("authz #%d returned error: %s", i+1, err)
			glog.Errorf("%s: %s", ar, err)
			return nil, authz.NoMatch
		}
		return result, nil
	}
	// Deny by default.
	glog.Warningf("%s did not match any authz rule", ar.ai)
	return nil, nil
}

// https://github.com/docker/distribution/blob/master/docs/spec/auth/token.md#example
func (as *AuthServer) CreateToken(ar *AuthRequest, actions []string) (string, error) {
	now := time.Now().Unix()
	tc := &as.config.Token

	// Sign something dummy to find out which algorithm is used.
	_, sigAlg, err := tc.privateKey.Sign(strings.NewReader("dummy"), 0)
	if err != nil {
		return "", fmt.Errorf("failed to sign: %s", err)
	}
	header := token.Header{
		Type:       "JWT",
		SigningAlg: sigAlg,
		KeyID:      tc.publicKey.KeyID(),
	}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("failed to marshal header: %s", err)
	}

	claims := token.ClaimSet{
		Issuer:     tc.Issuer,
		Subject:    ar.ai.Account,
		Audience:   ar.ai.Service,
		NotBefore:  now - 1,
		IssuedAt:   now,
		Expiration: now + tc.Expiration,
		JWTID:      fmt.Sprintf("%d", rand.Int63()),
		Access:     []*token.ResourceActions{},
	}
	if len(actions) > 0 {
		claims.Access = []*token.ResourceActions{
			&token.ResourceActions{Type: ar.ai.Type, Name: ar.ai.Name, Actions: actions},
		}
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("failed to marshal claims: %s", err)
	}

	payload := fmt.Sprintf("%s%s%s", joseBase64UrlEncode(headerJSON), token.TokenSeparator, joseBase64UrlEncode(claimsJSON))

	sig, sigAlg2, err := tc.privateKey.Sign(strings.NewReader(payload), 0)
	if err != nil || sigAlg2 != sigAlg {
		return "", fmt.Errorf("failed to sign token: %s", err)
	}
	glog.Infof("New token for %s: %s", *ar, claimsJSON)
	return fmt.Sprintf("%s%s%s", payload, token.TokenSeparator, joseBase64UrlEncode(sig)), nil
}

func (as *AuthServer) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	glog.V(3).Infof("Request: %+v", req)
	switch {
	case req.URL.Path == "/":
		as.doIndex(rw, req)
	case req.URL.Path == "/auth":
		as.doAuth(rw, req)
	case req.URL.Path == "/google_auth" && as.ga != nil:
		as.ga.DoGoogleAuth(rw, req)
	default:
		http.Error(rw, "Not found", http.StatusNotFound)
		return
	}
}

// https://developers.google.com/identity/sign-in/web/server-side-flow
func (as *AuthServer) doIndex(rw http.ResponseWriter, req *http.Request) {
	rw.Header().Set("Content-Type", "text-html; charset=utf-8")
	fmt.Fprintf(rw, "<h1>%s</h1>\n", as.config.Token.Issuer)
	if as.ga != nil {
		fmt.Fprint(rw, `<a href="/google_auth">Login with Google account</a>`)
	}
}

func (as *AuthServer) doAuth(rw http.ResponseWriter, req *http.Request) {
	ar, err := as.ParseRequest(req)
	authorizedActions := []string{}
	if err != nil {
		glog.Warningf("Bad request: %s", err)
		http.Error(rw, fmt.Sprintf("Bad request: %s", err), http.StatusBadRequest)
		return
	}
	glog.V(2).Infof("Auth request: %+v", ar)
	{
		authnResult, err := as.Authenticate(ar)
		if err != nil {
			http.Error(rw, fmt.Sprintf("Authentication failed (%s)", err), http.StatusInternalServerError)
			return
		}
		if !authnResult {
			glog.Warningf("Auth failed: %s", *ar)
			http.Error(rw, "Auth failed.", http.StatusUnauthorized)
			return
		}
	}
	if len(ar.ai.Actions) > 0 {
		authorizedActions, err = as.Authorize(ar)
		if err != nil {
			http.Error(rw, fmt.Sprintf("Authorization failed (%s)", err), http.StatusInternalServerError)
			return
		}
	} else {
		// Authenticaltion-only request ("docker login"), pass through.
	}
	token, err := as.CreateToken(ar, authorizedActions)
	if err != nil {
		msg := fmt.Sprintf("Failed to generate token %s", err)
		http.Error(rw, msg, http.StatusInternalServerError)
		glog.Errorf("%s: %s", ar, msg)
		return
	}
	result, _ := json.Marshal(&map[string]string{"token": token})
	glog.V(2).Infof("%s", result)
	rw.Header().Set("Content-Type", "application/json")
	rw.Write(result)
}

func (as *AuthServer) Stop() {
	for _, an := range as.authenticators {
		an.Stop()
	}
	for _, az := range as.authorizers {
		az.Stop()
	}
	glog.Infof("Server stopped")
}

// Copy-pasted from libtrust where it is private.
func joseBase64UrlEncode(b []byte) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString(b), "=")
}
