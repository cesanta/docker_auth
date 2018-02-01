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
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/cesanta/docker_auth/auth_server/authn"
	"github.com/cesanta/docker_auth/auth_server/authz"
	"github.com/cesanta/glog"
	"github.com/docker/distribution/registry/auth/token"
)

var (
	hostPortRegex = regexp.MustCompile(`\[?(.+?)\]?:\d+$`)
)

type AuthServer struct {
	config         *Config
	authenticators []authn.Authenticator
	authorizers    []authz.Authorizer
	ga             *authn.GoogleAuth
	gha            *authn.GitHubAuth
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
	if c.ACLMongo != nil {
		mongoAuthorizer, err := authz.NewACLMongoAuthorizer(c.ACLMongo)
		if err != nil {
			return nil, err
		}
		as.authorizers = append(as.authorizers, mongoAuthorizer)
	}
	if c.ExtAuthz != nil {
		extAuthorizer := authz.NewExtAuthzAuthorizer(c.ExtAuthz)
		as.authorizers = append(as.authorizers, extAuthorizer)
	}
	if c.Users != nil {
		as.authenticators = append(as.authenticators, authn.NewStaticUserAuth(c.Users))
	}
	if c.ExtAuth != nil {
		as.authenticators = append(as.authenticators, authn.NewExtAuth(c.ExtAuth))
	}
	if c.GoogleAuth != nil {
		ga, err := authn.NewGoogleAuth(c.GoogleAuth)
		if err != nil {
			return nil, err
		}
		as.authenticators = append(as.authenticators, ga)
		as.ga = ga
	}
	if c.GitHubAuth != nil {
		gha, err := authn.NewGitHubAuth(c.GitHubAuth)
		if err != nil {
			return nil, err
		}
		as.authenticators = append(as.authenticators, gha)
		as.gha = gha
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

type authRequest struct {
	RemoteConnAddr string
	RemoteAddr     string
	RemoteIP       net.IP
	User           string
	Password       authn.PasswordString
	Account        string
	Service        string
	Scopes         []authScope
	Labels         authn.Labels
}

type authScope struct {
	Type    string
	Name    string
	Actions []string
}

type authzResult struct {
	scope            authScope
	autorizedActions []string
}

func (ar authRequest) String() string {
	return fmt.Sprintf("{%s:%s@%s %s}", ar.User, ar.Password, ar.RemoteAddr, ar.Scopes)
}

func parseRemoteAddr(ra string) net.IP {
	hp := hostPortRegex.FindStringSubmatch(ra)
	if hp != nil {
		ra = string(hp[1])
	}
	res := net.ParseIP(ra)
	return res
}

func (as *AuthServer) ParseRequest(req *http.Request) (*authRequest, error) {
	ar := &authRequest{RemoteConnAddr: req.RemoteAddr, RemoteAddr: req.RemoteAddr}
	if as.config.Server.RealIPHeader != "" {
		hv := req.Header.Get(as.config.Server.RealIPHeader)
		ips := strings.Split(hv, ",")

		realIPPos := as.config.Server.RealIPPos
		if realIPPos < 0 {
			realIPPos = len(ips) + realIPPos
			if realIPPos < 0 {
				realIPPos = 0
			}
		}

		ar.RemoteAddr = strings.TrimSpace(ips[realIPPos])
		glog.V(3).Infof("Conn ip %s, %s: %s, addr: %s", ar.RemoteAddr, as.config.Server.RealIPHeader, hv, ar.RemoteAddr)
		if ar.RemoteAddr == "" {
			return nil, fmt.Errorf("client address not provided")
		}
	}
	ar.RemoteIP = parseRemoteAddr(ar.RemoteAddr)
	if ar.RemoteIP == nil {
		return nil, fmt.Errorf("unable to parse remote addr %s", ar.RemoteAddr)
	}
	user, password, haveBasicAuth := req.BasicAuth()
	if haveBasicAuth {
		ar.User = user
		ar.Password = authn.PasswordString(password)
	}
	ar.Account = req.FormValue("account")
	if ar.Account == "" {
		ar.Account = ar.User
	} else if haveBasicAuth && ar.Account != ar.User {
		return nil, fmt.Errorf("user and account are not the same (%q vs %q)", ar.User, ar.Account)
	}
	ar.Service = req.FormValue("service")
	if err := req.ParseForm(); err != nil {
		return nil, fmt.Errorf("invalid form value")
	}
	// https://github.com/docker/distribution/blob/1b9ab303a477ded9bdd3fc97e9119fa8f9e58fca/docs/spec/auth/scope.md#resource-scope-grammar
	if req.FormValue("scope") != "" {
		for _, scopeStr := range req.Form["scope"] {
			parts := strings.Split(scopeStr, ":")
			var scope authScope
			switch len(parts) {
			case 3:
				scope = authScope{
					Type:    parts[0],
					Name:    parts[1],
					Actions: strings.Split(parts[2], ","),
				}
			case 4:
				scope = authScope{
					Type:    parts[0],
					Name:    parts[1] + ":" + parts[2],
					Actions: strings.Split(parts[3], ","),
				}
			default:
				return nil, fmt.Errorf("invalid scope: %q", scopeStr)
			}
			sort.Strings(scope.Actions)
			ar.Scopes = append(ar.Scopes, scope)
		}
	}
	return ar, nil
}

func (as *AuthServer) Authenticate(ar *authRequest) (bool, authn.Labels, error) {
	for i, a := range as.authenticators {
		result, labels, err := a.Authenticate(ar.Account, ar.Password)
		glog.V(2).Infof("Authn %s %s -> %t, %+v, %v", a.Name(), ar.Account, result, labels, err)
		if err != nil {
			if err == authn.NoMatch {
				continue
			} else if err == authn.WrongPass {
				glog.Warningf("Failed authentication with %s: %s", err, ar.Account)
				return false, nil, nil
			}
			err = fmt.Errorf("authn #%d returned error: %s", i+1, err)
			glog.Errorf("%s: %s", ar, err)
			return false, nil, err
		}
		return result, labels, nil
	}
	// Deny by default.
	glog.Warningf("%s did not match any authn rule", ar)
	return false, nil, nil
}

func (as *AuthServer) authorizeScope(ai *authz.AuthRequestInfo) ([]string, error) {
	for i, a := range as.authorizers {
		result, err := a.Authorize(ai)
		glog.V(2).Infof("Authz %s %s -> %s, %s", a.Name(), *ai, result, err)
		if err != nil {
			if err == authz.NoMatch {
				continue
			}
			err = fmt.Errorf("authz #%d returned error: %s", i+1, err)
			glog.Errorf("%s: %s", *ai, err)
			return nil, err
		}
		return result, nil
	}
	// Deny by default.
	glog.Warningf("%s did not match any authz rule", *ai)
	return nil, nil
}

func (as *AuthServer) Authorize(ar *authRequest) ([]authzResult, error) {
	ares := []authzResult{}
	for _, scope := range ar.Scopes {
		ai := &authz.AuthRequestInfo{
			Account: ar.Account,
			Type:    scope.Type,
			Name:    scope.Name,
			Service: ar.Service,
			IP:      ar.RemoteIP,
			Actions: scope.Actions,
			Labels:  ar.Labels,
		}
		actions, err := as.authorizeScope(ai)
		if err != nil {
			return nil, err
		}
		ares = append(ares, authzResult{scope: scope, autorizedActions: actions})
	}
	return ares, nil
}

// https://github.com/docker/distribution/blob/master/docs/spec/auth/token.md#example
func (as *AuthServer) CreateToken(ar *authRequest, ares []authzResult) (string, error) {
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
		Subject:    ar.Account,
		Audience:   ar.Service,
		NotBefore:  now - 10,
		IssuedAt:   now,
		Expiration: now + tc.Expiration,
		JWTID:      fmt.Sprintf("%d", rand.Int63()),
		Access:     []*token.ResourceActions{},
	}
	for _, a := range ares {
		ra := &token.ResourceActions{
			Type:    a.scope.Type,
			Name:    a.scope.Name,
			Actions: a.autorizedActions,
		}
		if ra.Actions == nil {
			ra.Actions = []string{}
		}
		sort.Strings(ra.Actions)
		claims.Access = append(claims.Access, ra)
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
	glog.Infof("New token for %s %+v: %s", *ar, ar.Labels, claimsJSON)
	return fmt.Sprintf("%s%s%s", payload, token.TokenSeparator, joseBase64UrlEncode(sig)), nil
}

func (as *AuthServer) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	glog.V(3).Infof("Request: %+v", req)
	path_prefix := as.config.Server.PathPrefix
	switch {
	case req.URL.Path == path_prefix+"/":
		as.doIndex(rw, req)
	case req.URL.Path == path_prefix+"/auth":
		as.doAuth(rw, req)
	case req.URL.Path == path_prefix+"/google_auth" && as.ga != nil:
		as.ga.DoGoogleAuth(rw, req)
	case req.URL.Path == path_prefix+"/github_auth" && as.gha != nil:
		as.gha.DoGitHubAuth(rw, req)
	default:
		http.Error(rw, "Not found", http.StatusNotFound)
		return
	}
}

// https://developers.google.com/identity/sign-in/web/server-side-flow
func (as *AuthServer) doIndex(rw http.ResponseWriter, req *http.Request) {
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

func (as *AuthServer) doAuth(rw http.ResponseWriter, req *http.Request) {
	ar, err := as.ParseRequest(req)
	ares := []authzResult{}
	if err != nil {
		glog.Warningf("Bad request: %s", err)
		http.Error(rw, fmt.Sprintf("Bad request: %s", err), http.StatusBadRequest)
		return
	}
	glog.V(2).Infof("Auth request: %+v", ar)
	{
		authnResult, labels, err := as.Authenticate(ar)
		if err != nil {
			http.Error(rw, fmt.Sprintf("Authentication failed (%s)", err), http.StatusInternalServerError)
			return
		}
		if !authnResult {
			glog.Warningf("Auth failed: %s", *ar)
			rw.Header()["WWW-Authenticate"] = []string{fmt.Sprintf(`Basic realm="%s"`, as.config.Token.Issuer)}
			http.Error(rw, "Auth failed.", http.StatusUnauthorized)
			return
		}
		ar.Labels = labels
	}
	if len(ar.Scopes) > 0 {
		ares, err = as.Authorize(ar)
		if err != nil {
			http.Error(rw, fmt.Sprintf("Authorization failed (%s)", err), http.StatusInternalServerError)
			return
		}
	} else {
		// Authentication-only request ("docker login"), pass through.
	}
	token, err := as.CreateToken(ar, ares)
	if err != nil {
		msg := fmt.Sprintf("Failed to generate token %s", err)
		http.Error(rw, msg, http.StatusInternalServerError)
		glog.Errorf("%s: %s", ar, msg)
		return
	}
	result, _ := json.Marshal(&map[string]string{"token": token})
	glog.V(3).Infof("%s", result)
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
