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

	"github.com/casbin/casbin/v2"
	"github.com/cesanta/glog"
	"github.com/docker/distribution/registry/auth/token"

	"github.com/cesanta/docker_auth/auth_server/api"
	"github.com/cesanta/docker_auth/auth_server/authn"
	"github.com/cesanta/docker_auth/auth_server/authz"
)

var (
	hostPortRegex = regexp.MustCompile(`^(?:\[(.+)\]:\d+|([^:]+):\d+)$`)
	scopeRegex    = regexp.MustCompile(`([a-z0-9]+)(\([a-z0-9]+\))?`)
)

type AuthServer struct {
	config         *Config
	authenticators []api.Authenticator
	authorizers    []api.Authorizer
	ga             *authn.GoogleAuth
	gha            *authn.GitHubAuth
	oidc           *authn.OIDCAuth
	glab           *authn.GitlabAuth
}

func NewAuthServer(c *Config) (*AuthServer, error) {
	as := &AuthServer{
		config:      c,
		authorizers: []api.Authorizer{},
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
	if c.ACLXorm != nil {
		xormAuthorizer, err := authz.NewACLXormAuthz(c.ACLXorm)
		if err != nil {
			return nil, err
		}
		as.authorizers = append(as.authorizers, xormAuthorizer)
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
	if c.OIDCAuth != nil {
		oidc, err := authn.NewOIDCAuth(c.OIDCAuth)
		if err != nil {
			return nil, err
		}
		as.authenticators = append(as.authenticators, oidc)
		as.oidc = oidc
	}
	if c.GitlabAuth != nil {
		glab, err := authn.NewGitlabAuth(c.GitlabAuth)
		if err != nil {
			return nil, err
		}
		as.authenticators = append(as.authenticators, glab)
		as.glab = glab
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
	if c.XormAuthn != nil {
		xa, err := authn.NewXormAuth(c.XormAuthn)
		if err != nil {
			return nil, err
		}
		as.authenticators = append(as.authenticators, xa)
	}
	if c.PluginAuthn != nil {
		pluginAuthn, err := authn.NewPluginAuthn(c.PluginAuthn)
		if err != nil {
			return nil, err
		}
		as.authenticators = append(as.authenticators, pluginAuthn)
	}
	if c.PluginAuthz != nil {
		pluginAuthz, err := authz.NewPluginAuthzAuthorizer(c.PluginAuthz)
		if err != nil {
			return nil, err
		}
		as.authorizers = append(as.authorizers, pluginAuthz)
	}
	if c.CasbinAuthz != nil {
		enforcer, err := casbin.NewEnforcer(c.CasbinAuthz.ModelFilePath, c.CasbinAuthz.PolicyFilePath)
		if err != nil {
			return nil, err
		}
		casbinAuthz, err := authz.NewCasbinAuthorizer(enforcer)
		if err != nil {
			return nil, err
		}
		as.authorizers = append(as.authorizers, casbinAuthz)
	}
	return as, nil
}

type authRequest struct {
	RemoteConnAddr string
	RemoteAddr     string
	RemoteIP       net.IP
	User           string
	Password       api.PasswordString
	Account        string
	Service        string
	Scopes         []authScope
	Labels         api.Labels
}

type authScope struct {
	Type    string
	Class   string
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
		if hp[1] != "" {
			ra = hp[1]
		} else if hp[2] != "" {
			ra = hp[2]
		}
	}
	res := net.ParseIP(ra)
	return res
}

func parseScope(scope string) (string, string, error) {
	parts := scopeRegex.FindStringSubmatch(scope)
	if parts == nil {
		return "", "", fmt.Errorf("malformed scope request")
	}

	switch len(parts) {
	case 3:
		return parts[1], "", nil
	case 4:
		return parts[1], parts[3], nil
	default:
		return "", "", fmt.Errorf("malformed scope request")
	}
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
		ar.Password = api.PasswordString(password)
	} else if req.Method == "POST" {
		// username and password could be part of form data
		username := req.FormValue("username")
		password := req.FormValue("password")
		if username != "" && password != "" {
			ar.User = username
			ar.Password = api.PasswordString(password)
		}
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
		for _, scopeValue := range req.Form["scope"] {
			for _, scopeStr := range strings.Split(scopeValue, " ") {
				parts := strings.Split(scopeStr, ":")
				var scope authScope

				scopeType, scopeClass, err := parseScope(parts[0])
				if err != nil {
					return nil, err
				}

				switch len(parts) {
				case 3:
					scope = authScope{
						Type:    scopeType,
						Class:   scopeClass,
						Name:    parts[1],
						Actions: strings.Split(parts[2], ","),
					}
				case 4:
					scope = authScope{
						Type:    scopeType,
						Class:   scopeClass,
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
	}
	return ar, nil
}

func (as *AuthServer) Authenticate(ar *authRequest) (bool, api.Labels, error) {
	for i, a := range as.authenticators {
		result, labels, err := a.Authenticate(ar.Account, ar.Password)
		glog.V(2).Infof("Authn %s %s -> %t, %+v, %v", a.Name(), ar.Account, result, labels, err)
		if err != nil {
			if err == api.NoMatch {
				continue
			} else if err == api.WrongPass {
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

func (as *AuthServer) authorizeScope(ai *api.AuthRequestInfo) ([]string, error) {
	for i, a := range as.authorizers {
		result, err := a.Authorize(ai)
		glog.V(2).Infof("Authz %s %s -> %s, %s", a.Name(), *ai, result, err)
		if err != nil {
			if err == api.NoMatch {
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
		ai := &api.AuthRequestInfo{
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

	header := token.Header{
		Type:       "JWT",
		SigningAlg: tc.sigAlg,
		KeyID:      tc.keyID,
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
	if err != nil || sigAlg2 != tc.sigAlg {
		return "", fmt.Errorf("failed to sign token: %s", err)
	}
	glog.Infof("New token for %s %+v: %s", *ar, ar.Labels, claimsJSON)
	return fmt.Sprintf("%s%s%s", payload, token.TokenSeparator, joseBase64UrlEncode(sig)), nil
}

func (as *AuthServer) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	glog.V(3).Infof("Request: %+v", req)
	path_prefix := as.config.Server.PathPrefix
	if as.config.Server.HSTS {
		rw.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
	}
	switch {
	case req.URL.Path == path_prefix+"/":
		as.doIndex(rw, req)
	case req.URL.Path == path_prefix+"/auth":
		as.doAuth(rw, req)
	case req.URL.Path == path_prefix+"/auth/token":
		as.doAuth(rw, req) 
	case req.URL.Path == path_prefix+"/google_auth" && as.ga != nil:
		as.ga.DoGoogleAuth(rw, req)
	case req.URL.Path == path_prefix+"/github_auth" && as.gha != nil:
		as.gha.DoGitHubAuth(rw, req)
	case req.URL.Path == path_prefix+"/oidc_auth" && as.oidc != nil:
		as.oidc.DoOIDCAuth(rw, req)
	case req.URL.Path == path_prefix+"/gitlab_auth" && as.glab != nil:
		as.glab.DoGitlabAuth(rw, req)
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
	case as.oidc != nil:
		url := as.config.Server.PathPrefix + "/oidc_auth"
		http.Redirect(rw, req, url, 301)
	case as.glab != nil:
		url := as.config.Server.PathPrefix + "/gitlab_auth"
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
	// https://www.oauth.com/oauth2-servers/access-tokens/access-token-response/
	// describes that the response should have the token in `access_token`
	// https://docs.docker.com/registry/spec/auth/token/#token-response-fields
	// the token should also be in `token` to support older clients
	result, _ := json.Marshal(&map[string]string{"access_token": token, "token": token})
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
