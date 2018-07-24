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

package common

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

	"github.com/cesanta/glog"
	"github.com/docker/distribution/registry/auth/token"

)

var (
	hostPortRegex = regexp.MustCompile(`\[?(.+?)\]?:\d+$`)
)

// SimpleServer rigs the Authenticator and Authorizer interfaces into a cohesive whole, but without provider-specific logic.
// Unless you are using as a library, you probably want the AuthServer in the server package.
type SimpleServer struct {
	Server         ServerConfig
	Token          TokenConfig
	Authenticators []Authenticator
	Authorizers    []Authorizer
}

func (ar AuthRequest) String() string {
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

func (as *SimpleServer) ParseRequest(req *http.Request) (*AuthRequest, error) {
	ar := &AuthRequest{RemoteConnAddr: req.RemoteAddr, RemoteAddr: req.RemoteAddr}
	if as.Server.RealIPHeader != "" {
		hv := req.Header.Get(as.Server.RealIPHeader)
		ips := strings.Split(hv, ",")

		realIPPos := as.Server.RealIPPos
		if realIPPos < 0 {
			realIPPos = len(ips) + realIPPos
			if realIPPos < 0 {
				realIPPos = 0
			}
		}

		ar.RemoteAddr = strings.TrimSpace(ips[realIPPos])
		glog.V(3).Infof("Conn ip %s, %s: %s, addr: %s", ar.RemoteAddr, as.Server.RealIPHeader, hv, ar.RemoteAddr)
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
		ar.Password = PasswordString(password)
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
			var scope AuthScope
			switch len(parts) {
			case 3:
				scope = AuthScope{
					Type:    parts[0],
					Name:    parts[1],
					Actions: strings.Split(parts[2], ","),
				}
			case 4:
				scope = AuthScope{
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

func (as *SimpleServer) Authenticate(ar *AuthRequest) (bool, Labels, error) {
	for i, a := range as.Authenticators {
		result, labels, err := a.Authenticate(ar.Account, ar.Password)
		glog.V(2).Infof("Authn %s %s -> %t, %+v, %v", a.Name(), ar.Account, result, labels, err)
		if err != nil {
			if err == NoMatch {
				continue
			} else if err == WrongPass {
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

func (as *SimpleServer) authorizeScope(ai *AuthRequestInfo) ([]string, error) {
	for i, a := range as.Authorizers {
		result, err := a.Authorize(ai)
		glog.V(2).Infof("Authz %s %s -> %s, %s", a.Name(), *ai, result, err)
		if err != nil {
			if err == NoMatch {
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

func (as *SimpleServer) Authorize(ar *AuthRequest) ([]AuthzResult, error) {
	ares := []AuthzResult{}
	for _, scope := range ar.Scopes {
		ai := &AuthRequestInfo{
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
		ares = append(ares, AuthzResult{Scope: scope, AutorizedActions: actions})
	}
	return ares, nil
}

// https://github.com/docker/distribution/blob/master/docs/spec/auth/token.md#example
func (as *SimpleServer) CreateToken(ar *AuthRequest, ares []AuthzResult) (string, error) {
	now := time.Now().Unix()
	tc := &as.Token

	// Sign something dummy to find out which algorithm is used.
	_, sigAlg, err := tc.PrivateKey.Sign(strings.NewReader("dummy"), 0)
	if err != nil {
		return "", fmt.Errorf("failed to sign: %s", err)
	}
	header := token.Header{
		Type:       "JWT",
		SigningAlg: sigAlg,
		KeyID:      tc.PublicKey.KeyID(),
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
			Type:    a.Scope.Type,
			Name:    a.Scope.Name,
			Actions: a.AutorizedActions,
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

	payload := fmt.Sprintf("%s%s%s", JoseBase64UrlEncode(headerJSON), token.TokenSeparator, JoseBase64UrlEncode(claimsJSON))

	sig, sigAlg2, err := tc.PrivateKey.Sign(strings.NewReader(payload), 0)
	if err != nil || sigAlg2 != sigAlg {
		return "", fmt.Errorf("failed to sign token: %s", err)
	}
	glog.Infof("New token for %s %+v: %s", *ar, ar.Labels, claimsJSON)
	return fmt.Sprintf("%s%s%s", payload, token.TokenSeparator, JoseBase64UrlEncode(sig)), nil
}

func (as *SimpleServer) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	glog.V(3).Infof("Request: %+v", req)
	path_prefix := as.Server.PathPrefix
	switch {
	case req.URL.Path == path_prefix+"/":
		as.DoIndex(rw, req)
	case req.URL.Path == path_prefix+"/auth":
		as.DoAuth(rw, req)
	default:
		http.Error(rw, "Not found", http.StatusNotFound)
		return
	}
}

// https://developers.google.com/identity/sign-in/web/server-side-flow
func (as *SimpleServer) DoIndex(rw http.ResponseWriter, req *http.Request) {
	rw.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(rw, "<h1>%s</h1>\n", as.Token.Issuer)
}

func (as *SimpleServer) DoAuth(rw http.ResponseWriter, req *http.Request) {
	ar, err := as.ParseRequest(req)
	ares := []AuthzResult{}
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
			rw.Header()["WWW-Authenticate"] = []string{fmt.Sprintf(`Basic realm="%s"`, as.Token.Issuer)}
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

func (as *SimpleServer) Stop() {
	for _, an := range as.Authenticators {
		an.Stop()
	}
	for _, az := range as.Authorizers {
		az.Stop()
	}
	glog.Infof("Server stopped")
}

// Copy-pasted from libtrust where it is private.
func JoseBase64UrlEncode(b []byte) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString(b), "=")
}
