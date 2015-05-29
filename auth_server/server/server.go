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
	"errors"
	"fmt"
	"math/rand"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/docker/distribution/registry/auth/token"
	"github.com/golang/glog"
	"golang.org/x/crypto/bcrypt"
)

type AuthRequest struct {
	RemoteAddr string
	User       string
	Password   PasswordString

	Account string
	Type    string
	Name    string
	Service string
	Actions []string
}

func (ar AuthRequest) String() string {
	return fmt.Sprintf("{%s:%s@%s %s %s %s %s}", ar.User, ar.Password, ar.RemoteAddr, ar.Account, strings.Join(ar.Actions, ","), ar.Type, ar.Name)
}

type PasswordString string

func (ps PasswordString) String() string {
	if len(ps) == 0 {
		return ""
	}
	return "***"
}

type AuthServer struct {
	config *Config
}

func NewAuthServer(c *Config) *AuthServer {
	return &AuthServer{config: c}
}

func (as *AuthServer) ParseRequest(req *http.Request) (*AuthRequest, error) {
	ar := &AuthRequest{RemoteAddr: req.RemoteAddr, Actions: []string{}}
	user, password, haveBasicAuth := req.BasicAuth()
	if haveBasicAuth {
		ar.User = user
		ar.Password = PasswordString(password)
	}
	ar.Account = req.FormValue("account")
	if ar.Account == "" {
		ar.Account = ar.User
	}
	ar.Service = req.FormValue("service")
	scope := req.FormValue("scope")
	if scope != "" {
		parts := strings.Split(scope, ":")
		if len(parts) != 3 {
			return nil, fmt.Errorf("invalid scope: %q", scope)
		}
		ar.Type = parts[0]
		ar.Name = parts[1]
		ar.Actions = strings.Split(parts[2], ",")
		sort.Strings(ar.Actions)
	}
	return ar, nil
}

func (as *AuthServer) Authenticate(ar *AuthRequest) error {
	reqs := as.config.Users[ar.Account]
	if reqs == nil {
		return errors.New("unknown user")
	}
	if reqs.Password != nil {
		if bcrypt.CompareHashAndPassword([]byte(*reqs.Password), []byte(ar.Password)) != nil {
			return errors.New("wrong password")
		}
	}
	return nil
}

func (as *AuthServer) Authorize(ar *AuthRequest) (bool, error) {
	var e *ACLEntry
	var err error
	matched, allowed := false, false
	for _, e = range as.config.ACL {
		matched = e.Matches(ar)
		if matched {
			err = e.Check(ar)
			allowed = (err == nil)
			break
		}
	}
	if matched {
		if allowed {
			glog.V(2).Infof("%s allowed by %s", ar, e)
		} else {
			glog.Warningf("%s denied by %s: %s", ar, e, err)
		}
	} else {
		glog.Warningf("%s did not match any rule", ar)
	}
	return allowed, err
}

// https://github.com/docker/distribution/blob/master/docs/spec/auth/token.md#example
func (as *AuthServer) CreateToken(ar *AuthRequest) (string, error) {
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
		NotBefore:  now - 1,
		IssuedAt:   now,
		Expiration: now + tc.Expiration,
		JWTID:      fmt.Sprintf("%d", rand.Int63()),
		Access:     []*token.ResourceActions{},
	}
	if len(ar.Actions) > 0 {
		claims.Access = []*token.ResourceActions{
			&token.ResourceActions{Type: ar.Type, Name: ar.Name, Actions: ar.Actions},
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
	glog.Infof("New token: %s", claimsJSON)
	return fmt.Sprintf("%s%s%s", payload, token.TokenSeparator, joseBase64UrlEncode(sig)), nil
}

func (as *AuthServer) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	glog.V(2).Infof("Request: %+v", req)
	ar, err := as.ParseRequest(req)
	if err != nil {
		http.Error(rw, fmt.Sprintf("Bad request %s", err), http.StatusBadRequest)
		return
	}
	if err = as.Authenticate(ar); err != nil {
		http.Error(rw, err.Error(), http.StatusUnauthorized)
		glog.Errorf("%s: %s", ar, err)
		return
	}
	if len(ar.Actions) > 0 {
		if allowed, err := as.Authorize(ar); !allowed {
			http.Error(rw, fmt.Sprintf("Access denied (%s)", err), http.StatusForbidden)
			return
		}
	} else {
		// Authenticaltion-only request ("docker login"), pass through.
	}
	token, err := as.CreateToken(ar)
	if err != nil {
		msg := fmt.Sprintf("Failed to generate token %s", err)
		http.Error(rw, msg, http.StatusInternalServerError)
		glog.Errorf("%s: %s", ar, msg)
		return
	}
	result, _ := json.Marshal(&map[string]string{"token": token})
	glog.V(2).Infof("%s", result)
	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(http.StatusOK)
	rw.Write([]byte(result))
}

// Copy-pasted from libtrust where it is private.
func joseBase64UrlEncode(b []byte) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString(b), "=")
}
