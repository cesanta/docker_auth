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

package authn

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/cesanta/glog"
)

type KeycloakDirectGrantAuthConfig struct {
	URI              string        `yaml:"uri"`
	Realm            string        `yaml:"realm"`
	ClientID         string        `yaml:"client_id"`
	ClientSecret     string        `yaml:"client_secret"`
	ClientSecretFile string        `yaml:"client_secret_file,omitempty"`
	HTTPTimeout      time.Duration `yaml:"http_timeout,omitempty"`
}

type KeycloakDirectGrantAuth struct {
	config *KeycloakDirectGrantAuthConfig
	client *http.Client
}

// TokenResponse is sent by Keycloak server in response to the grant_type=password request.
type TokenResponse struct {
	AccessToken  string `json:"access_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	ExpiresIn    int64  `json:"expires_in,omitempty"`
	TokenType    string `json:"token_type,omitempty"`
	SessionState string `json:"session_state,omitempty"`
	// Returned in case of error.
	Error            string `json:"error,omitempty"`
	ErrorDescription string `json:"error_description,omitempty"`
}

func NewKeycloakDirectGrantAuth(c *KeycloakDirectGrantAuthConfig) *KeycloakDirectGrantAuth {
	return &KeycloakDirectGrantAuth{
		config: c,
		client: &http.Client{Timeout: c.HTTPTimeout * time.Second},
	}
}

func (kauth *KeycloakDirectGrantAuth) Authenticate(user string, password PasswordString) (bool, Labels, error) {
	err := kauth.validateAccount(user, password)
	if err != nil {
		return false, nil, err
	}
	return true, nil, nil
}

func (kauth *KeycloakDirectGrantAuth) validateAccount(user string, password PasswordString) error {
	uri := fmt.Sprintf("%s/auth/realms/%s/protocol/openid-connect/token", kauth.config.URI, kauth.config.Realm)
	v := url.Values{
		"client_id":  []string{kauth.config.ClientID},
		"grant_type": []string{"password"},
		"username":   []string{user},
		"password":   []string{string(password)},
	}
	if kauth.config.ClientSecret != "" {
		v.Set("client_secret", kauth.config.ClientSecret)
	}
	resp, err := kauth.client.PostForm(uri, v)
	if err != nil {
		err = fmt.Errorf("Error talking to Keycloak: %s", err)
		return err
	}
	body, _ := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		return WrongPass
	}
	var tr TokenResponse
	err = json.Unmarshal(body, &tr)
	if err != nil || tr.Error != "" || tr.ErrorDescription != "" {
		var et string
		if err != nil {
			et = err.Error()
		} else {
			et = fmt.Sprintf("%s: %s", tr.Error, tr.ErrorDescription)
		}
		err = fmt.Errorf("Failed to authenticate(%s): %s", resp.Status, et)
		return err
	}
	glog.V(2).Infof("Token info: %+v", strings.Replace(string(body), "\n", " ", -1))
	return nil
}

func (kauth *KeycloakDirectGrantAuth) Stop() {
}

func (kauth *KeycloakDirectGrantAuth) Name() string {
	return "KeycloakDirectGrant"
}
