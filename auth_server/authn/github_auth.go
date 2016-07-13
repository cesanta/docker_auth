/*
   Copyright 2016 Cesanta Software Ltd.

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
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/golang/glog"
	"github.com/syndtr/goleveldb/leveldb"
)

type GitHubAuthConfig struct {
	Domain       string `yaml:"domain,omitempty"`
	ClientId     string `yaml:"client_id,omitempty"`
	ClientSecret string `yaml:"client_secret,omitempty"`
	TokenDB      string `yaml:"token_db,omitempty"`
	HTTPTimeout  int    `yaml:"http_timeout,omitempty"`
}

type GitHubAuthRequest struct {
	Action string `json:"action,omitempty"`
	Code   string `json:"code,omitempty"`
	Token  string `json:"token,omitempty"`
}

type GitHubTokenUser struct {
	Login string `json:"login,omitempty"`
	Email string `json:"email,omitempty"`
}

type GitHubAuth struct {
	config *GitHubAuthConfig
	db     *TokenDB
	client *http.Client
	tmpl   *template.Template
}

func NewGitHubAuth(c *GitHubAuthConfig) (*GitHubAuth, error) {
	db, err := NewTokenDB(c.TokenDB)
	if err != nil {
		return nil, err
	}
	glog.Infof("GitHub auth token DB at %s", c.TokenDB)
	return &GitHubAuth{
		config: c,
		db:     db,
		client: &http.Client{Timeout: 10 * time.Second},
		tmpl:   template.Must(template.New("github_auth").Parse(string(MustAsset("data/github_auth.tmpl")))),
	}, nil
}

func (gha *GitHubAuth) doGitHubAuthPage(rw http.ResponseWriter, req *http.Request) {
	if err := gha.tmpl.Execute(rw, struct{ ClientId string }{ClientId: gha.config.ClientId}); err != nil {
		http.Error(rw, fmt.Sprintf("Template error: %s", err), http.StatusInternalServerError)
	}
}

func (gha *GitHubAuth) DoGitHubAuth(rw http.ResponseWriter, req *http.Request) {
	code := req.URL.Query().Get("code")

	if code != "" {
		gha.doGitHubAuthCreateToken(rw, code)
	} else if req.Method == "GET" {
		gha.doGitHubAuthPage(rw, req)
		return
	}
}

func (gha *GitHubAuth) doGitHubAuthCreateToken(rw http.ResponseWriter, code string) {
	data := url.Values{
		"code":          []string{string(code)},
		"client_id":     []string{gha.config.ClientId},
		"client_secret": []string{gha.config.ClientSecret},
	}
	req, err := http.NewRequest("POST", "https://github.com/login/oauth/access_token", bytes.NewBufferString(data.Encode()))
	if err != nil {
		http.Error(rw, fmt.Sprintf("Error creating request to GitHub auth backend: %s", err), http.StatusServiceUnavailable)
		return
	}
	req.Header.Add("Accept", "application/json")

	resp, err := gha.client.Do(req)
	if err != nil {
		http.Error(rw, fmt.Sprintf("Error talking to GitHub auth backend: %s", err), http.StatusServiceUnavailable)
		return
	}
	codeResp, _ := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	glog.V(2).Infof("Code to token resp: %s", strings.Replace(string(codeResp), "\n", " ", -1))

	var c2t CodeToTokenResponse
	err = json.Unmarshal(codeResp, &c2t)
	if err != nil || c2t.Error != "" || c2t.ErrorDescription != "" {
		var et string
		if err != nil {
			et = err.Error()
		} else {
			et = fmt.Sprintf("%s: %s", c2t.Error, c2t.ErrorDescription)
		}
		http.Error(rw, fmt.Sprintf("Failed to get token: %s", et), http.StatusBadRequest)
		return
	}

	user, err := gha.getTokenUser(c2t.AccessToken)
	if err != nil {
		glog.Errorf("Newly-acquired token is invalid: %+v %s", c2t, err)
		http.Error(rw, "Newly-acquired token is invalid", http.StatusInternalServerError)
		return
	}

	glog.Infof("New GitHub auth token for %s", user)

	v := &TokenDBValue{
		TokenType:   c2t.TokenType,
		AccessToken: c2t.AccessToken,
	}
	dp, err := gha.db.StoreToken(user, v, true)
	if err != nil {
		glog.Errorf("Failed to record server token: %s", err)
		http.Error(rw, "Failed to record server token: %s", http.StatusInternalServerError)
		return
	}

	fmt.Fprintf(rw, `Server logged in; now run "docker login", use %s as login and %s as password.`, user, dp)
}

func (gha *GitHubAuth) getTokenUser(token string) (string, error) {
	req, err := http.NewRequest("GET", "https://api.github.com/user", nil)
	if err != nil {
		return "", fmt.Errorf("could not create request to get information for token %s: %s", token, err)
	}
	req.Header.Add("Authorization", fmt.Sprintf("token %s", token))
	req.Header.Add("Accept", "application/json")

	resp, err := gha.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("could not verify token %s: %s", token, err)
	}
	body, _ := ioutil.ReadAll(resp.Body)
	resp.Body.Close()

	var ti GitHubTokenUser
	err = json.Unmarshal(body, &ti)
	if err != nil {
		return "", fmt.Errorf("could not unmarshal token user info %q: %s", string(body), err)
	}
	glog.V(2).Infof("Token user info: %+v", strings.Replace(string(body), "\n", " ", -1))

	return ti.Login, nil
}

func (gha *GitHubAuth) getDBValue(user string) (*TokenDBValue, error) {
	valueStr, err := gha.db.Get(getDBKey(user), nil)
	switch {
	case err == leveldb.ErrNotFound:
		return nil, nil
	case err != nil:
		glog.Errorf("error accessing token db: %s", err)
		return nil, fmt.Errorf("error accessing token db: %s", err)
	}
	var dbv TokenDBValue
	err = json.Unmarshal(valueStr, &dbv)
	if err != nil {
		glog.Errorf("bad DB value for %q (%q): %s", user, string(valueStr), err)
		return nil, fmt.Errorf("bad DB value", err)
	}
	return &dbv, nil
}

func (gha *GitHubAuth) Authenticate(user string, password PasswordString) (bool, error) {
	dbv, err := gha.db.GetValue(user)
	if err != nil {
		return false, err
	}
	if dbv == nil {
		return false, NoMatch
	}
	if bcrypt.CompareHashAndPassword([]byte(dbv.DockerPassword), []byte(password)) != nil {
		return false, nil
	}
	return true, nil
}

func (gha *GitHubAuth) Stop() {
	gha.db.Close()
	glog.Info("Token DB closed")
}

func (gha *GitHubAuth) Name() string {
	return "GitHub"
}
