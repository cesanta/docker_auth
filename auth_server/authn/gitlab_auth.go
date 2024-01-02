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
	"errors"
	"fmt"
	"html/template"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/cesanta/glog"

	"github.com/cesanta/docker_auth/auth_server/api"
)

type GitlabTeamCollection []GitlabTeam

type GitlabTeam struct {
	Id           int64               `json:"id"`
	Url          string              `json:"url,omitempty"`
	Name         string              `json:"name,omitempty"`
	Slug         string              `json:"slug,omitempty"`
	Organization *GitlabOrganization `json:"organization"`
	Parent       *ParentGitlabTeam   `json:"parent,omitempty"`
}

type GitlabOrganization struct {
	Login string `json:"login"`
	Id    int64  `json:"id,omitempty"`
}

type ParentGitlabTeam struct {
	Id   int64  `json:"id"`
	Name string `json:"name,omitempty"`
	Slug string `json:"slug,omitempty"`
}

type GitlabAuthConfig struct {
	Organization     string              `yaml:"organization,omitempty"`
	ClientId         string              `yaml:"client_id,omitempty"`
	ClientSecret     string              `yaml:"client_secret,omitempty"`
	ClientSecretFile string              `yaml:"client_secret_file,omitempty"`
	LevelTokenDB     *LevelDBStoreConfig `yaml:"level_token_db,omitempty"`
	GCSTokenDB       *GCSStoreConfig     `yaml:"gcs_token_db,omitempty"`
	RedisTokenDB     *RedisStoreConfig   `yaml:"redis_token_db,omitempty"`
	HTTPTimeout      time.Duration       `yaml:"http_timeout,omitempty"`
	RevalidateAfter  time.Duration       `yaml:"revalidate_after,omitempty"`
	GitlabWebUri     string              `yaml:"gitlab_web_uri,omitempty"`
	GitlabApiUri     string              `yaml:"gitlab_api_uri,omitempty"`
	RegistryUrl      string              `yaml:"registry_url,omitempty"`
	GrantType        string              `yaml:"grant_type,omitempty"`
	RedirectUri      string              `yaml:"redirect_uri,omitempty"`
}

type CodeToGitlabTokenResponse struct {
	AccessToken  string `json:"access_token,omitempty"`
	TokenType    string `json:"token_type,omitempty"`
	ExpiresIn    int64  `json:"expires_in,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	CreatedAt    int64  `json:"created_at,omitempty"`

	// Returned in case of error.
	Error            string `json:"error,omitempty"`
	ErrorDescription string `json:"error_description,omitempty"`
}

type GitlabAuthRequest struct {
	Action string `json:"action,omitempty"`
	Code   string `json:"code,omitempty"`
	Token  string `json:"token,omitempty"`
}

type GitlabTokenUser struct {
	Login string `json:"username,omitempty"`
	Email string `json:"email,omitempty"`
}

type GitlabAuth struct {
	config     *GitlabAuthConfig
	db         TokenDB
	client     *http.Client
	tmpl       *template.Template
	tmplResult *template.Template
}


func NewGitlabAuth(c *GitlabAuthConfig) (*GitlabAuth, error) {
	var db TokenDB
	var err error
	var dbName string

	switch {
	case c.GCSTokenDB != nil:
		db, err = NewGCSTokenDB(c.GCSTokenDB)
		dbName = "GCS: " + c.GCSTokenDB.Bucket
	case c.RedisTokenDB != nil:
		db, err = NewRedisTokenDB(c.RedisTokenDB)
		dbName = db.(*redisTokenDB).String()
	default:
		db, err = NewTokenDB(c.LevelTokenDB)
		dbName = c.LevelTokenDB.Path
	}

	if err != nil {
		return nil, err
	}
	glog.Infof("GitLab auth token DB at %s", dbName)
	gitlab_auth, _ := static.ReadFile("data/gitlab_auth.tmpl")
	gitlab_auth_result, _ := static.ReadFile("data/gitlab_auth_result.tmpl")
	return &GitlabAuth{
		config:     c,
		db:         db,
		client:     &http.Client{Timeout: c.HTTPTimeout},
		tmpl:       template.Must(template.New("gitlab_auth").Parse(string(gitlab_auth))),
		tmplResult: template.Must(template.New("gitlab_auth_result").Parse(string(gitlab_auth_result))),
	}, nil
}

func (glab *GitlabAuth) doGitlabAuthPage(rw http.ResponseWriter, req *http.Request) {
	if err := glab.tmpl.Execute(rw, struct {
		ClientId, GitlabWebUri, Organization, RedirectUri string
	}{
		ClientId:     glab.config.ClientId,
		GitlabWebUri: glab.getGitlabWebUri(),
		Organization: glab.config.Organization,
		RedirectUri:  glab.config.RedirectUri}); err != nil {
		http.Error(rw, fmt.Sprintf("Template error: %s", err), http.StatusInternalServerError)
	}
}

func (glab *GitlabAuth) doGitlabAuthResultPage(rw http.ResponseWriter, username string, password string) {
	if err := glab.tmplResult.Execute(rw, struct {
		Organization, Username, Password, RegistryUrl string
	}{Organization: glab.config.Organization,
		Username:    username,
		Password:    password,
		RegistryUrl: glab.config.RegistryUrl}); err != nil {
		http.Error(rw, fmt.Sprintf("Template error: %s", err), http.StatusInternalServerError)
	}
}

func (glab *GitlabAuth) DoGitlabAuth(rw http.ResponseWriter, req *http.Request) {
	code := req.URL.Query().Get("code")

	if code != "" {
		glab.doGitlabAuthCreateToken(rw, code)
	} else if req.Method == "GET" {
		glab.doGitlabAuthPage(rw, req)
		return
	}
}

func (glab *GitlabAuth) getGitlabApiUri() string {
	if glab.config.GitlabApiUri != "" {
		return glab.config.GitlabApiUri
	} else {
		return "https://gitlab.com"
	}
}

func (glab *GitlabAuth) getGitlabWebUri() string {
	if glab.config.GitlabWebUri != "" {
		return glab.config.GitlabWebUri
	} else {
		return "https://gitlab.com/api/v4"
	}
}

func (glab *GitlabAuth) doGitlabAuthCreateToken(rw http.ResponseWriter, code string) {
	data := url.Values{
		"client_id":     []string{glab.config.ClientId},
		"client_secret": []string{glab.config.ClientSecret},
		"code":          []string{string(code)},
		"grant_type":    []string{glab.config.GrantType},
		"redirect_uri":  []string{glab.config.RedirectUri},
	}
	req, err := http.NewRequest("POST", fmt.Sprintf("%s/oauth/token", glab.getGitlabWebUri()), bytes.NewBufferString(data.Encode()))
	if err != nil {
		http.Error(rw, fmt.Sprintf("Error creating request to GitHub auth backend: %s", err), http.StatusServiceUnavailable)
		return
	}
	req.Header.Add("Accept", "application/json")
	resp, err := glab.client.Do(req)
	if err != nil {
		http.Error(rw, fmt.Sprintf("Error talking to GitLab auth backend: %s", err), http.StatusServiceUnavailable)
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
	user, err := glab.validateGitlabAccessToken(c2t.AccessToken)
	if err != nil {
		glog.Errorf("Newly-acquired token is invalid: %+v %s", c2t, err)
		http.Error(rw, "Newly-acquired token is invalid", http.StatusInternalServerError)
		return
	}

	glog.Infof("New GitLab auth token for %s", user)


	v := &TokenDBValue{
		TokenType:   c2t.TokenType,
		AccessToken: c2t.AccessToken,
		ValidUntil:  time.Now().Add(glab.config.RevalidateAfter),
	}
	dp, err := glab.db.StoreToken(user, v, true)
	if err != nil {
		glog.Errorf("Failed to record server token: %s", err)
		http.Error(rw, "Failed to record server token: %s", http.StatusInternalServerError)
		return
	}
	glab.doGitlabAuthResultPage(rw, user, dp)
}

func (glab *GitlabAuth) validateGitlabAccessToken(token string) (user string, err error) {
	glog.Infof("Gitlab API: Fetching user info")
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/user", glab.getGitlabApiUri()),nil)

	if err != nil {
		err = fmt.Errorf("could not create request to get information for token %s: %s", token, err)
		return
	}
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))

	resp, err := glab.client.Do(req)
	if err != nil {
		err = fmt.Errorf("could not verify token %s: %s", token, err)
		return
	}
	body, _ := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	var ti GitlabTokenUser
	err = json.Unmarshal(body, &ti)
	if err != nil {
		err = fmt.Errorf("could not unmarshal token user info %q: %s", string(body), err)
		return
	}
	glog.V(2).Infof("Token user info: %+v", strings.Replace(string(body), "\n", " ", -1))
	return ti.Login, nil
}

func (glab *GitlabAuth) checkGitlabOrganization(token, user string) (err error) {
	if glab.config.Organization == "" {
		return nil
	}
	glog.Infof("Gitlab API: Fetching organization membership info")
	url := fmt.Sprintf("%s/orgs/%s/members/%s", glab.getGitlabApiUri(), glab.config.Organization, user)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		err = fmt.Errorf("could not create request to get organization membership: %s", err)
		return
	}
	req.Header.Add("Authorization", fmt.Sprintf("token %s", token))

	resp, err := glab.client.Do(req)
	if err != nil {
		return
	}
	switch resp.StatusCode {
	case http.StatusNoContent:
		return nil
	case http.StatusNotFound:
		return fmt.Errorf("user %s is not a member of organization %s", user, glab.config.Organization)
	case http.StatusFound:
		return fmt.Errorf("token %s could not get membership for organization %s", token, glab.config.Organization)
	}

	return fmt.Errorf("Unknown status for membership of organization %s: %s", glab.config.Organization, resp.Status)
}


func (glab *GitlabAuth) validateGitlabServerToken(user string) (*TokenDBValue, error) {
	v, err := glab.db.GetValue(user)
	if err != nil || v == nil {
		if err == nil {
			err = errors.New("no db value, please sign out and sign in again")
		}
		return nil, err
	}

	texp := v.ValidUntil.Sub(time.Now())
	glog.V(3).Infof("Existing Gitlab auth token for <%s> expires after: <%d> sec", user, int(texp.Seconds()))

	glog.V(1).Infof("Token has expired. I will revalidate the access token.")
	glog.V(3).Infof("Old token is: %+v", v)
	tokenUser, err := glab.validateGitlabAccessToken(v.AccessToken)
	if err != nil {
		glog.Warningf("Token for %q failed validation: %s", user, err)
		return nil, fmt.Errorf("server token invalid: %s", err)
	}
	if tokenUser != user {
		glog.Errorf("token for wrong user: expected %s, found %s", user, tokenUser)
		return nil, fmt.Errorf("found token for wrong user")
	}

	// Update revalidation timestamp
	v.ValidUntil = time.Now().Add(glab.config.RevalidateAfter)
	glog.V(3).Infof("New token is: %+v", v)

	// Update token
	_, err = glab.db.StoreToken(user, v, false)
	if err != nil {
		glog.Errorf("Failed to record server token: %s", err)
		return nil, fmt.Errorf("Unable to store renewed token expiry time: %s", err)
	}
	glog.V(2).Infof("Successfully revalidated token")

	texp = v.ValidUntil.Sub(time.Now())
	glog.V(3).Infof("Re-validated Gitlab auth token for %s. Next revalidation in %dsec.", user, int64(texp.Seconds()))
	return v, nil
}

func (glab *GitlabAuth) Authenticate(user string, password api.PasswordString) (bool, api.Labels, error) {
	err := glab.db.ValidateToken(user, password)
	if err == ExpiredToken {
		_, err = glab.validateGitlabServerToken(user)
		if err != nil {
			return false, nil, err
		}
	} else if err != nil {
		return false, nil, err
	}

	v, err := glab.db.GetValue(user)
	if err != nil || v == nil {
		if err == nil {
			err = errors.New("no db value, please sign out and sign in again")
		}
		return false, nil, err
	}

	return true, v.Labels, nil
}

func (glab *GitlabAuth) Stop() {
	glab.db.Close()
	glog.Info("Token DB closed")
}

func (glab *GitlabAuth) Name() string {
	return "Gitlab"
}
