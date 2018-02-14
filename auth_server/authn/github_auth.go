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
)

type GitHubTeamCollection []GitHubTeam

type GitHubTeam struct {
	Id              int64               `json:"id"`
	Url             string              `json:"url,omitempty"`
	Name            string              `json:"name,omitempty"`
	Slug            string              `json:"slug,omitempty"`
	Description     string              `json:"description,omitempty"`
	Privacy         string              `json:"privacy,omitempty"`
	Permission      string              `json:"permission,omitempty"`
	MembersUrl      string              `json:"members_url,omitempty"`
	RepositoriesUrl string              `json:"repositories_url,omitempty"`
	MembersCount    int64               `json:"members_count,omitempty"`
	ReposCount      int64               `json:"repos_count,omitempty"`
	CreatedAt       string              `json:"created_at,omitempty"`
	UpdatedAt       string              `json:"updated_at,omitempty"`
	Organization    *GitHubOrganization `json:"organization"`
	Parent          string              `json:"parent,omitempty"`
}

type GitHubOrganization struct {
	Login            string `json:"login"`
	Id               int64  `json:"id,omitempty"`
	Url              string `json:"url,omitempty"`
	ReposUrl         string `json:"repos_url,omitempty"`
	EventsUrl        string `json:"events_url,omitempty"`
	HooksUrl         string `json:"hooks_url,omitempty"`
	IssuesUrl        string `json:"issues_url,omitempty"`
	MembersUrl       string `json:"members_url,omitempty"`
	PublicMembersUrl string `json:"public_members_url,omitempty"`
	AvatarUrl        string `json:"avatar_url,omitempty"`
	Description      string `json:"Description,omitempty"`
}

type GitHubAuthConfig struct {
	Organization     string                `yaml:"organization,omitempty"`
	ClientId         string                `yaml:"client_id,omitempty"`
	ClientSecret     string                `yaml:"client_secret,omitempty"`
	ClientSecretFile string                `yaml:"client_secret_file,omitempty"`
	TokenDB          string                `yaml:"token_db,omitempty"`
	GCSTokenDB       *GitHubGCSStoreConfig `yaml:"gcs_token_db,omitempty"`
	HTTPTimeout      time.Duration         `yaml:"http_timeout,omitempty"`
	RevalidateAfter  time.Duration         `yaml:"revalidate_after,omitempty"`
	GithubWebUri     string                `yaml:"github_web_uri,omitempty"`
	GithubApiUri     string                `yaml:"github_api_uri,omitempty"`
	RegistryUrl      string                `yaml:"registry_url,omitempty"`
}

type GitHubGCSStoreConfig struct {
	Bucket           string `yaml:"bucket,omitempty"`
	ClientSecretFile string `yaml:"client_secret_file,omitempty"`
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
	config     *GitHubAuthConfig
	db         TokenDB
	client     *http.Client
	tmpl       *template.Template
	tmplResult *template.Template
}

type linkHeader struct {
	First string
	Last  string
	Next  string
	Prev  string
}

func execGHExperimentalApiRequest(url string, token string) (*http.Response, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		err = fmt.Errorf("could not create an http request for uri: %s. Error: %s", url, err)
		return nil, err
	}
	req.Header.Add("Authorization", fmt.Sprintf("token %s", token))
	// Currently an "experimental" API; https://developer.github.com/v3/orgs/teams/#list-user-teams
	req.Header.Add("Accept", "application/vnd.github.hellcat-preview+json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		err = fmt.Errorf("HTTP error while retrieving %s. Error : %s", url, err)
		return nil, err
	}

	return resp, nil
}

// removeSubstringsFromString removes all occurences of stringsToStrip from sourceStr
//
func removeSubstringsFromString(sourceStr string, stringsToStrip []string) string {
	theNewString := sourceStr
	for _, i := range stringsToStrip {
		theNewString = strings.Replace(theNewString, i, "", -1)
	}
	return theNewString
}

// parseLinkHeader parses the HTTP headers from the Github API response
//
// https://developer.github.com/v3/guides/traversing-with-pagination/
//
func parseLinkHeader(linkLines []string) (linkHeader, error) {
	var lH linkHeader
	// URL in link is enclosed in < >
	stringsToRemove := []string{"<", ">"}

	for _, linkLine := range linkLines {
		for _, linkItem := range strings.Split(linkLine, ",") {
			linkData := strings.Split(linkItem, ";")
			trimmedUrl := removeSubstringsFromString(strings.TrimSpace(linkData[0]), stringsToRemove)
			linkVal := linkData[1]
			switch {
			case strings.Contains(linkVal, "first"):
				lH.First = trimmedUrl
			case strings.Contains(linkVal, "last"):
				lH.Last = trimmedUrl
			case strings.Contains(linkVal, "next"):
				lH.Next = trimmedUrl
			case strings.Contains(linkVal, "prev"):
				lH.Prev = trimmedUrl
			}
		}
	}
	return lH, nil
}

func NewGitHubAuth(c *GitHubAuthConfig) (*GitHubAuth, error) {
	var db TokenDB
	var err error
	dbName := c.TokenDB
	if c.GCSTokenDB == nil {
		db, err = NewTokenDB(c.TokenDB)
	} else {
		db, err = NewGCSTokenDB(c.GCSTokenDB.Bucket, c.GCSTokenDB.ClientSecretFile)
		dbName = "GCS: " + c.GCSTokenDB.Bucket
	}

	if err != nil {
		return nil, err
	}
	glog.Infof("GitHub auth token DB at %s", dbName)
	return &GitHubAuth{
		config:     c,
		db:         db,
		client:     &http.Client{Timeout: 10 * time.Second},
		tmpl:       template.Must(template.New("github_auth").Parse(string(MustAsset("data/github_auth.tmpl")))),
		tmplResult: template.Must(template.New("github_auth_result").Parse(string(MustAsset("data/github_auth_result.tmpl")))),
	}, nil
}

func (gha *GitHubAuth) doGitHubAuthPage(rw http.ResponseWriter, req *http.Request) {
	if err := gha.tmpl.Execute(rw, struct {
		ClientId, GithubWebUri, Organization string
	}{
		ClientId:     gha.config.ClientId,
		GithubWebUri: gha.getGithubWebUri(),
		Organization: gha.config.Organization}); err != nil {
		http.Error(rw, fmt.Sprintf("Template error: %s", err), http.StatusInternalServerError)
	}
}

func (gha *GitHubAuth) doGitHubAuthResultPage(rw http.ResponseWriter, username string, password string) {
	if err := gha.tmplResult.Execute(rw, struct {
		Organization, Username, Password, RegistryUrl string
	}{Organization: gha.config.Organization,
		Username:    username,
		Password:    password,
		RegistryUrl: gha.config.RegistryUrl}); err != nil {
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

func (gha *GitHubAuth) getGithubApiUri() string {
	if gha.config.GithubApiUri != "" {
		return gha.config.GithubApiUri
	} else {
		return "https://api.github.com"
	}
}

func (gha *GitHubAuth) getGithubWebUri() string {
	if gha.config.GithubWebUri != "" {
		return gha.config.GithubWebUri
	} else {
		return "https://github.com"
	}
}

func (gha *GitHubAuth) doGitHubAuthCreateToken(rw http.ResponseWriter, code string) {
	data := url.Values{
		"code":          []string{string(code)},
		"client_id":     []string{gha.config.ClientId},
		"client_secret": []string{gha.config.ClientSecret},
	}

	req, err := http.NewRequest("POST", fmt.Sprintf("%s/login/oauth/access_token", gha.getGithubWebUri()), bytes.NewBufferString(data.Encode()))
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

	user, err := gha.validateAccessToken(c2t.AccessToken)
	if err != nil {
		glog.Errorf("Newly-acquired token is invalid: %+v %s", c2t, err)
		http.Error(rw, "Newly-acquired token is invalid", http.StatusInternalServerError)
		return
	}

	glog.Infof("New GitHub auth token for %s", user)

	userTeams, err := gha.fetchTeams(c2t.AccessToken)
	if err != nil {
		glog.Errorf("could not fetch user teams: %s", err)
	}

	v := &TokenDBValue{
		TokenType:   c2t.TokenType,
		AccessToken: c2t.AccessToken,
		ValidUntil:  time.Now().Add(gha.config.RevalidateAfter),
		Labels:      map[string][]string{"teams": userTeams},
	}
	dp, err := gha.db.StoreToken(user, v, true)
	if err != nil {
		glog.Errorf("Failed to record server token: %s", err)
		http.Error(rw, "Failed to record server token: %s", http.StatusInternalServerError)
		return
	}

	gha.doGitHubAuthResultPage(rw, user, dp)
}

func (gha *GitHubAuth) validateAccessToken(token string) (user string, err error) {
	glog.Infof("Github API: Fetching user info")
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/user", gha.getGithubApiUri()), nil)
	if err != nil {
		err = fmt.Errorf("could not create request to get information for token %s: %s", token, err)
		return
	}
	req.Header.Add("Authorization", fmt.Sprintf("token %s", token))
	req.Header.Add("Accept", "application/json")

	resp, err := gha.client.Do(req)
	if err != nil {
		err = fmt.Errorf("could not verify token %s: %s", token, err)
		return
	}
	body, _ := ioutil.ReadAll(resp.Body)
	resp.Body.Close()

	var ti GitHubTokenUser
	err = json.Unmarshal(body, &ti)
	if err != nil {
		err = fmt.Errorf("could not unmarshal token user info %q: %s", string(body), err)
		return
	}
	glog.V(2).Infof("Token user info: %+v", strings.Replace(string(body), "\n", " ", -1))

	err = gha.checkOrganization(token, ti.Login)
	if err != nil {
		err = fmt.Errorf("could not validate organization: %s", err)
		return
	}

	return ti.Login, nil
}

func (gha *GitHubAuth) checkOrganization(token, user string) (err error) {
	if gha.config.Organization == "" {
		return nil
	}
	glog.Infof("Github API: Fetching organization membership info")
	url := fmt.Sprintf("%s/orgs/%s/members/%s", gha.getGithubApiUri(), gha.config.Organization, user)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		err = fmt.Errorf("could not create request to get organization membership: %s", err)
		return
	}
	req.Header.Add("Authorization", fmt.Sprintf("token %s", token))

	resp, err := gha.client.Do(req)
	if err != nil {
		return
	}

	switch resp.StatusCode {
	case http.StatusNoContent:
		return nil
	case http.StatusNotFound:
		return fmt.Errorf("user %s is not a member of organization %s", user, gha.config.Organization)
	case http.StatusFound:
		return fmt.Errorf("token %s could not get membership for organization %s", token, gha.config.Organization)
	}

	return fmt.Errorf("Unknown status for membership of organization %s: %s", gha.config.Organization, resp.Status)
}

func (gha *GitHubAuth) fetchTeams(token string) ([]string, error) {
	var allTeams GitHubTeamCollection

	if gha.config.Organization == "" {
		return nil, nil
	}
	glog.Infof("Github API: Fetching user teams")
	url := fmt.Sprintf("%s/user/teams?per_page=100", gha.getGithubApiUri())
	var err error

	// Using an `i` iterator for debugging the results
	for i := 1; url != ""; i++ {
		var pagedTeams GitHubTeamCollection
		resp, err := execGHExperimentalApiRequest(url, token)
		if err != nil {
			return nil, err
		}

		respHeaders := resp.Header
		body, _ := ioutil.ReadAll(resp.Body)
		resp.Body.Close()

		err = json.Unmarshal(body, &pagedTeams)
		if err != nil {
			err = fmt.Errorf("Error parsing the JSON response while fetching teams: %s", err)
			return nil, err
		}

		allTeams = append(allTeams, pagedTeams...)

		// Do we need to paginate?
		if link, ok := respHeaders["Link"]; ok {
			parsedLink, _ := parseLinkHeader(link)
			url = parsedLink.Next
			glog.V(2).Infof("--> Page <%d>\n", i)
		} else {
			url = ""
		}
	}

	var organizationTeams []string
	for _, item := range allTeams {
		if item.Organization.Login == gha.config.Organization {
			organizationTeams = append(organizationTeams, item.Slug)
		}
	}

	glog.V(3).Infof("All teams for the user: %v", allTeams)
	glog.Infof("Teams for the <%s> organization: %v", gha.config.Organization, organizationTeams)
	return organizationTeams, err
}

func (gha *GitHubAuth) validateServerToken(user string) (*TokenDBValue, error) {
	v, err := gha.db.GetValue(user)
	if err != nil || v == nil {
		if err == nil {
			err = errors.New("no db value, please sign out and sign in again")
		}
		return nil, err
	}

	texp := v.ValidUntil.Sub(time.Now())
	glog.V(3).Infof("Existing GitHub auth token for <%s> expires after: <%d> sec", user, int(texp.Seconds()))

	glog.V(1).Infof("Token has expired. I will revalidate the access token.")
	glog.V(3).Infof("Old token is: %+v", v)
	tokenUser, err := gha.validateAccessToken(v.AccessToken)
	if err != nil {
		glog.Warningf("Token for %q failed validation: %s", user, err)
		return nil, fmt.Errorf("server token invalid: %s", err)
	}
	if tokenUser != user {
		glog.Errorf("token for wrong user: expected %s, found %s", user, tokenUser)
		return nil, fmt.Errorf("found token for wrong user")
	}

	// Update revalidation timestamp
	v.ValidUntil = time.Now().Add(gha.config.RevalidateAfter)
	glog.V(3).Infof("New token is: %+v", v)

	// Update token
	_, err = gha.db.StoreToken(user, v, false)
	if err != nil {
		glog.Errorf("Failed to record server token: %s", err)
		return nil, fmt.Errorf("Unable to store renewed token expiry time: %s", err)
	}
	glog.V(2).Infof("Successfully revalidated token")

	texp = v.ValidUntil.Sub(time.Now())
	glog.V(3).Infof("Re-validated GitHub auth token for %s. Next revalidation in %dsec.", user, int64(texp.Seconds()))
	return v, nil
}

func (gha *GitHubAuth) Authenticate(user string, password PasswordString) (bool, Labels, error) {
	err := gha.db.ValidateToken(user, password)
	if err == ExpiredToken {
		_, err = gha.validateServerToken(user)
		if err != nil {
			return false, nil, err
		}
	} else if err != nil {
		return false, nil, err
	}

	v, err := gha.db.GetValue(user)
	if err != nil || v == nil {
		if err == nil {
			err = errors.New("no db value, please sign out and sign in again")
		}
		return false, nil, err
	}

	return true, v.Labels, nil
}

func (gha *GitHubAuth) Stop() {
	gha.db.Close()
	glog.Info("Token DB closed")
}

func (gha *GitHubAuth) Name() string {
	return "GitHub"
}
