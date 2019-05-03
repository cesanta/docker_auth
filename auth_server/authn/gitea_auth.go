/*
   Copyright 2022 Cesanta Software Ltd.

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
	"io"
	"net/http"
	"time"

	"github.com/cesanta/docker_auth/auth_server/api"
)

type GiteaAuthConfig struct {
	HTTPTimeout     time.Duration `yaml:"http_timeout,omitempty"`
	RevalidateAfter time.Duration `yaml:"revalidate_after,omitempty"`
	ApiUri          string        `yaml:"api_uri,omitempty"`
}

type GiteaAuth struct {
	config *GiteaAuthConfig
	client *http.Client
}

type GiteaOrg struct {
	Username string `json:"username"`
}

func NewGiteaAuth(c *GiteaAuthConfig) (*GiteaAuth, error) {
	return &GiteaAuth{
		config: c,
		client: &http.Client{Timeout: 10 * time.Second},
	}, nil
}

// func (gha *GiteaAuth) authUser(user string, password PasswordString) (err error, l Labels) {
func (gha *GiteaAuth) Authenticate(user string, password api.PasswordString) (bool, api.Labels, error) {
	url := fmt.Sprintf("%s/v1/user/orgs", gha.config.ApiUri)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		err = fmt.Errorf("unable to auth: %s", err)
		return false, nil, err
	}
	req.SetBasicAuth(user, string(password))
	resp, err := gha.client.Do(req)

	if err != nil {
		return false, nil, err
	}

	if resp.StatusCode == 401 {
		return false, nil, nil
	} else if resp.StatusCode != 200 {
		err = fmt.Errorf("wrong error code %d", resp.StatusCode)
		return false, nil, err
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		err = fmt.Errorf("unable to read body %s: %s", body, err)
		return false, nil, err
	}
	resp.Body.Close()

	orgs := make([]GiteaOrg, 0)
	err = json.Unmarshal(body, &orgs)

	if err != nil {
		err = fmt.Errorf("could not unmarshal token user info %s: %s", body, err)
		return false, nil, err
	}

	labels := api.Labels{"project": []string{}}

	for _, org := range orgs {
		labels["project"] = append(labels["project"], org.Username)
	}

	return true, labels, nil
}

func (gha *GiteaAuth) Stop() {
}

func (gha *GiteaAuth) Name() string {
	return "Gitea"
}
