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
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/cesanta/docker_auth/auth_server/api"
)

type GiteaAuthConfig struct {
	HTTPTimeout     time.Duration `yaml:"http_timeout,omitempty"`
	RevalidateAfter time.Duration `yaml:"revalidate_after,omitempty"`
	GiteaWebUri     string        `yaml:"github_web_uri,omitempty"`
	GiteaApiUri     string        `yaml:"github_api_uri,omitempty"`
}

type GiteaAuth struct {
	config *GiteaAuthConfig
	client *http.Client
}

type GiteaOrg struct {
	Username string
}

func NewGiteaAuth(c *GiteaAuthConfig) (*GiteaAuth, error) {
	return &GiteaAuth{
		config: c,
		client: &http.Client{Timeout: 10 * time.Second},
	}, nil
}

func (gha *GiteaAuth) getGiteaApiUri() string {
	if gha.config.GiteaApiUri != "" {
		return gha.config.GiteaApiUri
	} else {
		return "https://git2.groschupp.org/api"
	}
}

func (gha *GiteaAuth) getGiteaWebUri() string {
	if gha.config.GiteaWebUri != "" {
		return gha.config.GiteaWebUri
	} else {
		return "https://git2.groschupp.org"
	}
}

//func (gha *GiteaAuth) authUser(user string, password PasswordString) (err error, l Labels) {
func (gha *GiteaAuth) Authenticate(user string, password api.PasswordString) (bool, api.Labels, error) {
	url := fmt.Sprintf("%s/v1/user/orgs", gha.getGiteaApiUri())
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
		err = fmt.Errorf("wrong error code %s", resp.StatusCode)
		return false, nil, err
	}

	body, _ := ioutil.ReadAll(resp.Body)
	resp.Body.Close()

	temp := make([]GiteaOrg, 0)
	err = json.Unmarshal(body, &temp)

	if err != nil {
		err = fmt.Errorf("could not unmarshal token user info %s: %s", body, err)
		return false, nil, err
	}

	l := make(map[string][]string)

	temp3 := make([]string, len(temp))

	for _, element := range temp {
		temp3 = append(temp3, element.Username)
	}

	if len(temp3) > 0 {
		l["project"] = temp3
	}

	return true, l, nil
}

func (gha *GiteaAuth) Stop() {
}

func (gha *GiteaAuth) Name() string {
	return "Gitea"
}
