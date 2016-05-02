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
	"net/http"
	"net/url"
	"io/ioutil"
	"strings"
)

type BitRequirements struct {
	Password *PasswordString `yaml:"password,omitempty" json:"password,omitempty"`
}

type BitbucketAuthConfig struct {
        ClientId         string `yaml:"client_id,omitempty"`
        ClientSecret     string `yaml:"client_secret,omitempty"`
}

type BitbucketAuth struct {
	config *BitbucketAuthConfig
}

func NewBitbucketAuth(c *BitbucketAuthConfig) (*BitbucketAuth, error) {
	return &BitbucketAuth{
                config: c, 
        }, nil
}

func (ba *BitbucketAuth) Authenticate(user string, password PasswordString) (bool, error) {
	client := http.Client{}
    
        form := url.Values{}
    	form.Add("grant_type", "password")
    	form.Add("username", user)
    	form.Add("password", string(password))

    	req, err := http.NewRequest("POST", "https://bitbucket.org/site/oauth2/access_token",
    	strings.NewReader(form.Encode()))
	req.SetBasicAuth(ba.config.ClientId, ba.config.ClientSecret)
    	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

    	resp, err := client.Do(req)

    	if err != nil {
		return false, err
    	} else {
        	body, _ := ioutil.ReadAll(resp.Body)

		type JsonBody struct {
    			Error string `json:"error"`
		}		

		var app JsonBody 
		err := json.Unmarshal(body, &app)
		if err != nil || app.Error != "" {
			return false, nil
		}
	}
	
	return true, nil
}

func (sua *BitbucketAuth) Stop() {
}

func (sua *BitbucketAuth) Name() string {
	return "bitbucket"
}
