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
	"golang.org/x/crypto/bcrypt"
)

type Requirements struct {
	Password *PasswordString `yaml:"password,omitempty" json:"password,omitempty"`
	Labels   Labels          `yaml:"labels,omitempty" json:"labels,omitempty"`
}

type staticUsersAuth struct {
	users map[string]*Requirements
}

func (r Requirements) String() string {
	p := r.Password
	if p != nil {
		pm := PasswordString("***")
		r.Password = &pm
	}
	b, _ := json.Marshal(r)
	r.Password = p
	return string(b)
}

func NewStaticUserAuth(users map[string]*Requirements) *staticUsersAuth {
	return &staticUsersAuth{users: users}
}

func (sua *staticUsersAuth) Authenticate(user string, password PasswordString) (bool, Labels, error) {
	reqs := sua.users[user]
	if reqs == nil {
		return false, nil, NoMatch
	}
	if reqs.Password != nil {
		if bcrypt.CompareHashAndPassword([]byte(*reqs.Password), []byte(password)) != nil {
			return false, nil, nil
		}
	}
	return true, reqs.Labels, nil
}

func (sua *staticUsersAuth) Stop() {
}

func (sua *staticUsersAuth) Name() string {
	return "static"
}
