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
	"errors"
	"golang.org/x/crypto/bcrypt"
)

type StaticUsersAuth struct {
	users map[string]*Requirements
}

func (sua *StaticUsersAuth) Authenticate(user string, password PasswordString) error {
	reqs := sua.users[user]
	if reqs == nil {
		return errors.New("unknown user")
	}
	if reqs.Password != nil {
		if bcrypt.CompareHashAndPassword([]byte(*reqs.Password), []byte(password)) != nil {
			return errors.New("wrong password")
		}
	}
	return nil
}
