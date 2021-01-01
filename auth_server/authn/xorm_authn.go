/*
   Copyright 2020 Cesanta Software Ltd.

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
	"fmt"

	"github.com/cesanta/docker_auth/auth_server/api"
	"golang.org/x/crypto/bcrypt"

	_ "github.com/go-sql-driver/mysql"
	_ "github.com/lib/pq"
	"xorm.io/xorm"
)

var (
	EnableSQLite3 = false
)

type XormAuthnConfig struct {
	DatabaseType string `yaml:"database_type,omitempty"`
	ConnString   string `yaml:"conn_string,omitempty"`
}

type XormAuthn struct {
	config *XormAuthnConfig
	engine *xorm.Engine
}

type XormUser struct {
	Id           int64      `xorm:"pk autoincr"`
	Username     string     `xorm:"VARCHAR(128) NOT NULL"`
	PasswordHash string     `xorm:"VARCHAR(128) NOT NULL"`
	Labels       api.Labels `xorm:"JSON"`
}

func NewXormAuth(c *XormAuthnConfig) (*XormAuthn, error) {
	e, err := xorm.NewEngine(c.DatabaseType, c.ConnString)
	if err != nil {
		return nil, err
	}

	if err := e.Sync2(new(XormUser)); err != nil {
		return nil, fmt.Errorf("Sync2: %v", err)
	}
	return &XormAuthn{
		config: c,
		engine: e,
	}, nil
}

func (xa *XormAuthn) Authenticate(user string, password api.PasswordString) (bool, api.Labels, error) {
	if user == "" || password == "" {
		return false, nil, api.NoMatch
	}
	var xuser XormUser
	has, err := xa.engine.Where("username = ?", user).Desc("id").Get(&xuser)
	if err != nil {
		return false, nil, err
	}
	if !has {
		return false, nil, api.NoMatch
	}
	if bcrypt.CompareHashAndPassword([]byte(xuser.PasswordHash), []byte(password)) != nil {
		return false, nil, nil
	}
	return true, xuser.Labels, nil
}

func (xa *XormAuthn) Name() string {
	return "XORM.io Authn"
}

func (xa *XormAuthn) Stop() {
	if xa.engine != nil {
		xa.engine.Close()
	}
}
func (xa *XormAuthnConfig) Validate(configKey string) error {
	// TODO: Validate auth
	return nil
}
