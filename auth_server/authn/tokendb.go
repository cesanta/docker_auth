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
	"time"

	"github.com/golang/glog"
	"github.com/syndtr/goleveldb/leveldb"
)

// TokenDB stores tokens using LevelDB
type TokenDB struct {
	*leveldb.DB
}

const (
	tokenDBPrefix = "t:" // Keys in the database are t:email@example.com
)

// TokenDBValue is stored in the database, JSON-serialized.
type TokenDBValue struct {
	TokenType    string    `json:"token_type,omitempty"` // Usually "Bearer"
	AccessToken  string    `json:"access_token,omitempty"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	ValidUntil   time.Time `json:"valid_until,omitempty"`
	// DockerPassword is the temporary password we use to authenticate Docker users.
	// Gneerated at the time of token creation, stored here as a BCrypt hash.
	DockerPassword string `json:"docker_password,omitempty"`
}

// NewTokenDB
func NewTokenDB(file string) (*TokenDB, error) {
	db, err := leveldb.OpenFile(file, nil)
	return &TokenDB{
		DB: db,
	}, err
}

func getDBKey(user string) []byte {
	return []byte(fmt.Sprintf("%s%s", tokenDBPrefix, user))
}

func (db *TokenDB) GetValue(user string) (*TokenDBValue, error) {
	valueStr, err := db.Get(getDBKey(user), nil)
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
