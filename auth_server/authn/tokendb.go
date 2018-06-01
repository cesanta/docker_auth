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
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/cesanta/glog"
	"github.com/dchest/uniuri"
	"github.com/syndtr/goleveldb/leveldb"
)

const (
	tokenDBPrefix = "t:" // Keys in the database are t:email@example.com
)

var ExpiredToken = errors.New("expired token")

// TokenDB stores tokens using LevelDB
type TokenDB interface {
	// GetValue takes a username returns the corresponding token
	GetValue(string) (*TokenDBValue, error)

	// StoreToken takes a username and token, stores them in the DB
	// and returns a password and error
	StoreToken(string, *TokenDBValue, bool) (string, error)

	// ValidateTOken takes a username and password
	// and returns an error
	ValidateToken(string, PasswordString) error

	// DeleteToken takes a username
	// and deletes the corresponding token from the DB
	DeleteToken(string) error

	// Composed from leveldb.DB
	Close() error
}

// TokenDB stores tokens using LevelDB
type TokenDBImpl struct {
	*leveldb.DB
}

// TokenDBValue is stored in the database, JSON-serialized.
type TokenDBValue struct {
	TokenType    string    `json:"token_type,omitempty"` // Usually "Bearer"
	AccessToken  string    `json:"access_token,omitempty"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	ValidUntil   time.Time `json:"valid_until,omitempty"`
	// DockerPassword is the temporary password we use to authenticate Docker users.
	// Generated at the time of token creation, stored here as a BCrypt hash.
	DockerPassword string `json:"docker_password,omitempty"`
	Labels         Labels `json:"labels,omitempty"`
}

// NewTokenDB returns a new TokenDB structure
func NewTokenDB(file string) (TokenDB, error) {
	db, err := leveldb.OpenFile(file, nil)
	return &TokenDBImpl{
		DB: db,
	}, err
}

func (db *TokenDBImpl) GetValue(user string) (*TokenDBValue, error) {
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
		return nil, fmt.Errorf("bad DB value due: %v", err)
	}
	return &dbv, nil
}

func (db *TokenDBImpl) StoreToken(user string, v *TokenDBValue, updatePassword bool) (dp string, err error) {
	if updatePassword {
		dp = uniuri.New()
		dph, _ := bcrypt.GenerateFromPassword([]byte(dp), bcrypt.DefaultCost)
		v.DockerPassword = string(dph)
	}

	data, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	err = db.Put(getDBKey(user), data, nil)
	if err != nil {
		glog.Errorf("failed to set token data for %s: %s", user, err)
	}
	glog.V(2).Infof("Server tokens for %s: %s", user, string(data))
	return
}

func (db *TokenDBImpl) ValidateToken(user string, password PasswordString) error {
	dbv, err := db.GetValue(user)
	if err != nil {
		return err
	}
	if dbv == nil {
		return NoMatch
	}
	if bcrypt.CompareHashAndPassword([]byte(dbv.DockerPassword), []byte(password)) != nil {
		return WrongPass
	}
	if time.Now().After(dbv.ValidUntil) {
		return ExpiredToken
	}
	return nil
}

func (db *TokenDBImpl) DeleteToken(user string) error {
	glog.V(1).Infof("deleting token for %s", user)
	if err := db.Delete(getDBKey(user), nil); err != nil {
		return fmt.Errorf("failed to delete %s: %s", user, err)
	}
	return nil
}

func getDBKey(user string) []byte {
	return []byte(fmt.Sprintf("%s%s", tokenDBPrefix, user))
}
