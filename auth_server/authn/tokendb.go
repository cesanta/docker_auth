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
	"errors"
	"time"

	"github.com/cesanta/docker_auth/auth_server/api"
	"github.com/go-redis/redis"
)

const (
	tokenDBPrefix = "t:" // Keys in the database are t:email@example.com
)

var ExpiredToken = errors.New("expired token")

// TokenDB stores and validates tokens from external authentication providers
type TokenDB interface {
	// GetValue takes a username returns the corresponding token
	GetValue(string) (*TokenDBValue, error)

	// StoreToken takes a username and token, stores them in the DB
	// and returns a password and error
	StoreToken(string, *TokenDBValue, bool) (string, error)

	// ValidateTOken takes a username and password
	// and returns an error
	ValidateToken(string, api.PasswordString) error

	// DeleteToken takes a username
	// and deletes the corresponding token from the DB
	DeleteToken(string) error

	// Composed from leveldb.DB
	Close() error
}

// TokenDBValue is stored in the database, JSON-serialized.
type TokenDBValue struct {
	TokenType    string    `json:"token_type,omitempty"` // Usually "Bearer"
	AccessToken  string    `json:"access_token,omitempty"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	ValidUntil   time.Time `json:"valid_until,omitempty"`
	// DockerPassword is the temporary password we use to authenticate Docker users.
	// Generated at the time of token creation, stored here as a BCrypt hash.
	DockerPassword string     `json:"docker_password,omitempty"`
	Labels         api.Labels `json:"labels,omitempty"`
}

// TokenConfiguration is a shared YAML configuration structure for multiple token types
type TokenConfiguration struct {
	TokenDB      string            `yaml:"token_db,omitempty"`
	GCSTokenDB   *GCSTokenConfig   `yaml:"gcs_token_db,omitempty"`
	RedisTokenDB *RedisTokenConfig `yaml:"redis_token_db,omitempty"`
}

// GCSTokenConfig is Google Cloud Storage-based token storage configuration
type GCSTokenConfig struct {
	Bucket           string `yaml:"bucket,omitempty"`
	ClientSecretFile string `yaml:"client_secret_file,omitempty"`
}

// RedisTokenConfig is Redis-based token storage configuration
type RedisTokenConfig struct {
	ClientOptions  *redis.Options        `yaml:"redis_options,omitempty"`
	ClusterOptions *redis.ClusterOptions `yaml:"redis_cluster_options,omitempty"`
}

// func NewTokenDB(filename string)
