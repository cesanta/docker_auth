/*
   Copyright 2017 Cesanta Software Ltd.

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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/cesanta/docker_auth/auth_server/api"
	"github.com/cesanta/glog"
	"github.com/dchest/uniuri"
	"github.com/go-redis/redis/v9"
)

var ctx = context.Background()

type RedisStoreConfig struct {
	ClientOptions  *redis.Options        `yaml:"redis_options,omitempty"`
	ClusterOptions *redis.ClusterOptions `yaml:"redis_cluster_options,omitempty"`
}

type RedisClient interface {
	Get(ctx context.Context, key string) *redis.StringCmd
	Set(ctx context.Context, key string, value interface{}, expiration time.Duration) *redis.StatusCmd
	Del(ctx context.Context, keys ...string) *redis.IntCmd
}

type redisTokenDB struct {
	client RedisClient
}

// NewRedisTokenDB returns a new TokenDB structure which uses Redis as the storage backend.
func NewRedisTokenDB(opts *RedisStoreConfig) (TokenDB, error) {
	var client redis.Cmdable
	switch {
	case opts.ClusterOptions != nil:
		client = redis.NewClusterClient(opts.ClusterOptions)
	case opts.ClientOptions != nil:
		client = redis.NewClient(opts.ClientOptions)
	default:
		return nil, errors.New("redis configuration not found")
	}
	return &redisTokenDB{client}, nil
}

func (db *redisTokenDB) String() string {
	return fmt.Sprintf("%v", db.client)
}

func (db *redisTokenDB) GetValue(user string) (*TokenDBValue, error) {
	// Short-circuit calling Redis when the user is anonymous
	if user == "" {
		return nil, nil
	}

	key := string(getDBKey(user))

	result, err := db.client.Get(ctx, key).Result()
	if err == redis.Nil {
		glog.V(2).Infof("Key <%s> doesn't exist\n", key)
		return nil, nil
	} else if err != nil {
		glog.Errorf("Error getting Redis key <%s>: %s\n", key, err)
		return nil, fmt.Errorf("Error getting key <%s>: %s", key, err)
	}

	var dbv TokenDBValue

	err = json.Unmarshal([]byte(result), &dbv)
	if err != nil {
		glog.Errorf("Error parsing value for user <%q> (%q): %s", user, string(result), err)
		return nil, fmt.Errorf("Error parsing value: %v", err)
	}
	glog.V(2).Infof("Redis: GET %s : %v\n", key, result)
	return &dbv, nil
}

func (db *redisTokenDB) StoreToken(user string, v *TokenDBValue, updatePassword bool) (dp string, err error) {
	if updatePassword {
		dp = uniuri.New()
		dph, _ := bcrypt.GenerateFromPassword([]byte(dp), bcrypt.DefaultCost)
		v.DockerPassword = string(dph)
	}

	data, err := json.Marshal(v)
	if err != nil {
		return "", err
	}

	key := string(getDBKey(user))

	err = db.client.Set(ctx, key, data, 0).Err()
	if err != nil {
		glog.Errorf("Failed to store token data for user <%s>: %s\n", user, err)
		return "", fmt.Errorf("Failed to store token data for user <%s>: %s", user, err)
	}

	glog.V(2).Infof("Server tokens for <%s>: %x\n", user, string(data))
	return
}

func (db *redisTokenDB) ValidateToken(user string, password api.PasswordString) error {
	dbv, err := db.GetValue(user)

	if err != nil {
		return err
	}

	if dbv == nil {
		return api.NoMatch
	}

	if bcrypt.CompareHashAndPassword([]byte(dbv.DockerPassword), []byte(password)) != nil {
		return api.WrongPass
	}

	if time.Now().After(dbv.ValidUntil) {
		return ExpiredToken
	}

	return nil
}

func (db *redisTokenDB) DeleteToken(user string) error {
	glog.Infof("Deleting token for user <%s>\n", user)

	key := string(getDBKey(user))
	err := db.client.Del(ctx, key).Err()
	if err != nil {
		return fmt.Errorf("Failed to delete token for user <%s>: %s", user, err)
	}
	return nil
}

func (db *redisTokenDB) Close() error {
	return nil
}
