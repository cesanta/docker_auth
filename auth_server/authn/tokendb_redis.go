package authn

import (
	"encoding/json"
	"fmt"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/cesanta/glog"
	"github.com/dchest/uniuri"
	"github.com/go-redis/redis"
)

// NewRedisTokenDB returns a new TokenDB structure which uses Redis as backend.
//
func NewRedisTokenDB(url string) (TokenDB, error) {
	client := redis.NewClient(&redis.Options{Addr: url})
	return &redisTokenDB{client}, nil
}

type redisTokenDB struct {
	client *redis.Client
}

func (db *redisTokenDB) GetValue(user string) (*TokenDBValue, error) {
	// Short-circuit calling Redis when the user is anonymous
	if user == "" {
		return nil, nil
	}

	key := string(getDBKey(user))

	result, err := db.client.Get(key).Result()
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

	err = db.client.Set(key, data, 0).Err()
	if err != nil {
		glog.Errorf("Failed to set token data for user <%s>: %s", user, err)
		return "", fmt.Errorf("Failed to set token data for user <%s>: %s", user, err)
	}

	glog.V(2).Infof("Server tokens for <%s>: %s", user, string(data))
	return
}

func (db *redisTokenDB) ValidateToken(user string, password PasswordString) error {
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

func (db *redisTokenDB) DeleteToken(user string) error {
	glog.Infof("Deleting token for user <%s>", user)

	key := string(getDBKey(user))
	err := db.client.Del(key).Err()
	if err != nil {
		return fmt.Errorf("Failed to delete token for user <%s>: %s", user, err)
	}
	return nil
}

func (db *redisTokenDB) Close() error {
	return nil
}
