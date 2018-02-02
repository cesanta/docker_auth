package authn

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/cesanta/glog"
	"github.com/dchest/uniuri"
	"github.com/go-redis/redis"
)

// NewRedisTokenDB returns a new TokenDB structure which uses Redis as backend.
//
func NewRedisTokenDB(url string, encrypt_key string) (TokenDB, error) {
	client := redis.NewClient(&redis.Options{Addr: url})
	return &redisTokenDB{client, encrypt_key}, nil
}

type redisTokenDB struct {
	client      *redis.Client
	encrypt_key string
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

	if db.encrypt_key != "" {
		result_b, err := db.Decrypt([]byte(result), []byte(db.encrypt_key))
		if err != nil {
			glog.Errorf("Error decrypting key <%s>: %s\n", key, err)
			return nil, fmt.Errorf("Error decrypting key <%s>: %s", key, err)
		}
		result = string(result_b[:])
	}

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

	if db.encrypt_key != "" {
		data, err = db.Encrypt(data, []byte(db.encrypt_key))
		if err != nil {
			glog.Errorf("Error encrypting key <%s>: %s\n", key, err)
			return "", fmt.Errorf("Error encrypting key <%s>: %s", key, err)
		}
	}

	err = db.client.Set(key, data, 0).Err()
	if err != nil {
		glog.Errorf("Failed to store token data for user <%s>: %s\n", user, err)
		return "", fmt.Errorf("Failed to store token data for user <%s>: %s", user, err)
	}

	glog.V(2).Infof("Server tokens for <%s>: %x\n", user, string(data))
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
	glog.Infof("Deleting token for user <%s>\n", user)

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

func (db *redisTokenDB) Encrypt(plaintext []byte, key []byte) ([]byte, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func (db *redisTokenDB) Decrypt(ciphertext []byte, key []byte) ([]byte, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("Encrypted content is too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}
