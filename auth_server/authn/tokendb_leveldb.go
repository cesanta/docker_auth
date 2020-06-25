package authn

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/cesanta/glog"
	"github.com/dchest/uniuri"
	"github.com/syndtr/goleveldb/leveldb"
	"golang.org/x/crypto/bcrypt"

	"github.com/cesanta/docker_auth/auth_server/api"
)

type leveldbTokenDB struct {
	*leveldb.DB
}

// NewLevelDBTokenDB returns LevelDB-based token instance
func NewLevelDBTokenDB(file string) (TokenDB, error) {
	db, err := leveldb.OpenFile(file, nil)
	return &leveldbTokenDB{
		DB: db,
	}, err
}

func (db *leveldbTokenDB) GetValue(user string) (*TokenDBValue, error) {
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

func (db *leveldbTokenDB) StoreToken(user string, v *TokenDBValue, updatePassword bool) (dp string, err error) {
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

func (db *leveldbTokenDB) ValidateToken(user string, password api.PasswordString) error {
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

func (db *leveldbTokenDB) DeleteToken(user string) error {
	glog.V(1).Infof("deleting token for %s", user)
	if err := db.Delete(getDBKey(user), nil); err != nil {
		return fmt.Errorf("failed to delete %s: %s", user, err)
	}
	return nil
}

func getDBKey(user string) []byte {
	return []byte(fmt.Sprintf("%s%s", tokenDBPrefix, user))
}
