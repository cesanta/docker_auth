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
	// "encoding/json"
	"errors"
	"time"

	"github.com/golang/glog"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
)

// MongoAuthDialConfig stores how we connect to the MongoDB server
type MongoAuthDialConfig struct {
	mgo.DialInfo `yaml:",inline"`
	PasswordFile string `yaml:"password_file,omitempty"`
}

// MongoAuthConfig stores how to connect to the MongoDB server and how long
// an ACL remains valid until new ones will be fetched.
type MongoAuthConfig struct {
	DialInfo   MongoAuthDialConfig `yaml:"dial_info,omitempty"`
	Collection string              `yaml:"collection,omitempty"`
	CacheTTL   time.Duration       `yaml:"cache_ttl,omitempty"`
}

type MongoAuth struct {
	config   *MongoAuthConfig
//	session  *mgo.Session
}

// Validate ensures the most common fields inside the mgo.DialInfo portion of
// an AuthMongoDialInfo are set correctly as well as other fields inside the
// MongoAuthConfig itself.
func (c *MongoAuthConfig) Validate() error {
	if len(c.DialInfo.DialInfo.Addrs) == 0 {
		return errors.New("At least one element in auth_mongo.dial_info.addrs is required")
	}
	if c.DialInfo.DialInfo.Timeout == 0 {
		c.DialInfo.DialInfo.Timeout = 10 * time.Second
	}
	if c.DialInfo.DialInfo.Database == "" {
		return errors.New("auth_mongo.dial_info.database is required")
	}
	if c.Collection == "" {
		return errors.New("auth_mongo.collection is required")
	}
	if c.CacheTTL < 0 {
		return errors.New(`auth_mongo.cache_ttl is required (e.g. "1m" for 1 minute)`)
	}
	return nil
}

type authUserEntry struct {
	Username *string `yaml:"username,omitempty" json:"username,omitempty"`
	Password *string `yaml:"password,omitempty" json:"password,omitempty"`
}

func NewMongoAuth(c *MongoAuthConfig) (*MongoAuth, error) {
	// // Attempt to create a MongoDB session which we can re-use when handling
	// // multiple auth requests.

	// // Read in the password (if any)
	// if c.DialInfo.PasswordFile != "" {
	// 	passBuf, err := ioutil.ReadFile(c.DialInfo.PasswordFile)
	// 	if err != nil {
	// 		return nil, fmt.Errorf(`Failed to read password file "%s": %s`, c.DialInfo.PasswordFile, err)
	// 	}
	// 	c.DialInfo.DialInfo.Password = strings.TrimSpace(string(passBuf))
	// }

	// glog.V(2).Infof("Creating MongoDB session (operation timeout %s)", c.DialInfo.DialInfo.Timeout)
	// session, err := mgo.DialWithInfo(&c.DialInfo.DialInfo)
	// if err != nil {
	// 	return nil, err
	// }

	return &MongoAuth{
		config: c,
//		session: session
	}, nil
}

func (mauth *MongoAuth) Authenticate(account string, password PasswordString) (bool, error) {
	// Login to mongo
	glog.V(2).Infof("Creating MongoDB session (operation timeout %s)", mauth.config.DialInfo.DialInfo.Timeout)
	session, derr := mgo.DialWithInfo(&mauth.config.DialInfo.DialInfo)
	if derr != nil {
		return false, derr
	}

	// Close up when we are done
	defer session.Close()

	// Get Users from MongoDB
	glog.V(2).Infof("Checking user %s against Mongo Users. DB: %s, collection:%s", 
		account, mauth.config.DialInfo.DialInfo.Database, mauth.config.Collection)
	var dbUserRecord authUserEntry
	collection := session.DB(mauth.config.DialInfo.DialInfo.Database).C(mauth.config.Collection)
	err := collection.Find(bson.M{"username": account}).One(&dbUserRecord)
	if err != nil {
		return false, err
	}

	// Validate db password against passed password 
	if dbUserRecord.Password != nil {
		if bcrypt.CompareHashAndPassword([]byte(*dbUserRecord.Password), []byte(password)) != nil {
			return false, nil
		}
	}

	// Auth success
	return true, nil
}


// type Requirements struct {
// 	Password *PasswordString `yaml:"password,omitempty" json:"password,omitempty"`
// }

// type staticUsersAuth struct {
// 	users map[string]*Requirements
// }

// func (r Requirements) String() string {
// 	p := r.Password
// 	if p != nil {
// 		pm := PasswordString("***")
// 		r.Password = &pm
// 	}
// 	b, _ := json.Marshal(r)
// 	r.Password = p
// 	return string(b)
// }

// func NewStaticUserAuth(users map[string]*Requirements) *staticUsersAuth {
// 	return &staticUsersAuth{users: users}
// }

// func (sua *staticUsersAuth) Authenticate(user string, password PasswordString) (bool, error) {
// 	reqs := sua.users[user]
// 	if reqs == nil {
// 		return false, NoMatch
// 	}
// 	if reqs.Password != nil {
// 		if bcrypt.CompareHashAndPassword([]byte(*reqs.Password), []byte(password)) != nil {
// 			return false, nil
// 		}
// 	}
// 	return true, nil
// }

// func (sua *staticUsersAuth) Stop() {
// }

// func (sua *staticUsersAuth) Name() string {
// 	return "static"
// }

func (ma *MongoAuth) Stop() {
	// Close connection to MongoDB database (if any)
	// if ma.session != nil {
	// 	ma.session.Close()
	// }
}

func (ga *MongoAuth) Name() string {
	return "MongoDB"
}
