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
	"github.com/cesanta/docker_auth/auth_server/mgo_session"
	"github.com/golang/glog"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
)

type MongoAuth struct {
	config   *mgo_session.Config
	session  *mgo.Session
}

type authUserEntry struct {
	Username *string `yaml:"username,omitempty" json:"username,omitempty"`
	Password *string `yaml:"password,omitempty" json:"password,omitempty"`
}

func NewMongoAuth(c *mgo_session.Config) (*MongoAuth, error) {
	// Attempt to create new mongo session.
	session, err := mgo_session.New(c)
	if err != nil {
		return nil, err
	}

	return &MongoAuth{
		config: c,
		session: session,
	}, nil
}

func (mauth *MongoAuth) Authenticate(account string, password PasswordString) (bool, error) {
	// Copy our session
	tmp_session := mauth.session.Copy()
	// Close up when we are done
	defer tmp_session.Close()

	// Get Users from MongoDB
	glog.V(2).Infof("Checking user %s against Mongo Users. DB: %s, collection:%s", 
		account, mauth.config.DialConfig.DialInfo.Database, mauth.config.Collection)
	var dbUserRecord authUserEntry
	collection := tmp_session.DB(mauth.config.DialConfig.DialInfo.Database).C(mauth.config.Collection)
	err := collection.Find(bson.M{"username": account}).One(&dbUserRecord)

	// If we connect and get no results we return a NoMatch so auth can fall-through
	if err == mgo.ErrNotFound {
		return false, NoMatch
	} else if err != nil {
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

func (ma *MongoAuth) Stop() {
	// Close connection to MongoDB database (if any)
	if ma.session != nil {
		ma.session.Close()
	}
}

func (ga *MongoAuth) Name() string {
	return "MongoDB"
}
