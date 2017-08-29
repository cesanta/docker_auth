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
	"fmt"
	"io"
	"time"

	"github.com/cesanta/docker_auth/auth_server/mgo_session"
	"github.com/cesanta/glog"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
)

type MongoAuthConfig struct {
	MongoConfig *mgo_session.Config `yaml:"dial_info,omitempty"`
	Collection  string              `yaml:"collection,omitempty"`
}

type MongoAuth struct {
	config     *MongoAuthConfig
	session    *mgo.Session
	Collection string `yaml:"collection,omitempty"`
}

type authUserEntry struct {
	Username *string `yaml:"username,omitempty" json:"username,omitempty"`
	Password *string `yaml:"password,omitempty" json:"password,omitempty"`
	Labels   Labels  `yaml:"labels,omitempty" json:"labels,omitempty"`
}

func NewMongoAuth(c *MongoAuthConfig) (*MongoAuth, error) {
	// Attempt to create new mongo session.
	session, err := mgo_session.New(c.MongoConfig)
	if err != nil {
		return nil, err
	}

	// Copy our session
	tmp_session := session.Copy()
	// Close up when we are done
	defer tmp_session.Close()

	// determine collection
	collection := tmp_session.DB(c.MongoConfig.DialInfo.Database).C(c.Collection)

	// Create username index obj
	index := mgo.Index{
		Key:      []string{"username"},
		Unique:   true,
		DropDups: false, // Error on duplicate key document instead of drop.
	}

	// Enforce a username index. This is fine to do frequently per the docs:
	// https://godoc.org/gopkg.in/mgo.v2#Collection.EnsureIndex:
	//    Once EnsureIndex returns successfully, following requests for the same index
	//    will not contact the server unless Collection.DropIndex is used to drop the same
	//    index, or Session.ResetIndexCache is called.
	if err := collection.EnsureIndex(index); err != nil {
		return nil, err
	}

	return &MongoAuth{
		config:  c,
		session: session,
	}, nil
}

func (mauth *MongoAuth) Authenticate(account string, password PasswordString) (bool, Labels, error) {
	for true {
		result, labels, err := mauth.authenticate(account, password)
		if err == io.EOF {
			glog.Warningf("EOF error received from Mongo. Retrying connection")
			time.Sleep(time.Second)
			continue
		}
		return result, labels, err
	}

	return false, nil, errors.New("Unable to communicate with Mongo.")
}

func (mauth *MongoAuth) authenticate(account string, password PasswordString) (bool, Labels, error) {
	// Copy our session
	tmp_session := mauth.session.Copy()
	// Close up when we are done
	defer tmp_session.Close()

	// Get Users from MongoDB
	glog.V(2).Infof("Checking user %s against Mongo Users. DB: %s, collection:%s",
		account, mauth.config.MongoConfig.DialInfo.Database, mauth.config.Collection)
	var dbUserRecord authUserEntry
	collection := tmp_session.DB(mauth.config.MongoConfig.DialInfo.Database).C(mauth.config.Collection)
	err := collection.Find(bson.M{"username": account}).One(&dbUserRecord)

	// If we connect and get no results we return a NoMatch so auth can fall-through
	if err == mgo.ErrNotFound {
		return false, nil, NoMatch
	} else if err != nil {
		return false, nil, err
	}

	// Validate db password against passed password
	if dbUserRecord.Password != nil {
		if bcrypt.CompareHashAndPassword([]byte(*dbUserRecord.Password), []byte(password)) != nil {
			return false, nil, nil
		}
	}

	// Auth success
	return true, dbUserRecord.Labels, nil
}

// Validate ensures that any custom config options
// in a Config are set correctly.
func (c *MongoAuthConfig) Validate(configKey string) error {
	//First validate the mongo config.
	if err := c.MongoConfig.Validate(configKey); err != nil {
		return err
	}

	// Now check additional config fields.
	if c.Collection == "" {
		return fmt.Errorf("%s.collection is required", configKey)
	}

	return nil
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
