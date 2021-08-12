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
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/cesanta/glog"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"

	"github.com/cesanta/docker_auth/auth_server/api"
	"github.com/cesanta/docker_auth/auth_server/mgo_session"
)

type MongoAuthConfig struct {
	MongoConfig *mgo_session.Config `yaml:"dial_info,omitempty"`
	Collection  string              `yaml:"collection,omitempty"`
}

type MongoAuth struct {
	config     *MongoAuthConfig
	session    *mongo.Client
	Collection string `yaml:"collection,omitempty"`
}

type authUserEntry struct {
	Username *string    `yaml:"username,omitempty" json:"username,omitempty"`
	Password *string    `yaml:"password,omitempty" json:"password,omitempty"`
	Labels   api.Labels `yaml:"labels,omitempty" json:"labels,omitempty"`
}

func NewMongoAuth(c *MongoAuthConfig) (*MongoAuth, error) {
	// Attempt to create new mongo session.
	session, err := mgo_session.New(c.MongoConfig)
	if err != nil {
		return nil, err
	}
	// determine collection
	collection := session.Database(c.MongoConfig.DialInfo.Database).Collection(c.Collection)

	// Create username index obj
	index := mongo.IndexModel{
		Keys:    bson.M{"username": 1},
		Options: options.Index().SetUnique(true),
	}

	// Enforce a username index.
	// mongodb will do no operation if index still exists.
	// see: https://pkg.go.dev/go.mongodb.org/mongo-driver/mongo#Collection.Indexes
	_, erri := collection.Indexes().CreateOne(context.TODO(), index)
	if erri != nil {
		fmt.Println(erri.Error())
		return nil, erri
	}

	return &MongoAuth{
		config:  c,
		session: session,
	}, nil
}

func (mauth *MongoAuth) Authenticate(account string, password api.PasswordString) (bool, api.Labels, error) {
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

func (mauth *MongoAuth) authenticate(account string, password api.PasswordString) (bool, api.Labels, error) {

	// Get Users from MongoDB
	glog.V(2).Infof("Checking user %s against Mongo Users. DB: %s, collection:%s",
		account, mauth.config.MongoConfig.DialInfo.Database, mauth.config.Collection)
	var dbUserRecord authUserEntry
	collection := mauth.session.Database(mauth.config.MongoConfig.DialInfo.Database).Collection(mauth.config.Collection)

	err := collection.FindOne(context.TODO(), bson.M{"username": account}).Decode(&dbUserRecord)

	// If we connect and get no results we return a NoMatch so auth can fall-through
	if err == mongo.ErrNoDocuments {
		return false, nil, api.NoMatch
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

}

func (ga *MongoAuth) Name() string {
	return "MongoDB"
}
