package authn

import (
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/cesanta/docker_auth/auth_server/couchdb_session"
	"github.com/cesanta/docker_auth/auth_server/utils"
	"github.com/golang/glog"
	"github.com/segmentio/pointer"
	"github.com/zemirco/couchdb"
)

type CouchDBAuthConfig struct {
	CouchDBConfig *couchdb_session.Config `yaml:"dial_info,omitempty"`
}

type CouchDBAuth struct {
	config *CouchDBAuthConfig
	db     *couchdb.Database
}

type CouchDBUser struct {
	couchdb.Document
	Username *string `yaml:"username,omitempty" json:"username,omitempty"`
	Password *string `yaml:"password,omitempty" json:"password,omitempty"`
}

func NewCouchDBAuth(c *CouchDBAuthConfig) (*CouchDBAuth, error) {
	// Attempt to create new couchdb client.
	client, err := couchdb_session.New(c.CouchDBConfig)
	if err != nil {
		return nil, err
	}

	dbName := c.CouchDBConfig.DialInfo.Database
	allDBs, err := client.All()
	if err != nil {
		return nil, err
	}
	if !utils.StringInSlice(dbName, allDBs) {
		// db not exist, create
		_, err = client.Create(dbName)
		if err != nil {
			glog.V(2).Infof("Create db %s on CouchDB error: %v\n", dbName, err)
			return nil, err
		}
	}

	db := client.Use(dbName)

	return &CouchDBAuth{
		config: c,
		db:     &db,
	}, nil
}

func (cauth *CouchDBAuth) Authenticate(account string, password PasswordString) (bool, Labels, error) {
	for true {
		result, err := cauth.authenticate(account, password)
		if err == io.EOF {
			glog.Warningf("EOF error received from CouchDB. Retrying connection")
			time.Sleep(time.Second)
			continue
		}
		return result, nil, err
	}

	return false, nil, errors.New("Unable to communicate with CouchDB.")
}

// CouchDB need `view` to find(filter) data from database.
// A `view` is some javascript segment in document named `_design/*`
// http://guide.couchdb.org/draft/views.html
//
// We know:
// 		DB: user
// 		DesignDoc: _design/user
// 		View: getByUsername
//		Field username: doc.username
//		Field password: doc.password
func (cauth *CouchDBAuth) authenticate(account string, password PasswordString) (bool, error) {
	// Get Users from CouchDB
	glog.V(2).Infof("Checking user %s against CouchDB Users. DB: %s",
		account, cauth.config.CouchDBConfig.DialInfo.Database)

	view := cauth.db.View(cauth.config.CouchDBConfig.DialInfo.Design)
	queryParams := couchdb.QueryParameters{
		Key: pointer.String(fmt.Sprintf("%q", account)),
	}
	res, err := view.Get(cauth.config.CouchDBConfig.DialInfo.View, queryParams)
	if err != nil {
		return false, err
	}
	if res != nil {
		for _, r := range res.Rows {
			valueMap := r.Value.(map[string]interface{})
			// valueMap looks like this
			// Key "_id", Value "d61501d99587ad7d86e69a5520005844"
			// Key "_rev", Value "1-4e9b44eafd0fbc6bd4a04c0f73868627"
			// Key "username", Value "someone"
			// Key "password", Value "secret123"
			if valueMap["username"] == account && valueMap["password"] == string(password) {
				return true, nil
			}
		}
	}
	return false, NoMatch
}

// Validate ensures that any custom config options
// in a Config are set correctly.
func (c *CouchDBAuthConfig) Validate(configKey string) (err error) {
	//First validate the couchdb config.
	if err := c.CouchDBConfig.Validate(configKey); err != nil {
		return err
	}

	// Now check additional config fields.

	return nil
}

func (cauth *CouchDBAuth) Stop() {
	// Close connection to CouchDB database (if any)
	if cauth.db != nil {
		// TODO caution memory leak
		// cauth.db.Close()
	}
}

func (cauth *CouchDBAuth) Name() string {
	return "CouchDB"
}
