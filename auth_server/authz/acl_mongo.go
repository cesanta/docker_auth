package authz

import (
	"errors"
	"fmt"
	"io/ioutil"
	"time"

	"github.com/golang/glog"
	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
)

// ACLMongoConfig stores how to connect to the MongoDB server and how long
// an ACL remains valid until new ones will be fetched.
type ACLMongoConfig struct {
	Host             string        `yaml:"host,omitempty"`
	Port             int           `yaml:"port,omitempty"`
	OperationTimeout time.Duration `yaml:"operation_timeout,omitempty"`
	User             string        `yaml:"user,omitempty"`
	PasswordFile     string        `yaml:"password_file,omitempty"`
	Db               string        `yaml:"db,omitempty"`
	Collection       string        `yaml:"collection,omitempty"`
	CacheDuration    time.Duration `yaml:"cache_duration,omitempty"`
}

// Validate ensures all fields inside an ACLMongoConfig object are okay
func (c *ACLMongoConfig) Validate() error {
	if c.Host == "" {
		return errors.New("acl_mongo.host is required")
	}
	if c.Port <= 0 {
		return errors.New("acl_mongo.port is required")
	}
	if c.OperationTimeout.String() == "" {
		return errors.New("acl_mongo.operation_timeout is required (e.g. \"10s\" for 10 seconds)")
	}
	if c.Db == "" {
		return errors.New("acl_mongo.db is required")
	}
	if c.Collection == "" {
		return errors.New("acl_mongo.collection is required")
	}
	if c.CacheDuration.String() == "" {
		return errors.New("acl_mongo.cache_duration is required (e.g. \"1m\" for one minute)")
	}
	return nil
}

type aclMongoAuthorizer struct {
	config           *ACLMongoConfig
	cache            ACLCache
	staticAuthorizer Authorizer
}

// ACLCache caches ACL and remembers the last time it was updated
type ACLCache struct {
	ACL        ACL
	LastUpdate time.Time
}

// NewACLMongoAuthorizer creates a new ACL Mongo authorizer
func NewACLMongoAuthorizer(config *ACLMongoConfig) (Authorizer, error) {
	return &aclMongoAuthorizer{config: config}, nil
}

func (mongoAuthorizer *aclMongoAuthorizer) Authorize(ai *AuthRequestInfo) ([]string, error) {
	if mongoAuthorizer.config == nil {
		return nil, fmt.Errorf("MongoDB ACL config is not set")
	}

	if err := mongoAuthorizer.MaybeUpdateACLCache(); err != nil {
		return nil, err
	}

	return mongoAuthorizer.staticAuthorizer.Authorize(ai)
}

func (mongoAuthorizer *aclMongoAuthorizer) Stop() {
	// Nothing to do.
}

func (mongoAuthorizer *aclMongoAuthorizer) Name() string {
	return "mongo ACL"
}

// MaybeUpdateACLCache checks if the ACL cache has expired and depending on the
// the result it updates the cache with the ACL from the MongoDB server. The
// ACL will be stored inside the static authorizer instance which we use
// to minimize duplication of code and maximize reuse of existing code.
func (mongoAuthorizer *aclMongoAuthorizer) MaybeUpdateACLCache() error {
	c := mongoAuthorizer.config

	duration := time.Now().Sub(mongoAuthorizer.cache.LastUpdate)
	glog.V(2).Infof("Duration since last update of ACL %s. Cache expires afer %s.", duration.String(), c.CacheDuration.String())

	// Test if cache has ever been filled or needs to be updated
	if len(mongoAuthorizer.cache.ACL) == 0 || duration.Seconds() > c.CacheDuration.Seconds() {
		// Read in the password (if any)
		var password string
		if c.PasswordFile != "" {
			passBuf, err := ioutil.ReadFile(c.PasswordFile)
			if err != nil {
				return fmt.Errorf("Failed to read password file \"%s\": %s", c.PasswordFile, err)
			}
			password = string(passBuf)
		}

		glog.Infof("ACL from MongoDB will be fetched from %s:%d (operation timeout %s)", c.Host, c.Port, c.OperationTimeout.String())
		session, err := mgo.DialWithInfo(&mgo.DialInfo{
			Addrs:    []string{c.Host},
			Username: c.User,
			Password: password,
			Database: c.Db,
			Timeout:  c.OperationTimeout,
		})

		glog.V(2).Infof("ERROR: %s", err)

		if err != nil {
			return err
		}
		defer session.Close()

		mongoAuthorizer.cache.ACL = ACL{} // Reset ACL
		collection := session.DB(c.Db).C(c.Collection)
		err = collection.Find(bson.M{}).All(&mongoAuthorizer.cache.ACL)
		if err != nil {
			return err
		}
		mongoAuthorizer.cache.LastUpdate = time.Now()

		// Create a new static authorizer reusing the ACL we fetched from MongoDB
		mongoAuthorizer.staticAuthorizer, err = NewACLAuthorizer(mongoAuthorizer.cache.ACL)
		if err != nil {
			return err
		}
	} else {
		glog.V(2).Infof("Using cached ACL from MongoDB.")
	}

	return nil
}
