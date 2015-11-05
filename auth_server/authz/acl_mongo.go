package authz

import (
	"errors"
	"fmt"
	"io/ioutil"
	"sync"
	"time"

	"github.com/golang/glog"
	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
)

// ACLMongoConfig stores how to connect to the MongoDB server and how long
// an ACL remains valid until new ones will be fetched.
type ACLMongoConfig struct {
	DialInfo   ACLMongoDialConfig `yaml:"dial_info,omitempty"`
	Collection string             `yaml:"collection,omitempty"`
	CacheTTL   time.Duration      `yaml:"cache_ttl,omitempty"`
}

// ACLMongoDialConfig stores how we connect to the MongoDB server
type ACLMongoDialConfig struct {
	mgo.DialInfo `yaml:",inline"`
	PasswordFile string `yaml:"password_file,omitempty"`
}

// Validate ensures the most common fields inside the mgo.DialInfo portion of
// an ACLMongoDialInfo are set correctly as well as other fields inside the
// ACLMongoConfig itself.
func (c *ACLMongoConfig) Validate() error {
	if len(c.DialInfo.DialInfo.Addrs) == 0 {
		return errors.New("At least one element in acl_mongo.dial_info.addrs is required")
	}
	if c.DialInfo.DialInfo.Timeout == 0 {
		c.DialInfo.DialInfo.Timeout = 10 * time.Second
	}
	if c.DialInfo.DialInfo.Database == "" {
		return errors.New("acl_mongo.dial_info.database is required")
	}
	if c.Collection == "" {
		return errors.New("acl_mongo.collection is required")
	}
	if c.CacheTTL < 0 {
		return errors.New("acl_mongo.cache_ttl is required (e.g. \"1m\" for 1 minute)")
	}
	return nil
}

type aclMongoAuthorizer struct {
	lastCacheUpdate  time.Time
	lock             sync.RWMutex
	config           ACLMongoConfig
	staticAuthorizer Authorizer
	session          *mgo.Session
}

// NewACLMongoAuthorizer creates a new ACL Mongo authorizer
func NewACLMongoAuthorizer(c ACLMongoConfig) (Authorizer, error) {
	// Attempt to create a MongoDB session which we can re-use when handling
	// multiple auth requests.

	// Read in the password (if any)
	if c.DialInfo.PasswordFile != "" {
		passBuf, err := ioutil.ReadFile(c.DialInfo.PasswordFile)
		if err != nil {
			return nil, fmt.Errorf("Failed to read password file \"%s\": %s", c.DialInfo.PasswordFile, err)
		}
		c.DialInfo.DialInfo.Password = string(passBuf)
	}

	glog.Infof("Creating MongoDB session (operation timeout %s)", c.DialInfo.DialInfo.Timeout)
	session, err := mgo.DialWithInfo(&c.DialInfo.DialInfo)
	if err != nil {
		return nil, err
	}

	return &aclMongoAuthorizer{config: c, session: session}, nil
}

func (ma *aclMongoAuthorizer) Authorize(ai *AuthRequestInfo) ([]string, error) {
	if err := ma.MaybeUpdateACLCache(); err != nil {
		return nil, err
	}

	return ma.staticAuthorizer.Authorize(ai)
}

func (ma *aclMongoAuthorizer) Stop() {
	// Close connection to MongoDB database (if any)
	if ma.session != nil {
		ma.session.Close()
	}
}

func (ma *aclMongoAuthorizer) Name() string {
	return "MongoDB ACL"
}

// MaybeUpdateACLCache checks if the ACL cache has expired and depending on the
// the result it updates the cache with the ACL from the MongoDB server. The
// ACL will be stored inside the static authorizer instance which we use
// to minimize duplication of code and maximize reuse of existing code.
func (ma *aclMongoAuthorizer) MaybeUpdateACLCache() error {
	// Acquire a read lock on the cache.
	// We would like to automatically unlock the mutex but we might have to
	// acquire a write lock on the mutex for which we have to manually RUnlock it
	// first. With the commented out defer line below we would then RUnlock the
	// mutex twice which would result in a run-time error.
	ma.lock.RLock()
	//defer ma.cache.guard.RUnlock()

	aclAge := time.Now().Sub(ma.lastCacheUpdate)
	glog.V(2).Infof("ACL age: %s. CacheTTL: %s", aclAge, ma.config.CacheTTL)

	// Test if cache has needs to be updated
	if aclAge < ma.config.CacheTTL {
		glog.V(2).Infof("Using cached ACL from MongoDB (Age: %s, TTL: %s).", aclAge, ma.config.CacheTTL)
		ma.lock.RUnlock()
		return nil
	}

	// Time to acquire a write lock on the ACL cache.
	ma.lock.RUnlock()
	ma.lock.Lock()
	defer ma.lock.Unlock()

	// Potentially the cache can be modified between RUnlock() and Lock(),
	// therefore we need to re-check if the acl cache expired once we acquired
	// the write lock.
	if aclAge < ma.config.CacheTTL {
		glog.V(2).Infof("Using cached ACL from MongoDB (Age: %s, TTL: %s).", aclAge, ma.config.CacheTTL)
		return nil
	}

	sessionCopy := ma.session.Copy()
	defer sessionCopy.Close()

	var newCache ACL
	collection := sessionCopy.DB(ma.config.DialInfo.DialInfo.Database).C(ma.config.Collection)
	err := collection.Find(bson.M{}).All(&newCache)
	if err != nil {
		glog.Errorf("Failed to update ACL from MongoDB. ERROR: %s", err)
		// Only return the error if there's no authorizer we can re-use
		if ma.staticAuthorizer == nil {
			return err
		}
		glog.Infof("Using stale ACL (Age: %s, TTL: %s)", aclAge, ma.config.CacheTTL)
		return nil
	}

	// Finally update the cache
	ma.lastCacheUpdate = time.Now()
	// Create a new static authorizer reusing the ACL we fetched from MongoDB
	ma.staticAuthorizer, err = NewACLAuthorizer(newCache)
	if err != nil {
		return err
	}

	return nil
}
