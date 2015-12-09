package authz

import (
	"errors"
	"fmt"
	"io/ioutil"
	"strings"
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
		return errors.New(`acl_mongo.cache_ttl is required (e.g. "1m" for 1 minute)`)
	}
	return nil
}

type aclMongoAuthorizer struct {
	lastCacheUpdate  time.Time
	lock             sync.RWMutex
	config           ACLMongoConfig
	staticAuthorizer Authorizer
	session          *mgo.Session
	updateTicker     *time.Ticker
}

// NewACLMongoAuthorizer creates a new ACL Mongo authorizer
func NewACLMongoAuthorizer(c ACLMongoConfig) (Authorizer, error) {
	// Attempt to create a MongoDB session which we can re-use when handling
	// multiple auth requests.

	// Read in the password (if any)
	if c.DialInfo.PasswordFile != "" {
		passBuf, err := ioutil.ReadFile(c.DialInfo.PasswordFile)
		if err != nil {
			return nil, fmt.Errorf(`Failed to read password file "%s": %s`, c.DialInfo.PasswordFile, err)
		}
		c.DialInfo.DialInfo.Password = strings.TrimSpace(string(passBuf))
	}

	glog.V(2).Infof("Creating MongoDB session (operation timeout %s)", c.DialInfo.DialInfo.Timeout)
	session, err := mgo.DialWithInfo(&c.DialInfo.DialInfo)
	if err != nil {
		return nil, err
	}

	authorizer := &aclMongoAuthorizer{
		config:       c,
		session:      session,
		updateTicker: time.NewTicker(c.CacheTTL),
	}

	// Initially fetch the ACL from MongoDB
	if err := authorizer.updateACLCache(); err != nil {
		return nil, err
	}

	go authorizer.continuouslyUpdateACLCache()

	return authorizer, nil
}

func (ma *aclMongoAuthorizer) Authorize(ai *AuthRequestInfo) ([]string, error) {
	ma.lock.RLock()
	defer ma.lock.RUnlock()

	// Test if authorizer has been initialized
	if ma.staticAuthorizer == nil {
		return nil, fmt.Errorf("MongoDB authorizer is not ready")
	}

	return ma.staticAuthorizer.Authorize(ai)
}

func (ma *aclMongoAuthorizer) Stop() {
	// This causes the background go routine which updates the ACL to stop
	ma.updateTicker.Stop()

	// Close connection to MongoDB database (if any)
	if ma.session != nil {
		ma.session.Close()
	}
}

func (ma *aclMongoAuthorizer) Name() string {
	return "MongoDB ACL"
}

// continuouslyUpdateACLCache checks if the ACL cache has expired and depending
// on the the result it updates the cache with the ACL from the MongoDB server.
// The ACL will be stored inside the static authorizer instance which we use
// to minimize duplication of code and maximize reuse of existing code.
func (ma *aclMongoAuthorizer) continuouslyUpdateACLCache() {
	var tick time.Time
	for ; true; tick = <-ma.updateTicker.C {
		aclAge := time.Now().Sub(ma.lastCacheUpdate)
		glog.V(2).Infof("Updating ACL at %s (ACL age: %s. CacheTTL: %s)", tick, aclAge, ma.config.CacheTTL)

		err := ma.updateACLCache()
		if err == nil {
			continue
		}

		glog.Errorf("Failed to update ACL. ERROR: %s", err)
		glog.Warningf("Using stale ACL (Age: %s, TTL: %s)", aclAge, ma.config.CacheTTL)
	}
}

func (ma *aclMongoAuthorizer) updateACLCache() error {
	// Get ACL from MongoDB
	var newACL ACL
	collection := ma.session.DB(ma.config.DialInfo.DialInfo.Database).C(ma.config.Collection)
	err := collection.Find(bson.M{}).All(&newACL)
	if err != nil {
		return err
	}
	glog.V(2).Infof("Number of new ACL entries from MongoDB: %d", len(newACL))

	newStaticAuthorizer, err := NewACLAuthorizer(newACL)
	if err != nil {
		return err
	}

	ma.lock.Lock()
	ma.lastCacheUpdate = time.Now()
	ma.staticAuthorizer = newStaticAuthorizer
	ma.lock.Unlock()

	glog.V(2).Infof("Got new ACL from MongoDB: %s", newACL)
	glog.V(1).Infof("Installed new ACL from MongoDB (%d entries)", len(newACL))
	return nil
}
