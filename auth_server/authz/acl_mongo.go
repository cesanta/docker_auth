package authz

import (
	"fmt"
	"sync"
	"time"

	"github.com/cesanta/docker_auth/auth_server/mgo_session"
	"github.com/golang/glog"
	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
)

type aclMongoAuthorizer struct {
	lastCacheUpdate  time.Time
	lock             sync.RWMutex
	config           *mgo_session.MongoConfig
	staticAuthorizer Authorizer
	session          *mgo.Session
	updateTicker     *time.Ticker
}

// NewACLMongoAuthorizer creates a new ACL Mongo authorizer
func NewACLMongoAuthorizer(c *mgo_session.MongoConfig) (Authorizer, error) {
	// Attempt to create new mongo session.
	session, err := mgo_session.New(c)
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

	// Copy our session
	glog.V(2).Infof("Copy MongoDB session for Authenticate")
	tmp_session := ma.session.Copy()

	// Close up when we are done
	defer tmp_session.Close()

	collection := tmp_session.DB(ma.config.DialConfig.DialInfo.Database).C(ma.config.Collection)
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
