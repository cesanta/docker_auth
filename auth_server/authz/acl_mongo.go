package authz

import (
	"errors"
	"fmt"
	"github.com/cesanta/docker_auth/auth_server/mgo_session"
	"github.com/cesanta/glog"
	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
	"io"
	"sync"
	"time"
)

type MongoACL []MongoACLEntry

type MongoACLEntry struct {
	ACLEntry `bson:",inline"`
	Seq      *int
}

type ACLMongoConfig struct {
	MongoConfig *mgo_session.Config `yaml:"dial_info,omitempty"`
	Collection  string              `yaml:"collection,omitempty"`
	CacheTTL    time.Duration       `yaml:"cache_ttl,omitempty"`
}

type aclMongoAuthorizer struct {
	lastCacheUpdate  time.Time
	lock             sync.RWMutex
	config           *ACLMongoConfig
	staticAuthorizer Authorizer
	session          *mgo.Session
	updateTicker     *time.Ticker
	Collection       string        `yaml:"collection,omitempty"`
	CacheTTL         time.Duration `yaml:"cache_ttl,omitempty"`
}

// NewACLMongoAuthorizer creates a new ACL MongoDB authorizer
func NewACLMongoAuthorizer(c *ACLMongoConfig) (Authorizer, error) {
	// Attempt to create new MongoDB session.
	session, err := mgo_session.New(c.MongoConfig)
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

// Validate ensures that any custom config options
// in a Config are set correctly.
func (c *ACLMongoConfig) Validate(configKey string) error {
	//First validate the MongoDB config.
	if err := c.MongoConfig.Validate(configKey); err != nil {
		return err
	}

	// Now check additional config fields.
	if c.Collection == "" {
		return fmt.Errorf("%s.collection is required", configKey)
	}
	if c.CacheTTL < 0 {
		return fmt.Errorf("%s.cache_ttl is required (e.g. \"1m\" for 1 minute)", configKey)
	}

	return nil
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

		for true {
			err := ma.updateACLCache()
			if err == nil {
				break
			} else if err == io.EOF {
				glog.Warningf("EOF error received from Mongo. Retrying connection")
				time.Sleep(time.Second)
				continue
			} else {
				glog.Errorf("Failed to update ACL. ERROR: %s", err)
				glog.Warningf("Using stale ACL (Age: %s, TTL: %s)", aclAge, ma.config.CacheTTL)
				break
			}
		}
	}
}

func (ma *aclMongoAuthorizer) updateACLCache() error {
	// Get ACL from MongoDB
	var newACL MongoACL

	// Copy our session
	tmp_session := ma.session.Copy()

	// Close up when we are done
	defer tmp_session.Close()

	collection := tmp_session.DB(ma.config.MongoConfig.DialInfo.Database).C(ma.config.Collection)

	// Create sequence index obj
	index := mgo.Index{
		Key:      []string{"seq"},
		Unique:   true,
		DropDups: false, // Error on duplicate key document instead of drop.
	}

	// Enforce a sequence index. This is fine to do frequently per the docs:
	// https://godoc.org/gopkg.in/mgo.v2#Collection.EnsureIndex:
	//    Once EnsureIndex returns successfully, following requests for the same index
	//    will not contact the server unless Collection.DropIndex is used to drop the same
	//    index, or Session.ResetIndexCache is called.
	if err := collection.EnsureIndex(index); err != nil {
		return err
	}

	// Get all ACLs that have the required key
	if err := collection.Find(bson.M{}).Sort("seq").All(&newACL); err != nil {
		return err
	}

	glog.V(2).Infof("Number of new ACL entries from MongoDB: %d", len(newACL))

	// It is possible that the top document in the collection exists with a nil Seq.
	// if that's true we pull it out of the slice and complain about it.
	if len(newACL) > 0 && newACL[0].Seq == nil {
		topACL := newACL[0]
		return errors.New(fmt.Sprintf("Seq not set for ACL entry: %+v", topACL))
	}

	var retACL ACL
	for _, e := range newACL {
		retACL = append(retACL, e.ACLEntry)
	}

	newStaticAuthorizer, err := NewACLAuthorizer(retACL)
	if err != nil {
		return err
	}

	ma.lock.Lock()
	ma.lastCacheUpdate = time.Now()
	ma.staticAuthorizer = newStaticAuthorizer
	ma.lock.Unlock()

	glog.V(2).Infof("Got new ACL from MongoDB: %s", retACL)
	glog.V(1).Infof("Installed new ACL from MongoDB (%d entries)", len(retACL))
	return nil
}
