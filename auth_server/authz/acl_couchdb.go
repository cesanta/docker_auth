package authz

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/cesanta/docker_auth/auth_server/couchdb_session"
	"github.com/cesanta/docker_auth/auth_server/utils"
	"github.com/golang/glog"
	"github.com/zemirco/couchdb"
)

type CouchDBACL []CouchDBACLEntry

type CouchDBACLEntry struct {
	ACLEntry `bson:",inline"`
	Seq      *int
}

type ACLCouchDBConfig struct {
	CouchDBConfig *couchdb_session.Config `yaml:"dial_info,omitempty"`
	CacheTTL      time.Duration           `yaml:"cache_ttl,omitempty"`
}

type aclCouchDBAuthorizer struct {
	lastCacheUpdate  time.Time
	lock             sync.RWMutex
	config           *ACLCouchDBConfig
	staticAuthorizer Authorizer
	db               *couchdb.Database
	updateTicker     *time.Ticker
	CacheTTL         time.Duration `yaml:"cache_ttl,omitempty"`
}

// NewACLCouchDBAuthorizer creates a new ACL CouchDB authorizer
func NewACLCouchDBAuthorizer(c *ACLCouchDBConfig) (Authorizer, error) {
	// Attempt to create new CouchDB session.
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

	authorizer := &aclCouchDBAuthorizer{
		config:       c,
		db:           &db,
		updateTicker: time.NewTicker(c.CacheTTL),
	}

	// Initially fetch the ACL from CouchDB
	if err := authorizer.updateACLCache(); err != nil {
		return nil, err
	}

	go authorizer.continuouslyUpdateACLCache()

	return authorizer, nil
}

func (ca *aclCouchDBAuthorizer) Authorize(ai *AuthRequestInfo) ([]string, error) {
	ca.lock.RLock()
	defer ca.lock.RUnlock()

	// Test if authorizer has been initialized
	if ca.staticAuthorizer == nil {
		return nil, fmt.Errorf("CouchDB authorizer is not ready")
	}

	return ca.staticAuthorizer.Authorize(ai)
}

// Validate ensures that any custom config options
// in a Config are set correctly.
func (c *ACLCouchDBConfig) Validate(configKey string) error {
	//First validate the CouchDB config.
	if err := c.CouchDBConfig.Validate(configKey); err != nil {
		return err
	}

	// Now check additional config fields.
	if c.CacheTTL < 0 {
		return fmt.Errorf("%s.cache_ttl is required (e.g. \"1m\" for 1 minute)", configKey)
	}

	return nil
}

func (ca *aclCouchDBAuthorizer) Stop() {
	// This causes the background go routine which updates the ACL to stop
	ca.updateTicker.Stop()

	// Close connection to CouchDB database (if any)
	if ca.db != nil {
		// TODO caution memory leak
		// ca.db.Close()
	}
}

func (ca *aclCouchDBAuthorizer) Name() string {
	return "CouchDB ACL"
}

// continuouslyUpdateACLCache checks if the ACL cache has expired and depending
// on the the result it updates the cache with the ACL from the CouchDB server.
// The ACL will be stored inside the static authorizer instance which we use
// to minimize duplication of code and maximize reuse of existing code.
func (ca *aclCouchDBAuthorizer) continuouslyUpdateACLCache() {
	var tick time.Time
	for ; true; tick = <-ca.updateTicker.C {
		aclAge := time.Now().Sub(ca.lastCacheUpdate)
		glog.V(2).Infof("Updating ACL at %s (ACL age: %s. CacheTTL: %s)", tick, aclAge, ca.config.CacheTTL)

		for true {
			err := ca.updateACLCache()
			if err == nil {
				break
			} else if err == io.EOF {
				glog.Warningf("EOF error received from CouchDB. Retrying connection")
				time.Sleep(time.Second)
				continue
			} else {
				glog.Errorf("Failed to update ACL. ERROR: %s", err)
				glog.Warningf("Using stale ACL (Age: %s, TTL: %s)", aclAge, ca.config.CacheTTL)
				break
			}
		}
	}
}

func (ca *aclCouchDBAuthorizer) updateACLCache() error {
	// Get ACL from CouchDB
	var newACL CouchDBACL

	view := ca.db.View(ca.config.CouchDBConfig.DialInfo.Design)
	// query all
	queryParams := couchdb.QueryParameters{}
	res, err := view.Get(ca.config.CouchDBConfig.DialInfo.View, queryParams)
	if err != nil {
		glog.V(2).Infof("Query acls by view getBySeq error: %v", err)
		return err
	}
	if res != nil {
		for _, r := range res.Rows {
			valueMap := r.Value.(map[string]interface{})
			// valueMap looks like this
			// Key Match, Value map[account:admin]
			// Key Actions, Value [*]
			// Key Comment, Value Admin has full access to everything.
			// Key _id, Value 52df6a4c186dc6677e2dba92860000c0
			// Key _rev, Value 1-6722270fc0288e04673d17366318cbba
			// Key Seq, Value 10

			// I have to marshal/unmarshal because it cannot convert to struct CouchDBACLEntry
			// TODO any better idea?
			aclEntry := CouchDBACLEntry{}
			data, errMa := json.Marshal(valueMap)
			if errMa != nil {
				return errMa
			}
			errUm := json.Unmarshal(data, &aclEntry)
			if errUm != nil {
				return errUm
			}
			newACL = append(newACL, aclEntry)
		}
	}

	glog.V(2).Infof("Number of new ACL entries from CouchDB: %d", len(newACL))

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

	ca.lock.Lock()
	ca.lastCacheUpdate = time.Now()
	ca.staticAuthorizer = newStaticAuthorizer
	ca.lock.Unlock()

	glog.V(2).Infof("Got new ACL from CouchDB: %s", retACL)
	glog.V(1).Infof("Installed new ACL from CouchDB (%d entries)", len(retACL))
	return nil
}
