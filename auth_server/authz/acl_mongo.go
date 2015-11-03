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

// ACLMongoConfig stores how to connect to
type ACLMongoConfig struct {
	Host            string `yaml:"host,omitempty"`
	Port            int    `yaml:"port,omitempty"`
	User            string `yaml:"user,omitempty"`
	PasswordFile    string `yaml:"password_file,omitempty"`
	Db              string `yaml:"db,omitempty"`
	Collection      string `yaml:"collection,omitempty"`
	CacheExpiration int64  `yaml:"cacheexpiration,omitempty"`
}

// Validate ensures all fields inside an ACLMongoConfig object are okay
func (c *ACLMongoConfig) Validate() error {
	if c.Host == "" {
		return errors.New("acl_mongo.host is required")
	}
	if c.Port <= 0 {
		return errors.New("acl_mongo.port is required")
	}
	/*
		if c.User == "" {
			return errors.New("acl_mongo.user is required")
		}
		if c.PasswordFile == "" {
			return errors.New("acl_mongo.password is required")
		}
	*/
	if c.Db == "" {
		return errors.New("acl_mongo.db is required")
	}
	if c.Collection == "" {
		return errors.New("acl_mongo.collection is required")
	}
	if c.CacheExpiration < 0 {
		return errors.New("acl_mongo.cacheexpiration is required")
	}
	return nil
}

type aclMongoAuthorizer struct {
	config *ACLMongoConfig
	cache  ACLCache
}

// ACLCache caches ACLs and remembers the last time it was updated
type ACLCache struct {
	ACL        ACL
	LastUpdate int64
}

// NewACLMongoAuthorizer creates a new ACL Mongo authorizer
func NewACLMongoAuthorizer(config *ACLMongoConfig) (Authorizer, error) {
	return &aclMongoAuthorizer{config: config}, nil
}

func (mongoAuthorizer *aclMongoAuthorizer) Authorize(ai *AuthRequestInfo) ([]string, error) {
	c := mongoAuthorizer.config

	if c == nil {
		return []string{}, fmt.Errorf("MongoDB ACL config is not set")
	}

	// Read in the password (if any)
	var password string
	if c.PasswordFile != "" {
		passBuf, err := ioutil.ReadFile(c.PasswordFile)
		if err != nil {
			return []string{}, fmt.Errorf("Failed to read password file \"%s\": %s", c.PasswordFile, err)
		}
		password = string(passBuf)
	}

	secondsSinceLastUpdate := time.Now().Unix() - mongoAuthorizer.cache.LastUpdate
	glog.V(2).Infof("Seconds since last update of ACL %d. Expiration time %d secs.", secondsSinceLastUpdate, c.CacheExpiration)

	// Test if cache has ever been filled or needs to be updated
	if len(mongoAuthorizer.cache.ACL) == 0 || secondsSinceLastUpdate > c.CacheExpiration {
		var credentialString string
		var credentialStringSafe string // Same as above but will have *** as password placeholder
		if c.User != "" && password == "" {
			credentialString = fmt.Sprintf("%s@", c.User)
			credentialStringSafe = fmt.Sprintf("%s@", c.User)
		}
		if c.User != "" && password != "" {
			credentialString = fmt.Sprintf("%s:%s@", c.User, password)
			credentialStringSafe = fmt.Sprintf("%s:%s@", c.User, "***")
		}
		connectionString := fmt.Sprintf("mongodb://%s%s:%d/%s", credentialString, c.Host, c.Port, c.Db)
		connectionStringSafe := fmt.Sprintf("mongodb://%s%s:%d/%s", credentialStringSafe, c.Host, c.Port, c.Db)
		glog.Infof("ACLs from MongoDB will be fetched from %s", connectionStringSafe)
		session, err := mgo.Dial(connectionString)
		if err != nil {
			return []string{}, err
		}
		defer session.Close()

		// Wait for errors on inserts and updates and for flushing changes to disk
		session.SetSafe(&mgo.Safe{FSync: true})

		collection := session.DB(c.Db).C(c.Collection)
		_ = collection.Find(bson.M{}).All(&mongoAuthorizer.cache.ACL)
		mongoAuthorizer.cache.LastUpdate = time.Now().Unix()
	} else {
		glog.V(2).Infof("Using cached ACLs from MongoDB")
	}

	// This loop is basically copied from the static authorizer
	for _, e := range mongoAuthorizer.cache.ACL {
		matched := e.Matches(ai)
		if matched {
			glog.V(2).Infof("%s matched %s (Comment: %s)", ai, e, e.Comment)
			if len(*e.Actions) == 1 && (*e.Actions)[0] == "*" {
				return ai.Actions, nil
			}
			return StringSetIntersection(ai.Actions, *e.Actions), nil
		}
	}
	return nil, NoMatch
}

func (mongoAuthorizer *aclMongoAuthorizer) Stop() {
	// Nothing to do.
}

func (mongoAuthorizer *aclMongoAuthorizer) Name() string {
	return "mongo ACL"
}

/*
type aclEntryJSON *ACLEntry

func (e ACLEntry) String() string {
	b, _ := json.Marshal(e)
	return string(b)
}

func matchString(pp *string, s string, vars []string) bool {
	if pp == nil {
		return true
	}
	p := strings.NewReplacer(vars...).Replace(*pp)

	var matched bool
	var err error
	if len(p) > 2 && p[0] == '/' && p[len(p)-1] == '/' {
		matched, err = regexp.Match(p[1:len(p)-1], []byte(s))
	} else {
		matched, err = path.Match(p, s)
	}
	return err == nil && matched
}

func (e *ACLEntry) Matches(ai *AuthRequestInfo) bool {
	vars := []string{
		"${account}", regexp.QuoteMeta(ai.Account),
		"${type}", regexp.QuoteMeta(ai.Type),
		"${name}", regexp.QuoteMeta(ai.Name),
		"${service}", regexp.QuoteMeta(ai.Service),
	}
	if matchString(e.Match.Account, ai.Account, vars) &&
		matchString(e.Match.Type, ai.Type, vars) &&
		matchString(e.Match.Name, ai.Name, vars) {
		return true
	}
	return false
}
*/
