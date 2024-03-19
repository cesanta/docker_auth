/*
   Copyright 2020 Cesanta Software Ltd.

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

package authz

import (
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/cesanta/docker_auth/auth_server/api"
	"github.com/cesanta/glog"

	_ "github.com/go-sql-driver/mysql"
	_ "github.com/lib/pq"
	"xorm.io/xorm"
)

var (
	EnableSQLite3 = false
)

type XormAuthzConfig struct {
	DatabaseType string        `yaml:"database_type,omitempty"`
	ConnString   string        `yaml:"conn_string,omitempty"`
	CacheTTL     time.Duration `yaml:"cache_ttl,omitempty"`
}

type XormACL []XormACLEntry

type XormACLEntry struct {
	ACLEntry `xorm:"'acl_entry' JSON"`
	Seq      int64
}

func (x XormACLEntry) TableName() string {
	return "xorm_acl_entry"
}

type aclXormAuthz struct {
	lastCacheUpdate  time.Time
	lock             sync.RWMutex
	config           *XormAuthzConfig
	staticAuthorizer api.Authorizer
	engine           *xorm.Engine
	updateTicker     *time.Ticker
}

func NewACLXormAuthz(c *XormAuthzConfig) (api.Authorizer, error) {
	e, err := xorm.NewEngine(c.DatabaseType, c.ConnString)
	if err != nil {
		return nil, err
	}

	if err := e.Sync2(new(XormACLEntry)); err != nil {
		return nil, fmt.Errorf("Sync2: %v", err)
	}
	authorizer := &aclXormAuthz{
		config:       c,
		engine:       e,
		updateTicker: time.NewTicker(c.CacheTTL),
	}

	// Initially fetch the ACL from XORM
	if err := authorizer.updateACLCache(); err != nil {
		return nil, err
	}

	go authorizer.continuouslyUpdateACLCache()

	return authorizer, nil
}

func (xa *aclXormAuthz) Authorize(ai *api.AuthRequestInfo) ([]string, error) {
	xa.lock.RLock()
	defer xa.lock.RUnlock()

	// Test if authorizer has been initialized
	if xa.staticAuthorizer == nil {
		return nil, fmt.Errorf("XORM.io authorizer is not ready")
	}

	return xa.staticAuthorizer.Authorize(ai)
}

func (xa *aclXormAuthz) Stop() {
	if xa.engine != nil {
		xa.engine.Close()
	}
}
func (xa *XormAuthzConfig) Validate(configKey string) error {
	// TODO: Validate authz
	return nil
}

func (xa *aclXormAuthz) Name() string {
	return "XORM.io Authz"
}

func (xa *aclXormAuthz) continuouslyUpdateACLCache() {
	var tick time.Time
	for ; true; tick = <-xa.updateTicker.C {
		aclAge := time.Now().Sub(xa.lastCacheUpdate)
		glog.V(2).Infof("Updating ACL at %s (ACL age: %s. CacheTTL: %s)", tick, aclAge, xa.config.CacheTTL)

		for true {
			err := xa.updateACLCache()
			if err == nil {
				break
			} else if err == io.EOF {
				glog.Warningf("EOF error received from Xorm. Retrying connection")
				time.Sleep(time.Second)
				continue
			} else {
				glog.Errorf("Failed to update ACL. ERROR: %s", err)
				glog.Warningf("Using stale ACL (Age: %s, TTL: %s)", aclAge, xa.config.CacheTTL)
				break
			}
		}
	}
}

func (xa *aclXormAuthz) updateACLCache() error {
	// Get ACL from Xorm.io database connection
	var newACL []XormACLEntry

	err := xa.engine.OrderBy("seq").Find(&newACL)
	if err != nil {
		return err
	}
	var retACL ACL
	for _, e := range newACL {
		retACL = append(retACL, e.ACLEntry)
	}

	newStaticAuthorizer, err := NewACLAuthorizer(retACL)
	if err != nil {
		return err
	}

	xa.lock.Lock()
	xa.lastCacheUpdate = time.Now()
	xa.staticAuthorizer = newStaticAuthorizer
	xa.lock.Unlock()

	glog.V(2).Infof("Got new ACL from XORM: %s", retACL)
	glog.V(1).Infof("Installed new ACL from XORM (%d entries)", len(retACL))
	return nil

}
