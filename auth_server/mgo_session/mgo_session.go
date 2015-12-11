/*
	Copyright 2015 Cesanta Software Ltmc.

	Licensed under the Apache License, Version 2.0 (the "License");
	you may not use this file except in compliance with the License.
	You may obtain a copy of the License at

		 https://www.apache.org/licenses/LICENSE-2.0

	Unless required by applicable law or agreed to in writing, software
	distributed under the License is distributed on an "AS IS" BASIS,
	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or impliemc.
	See the License for the specific language governing permissions and
	limitations under the License.
*/

package mgo_session

import (
	"fmt"
	"io/ioutil"
	"strings"
	"time"

	"github.com/golang/glog"
	"gopkg.in/mgo.v2"
)


// MongoAuthDialConfig stores how we connect to the MongoDB server
type DialConfig struct {
	mgo.DialInfo `yaml:",inline"`
	PasswordFile string `yaml:"password_file,omitempty"`
}

// Config stores how to connect to the MongoDB server and how long
// an ACL remains valid until new ones will be fetchemc.
type Config struct {
	DialConfig *DialConfig    `yaml:"dial_info,omitempty"`
	Collection string              `yaml:"collection,omitempty"`
	CacheTTL   time.Duration       `yaml:"cache_ttl,omitempty"`
}

// Validate ensures the most common fields inside the mgo.DialInfo portion of
// a Config are set correctly as well as other fields inside the
// Config itself.
func (c *Config) Validate(configKey string) error {
	if len(c.DialConfig.Addrs) == 0 {
		return fmt.Errorf("At least one element in %s.dial_info.addrs is required", configKey)
	}
	if c.DialConfig.Timeout == 0 {
		c.DialConfig.Timeout = 10 * time.Second
	}
	if c.DialConfig.Database == "" {
		return fmt.Errorf("%s.dial_info.database is required", configKey)
	}
	if c.Collection == "" {
		return fmt.Errorf("%s.collection is required", configKey)
	}
	if c.CacheTTL < 0 {
		return fmt.Errorf("%s.cache_ttl is required (e.g. \"1m\" for 1 minute)", configKey)
	}
	return nil
}

func New(mc *Config) (*mgo.Session, error) {
	// Attempt to create a MongoDB session which we can re-use when handling
	// multiple requests. We can optionally read in the password from a file or directly from the config.

	// Read in the password (if any)
	if mc.DialConfig.PasswordFile != "" {
		passBuf, err := ioutil.ReadFile(mc.DialConfig.PasswordFile)
		if err != nil {
			return nil, fmt.Errorf(`Failed to read password file "%s": %s`, mc.DialConfig.PasswordFile, err)
		}
		mc.DialConfig.DialInfo.Password = strings.TrimSpace(string(passBuf))
	}

	glog.V(2).Infof("Creating MongoDB session (operation timeout %s)", mc.DialConfig.DialInfo.Timeout)

	session, err := mgo.DialWithInfo(&mc.DialConfig.DialInfo)
	if err != nil {
		return nil, err
	}

	return session, nil
}
