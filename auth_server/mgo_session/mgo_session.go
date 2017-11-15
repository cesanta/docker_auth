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
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net"
	"strings"
	"time"

	"github.com/cesanta/glog"
	"gopkg.in/mgo.v2"
)

// Config stores how to connect to the MongoDB server and an optional password file
type Config struct {
	DialInfo     mgo.DialInfo `yaml:",inline"`
	PasswordFile string       `yaml:"password_file,omitempty"`
	EnableTLS    bool         `yaml:"enable_tls,omitempty"`
}

// Validate ensures the most common fields inside the mgo.DialInfo portion of
// a Config are set correctly as well as other fields inside the
// Config itself.
func (c *Config) Validate(configKey string) error {
	if len(c.DialInfo.Addrs) == 0 {
		return fmt.Errorf("At least one element in %s.dial_info.addrs is required", configKey)
	}
	if c.DialInfo.Timeout == 0 {
		c.DialInfo.Timeout = 10 * time.Second
	}
	if c.DialInfo.Database == "" {
		return fmt.Errorf("%s.dial_info.database is required", configKey)
	}
	return nil
}

func New(c *Config) (*mgo.Session, error) {
	// Attempt to create a MongoDB session which we can re-use when handling
	// multiple requests. We can optionally read in the password from a file or directly from the config.

	// Read in the password (if any)
	if c.PasswordFile != "" {
		passBuf, err := ioutil.ReadFile(c.PasswordFile)
		if err != nil {
			return nil, fmt.Errorf(`Failed to read password file "%s": %s`, c.PasswordFile, err)
		}
		c.DialInfo.Password = strings.TrimSpace(string(passBuf))
	}

	if c.EnableTLS {
		c.DialInfo.DialServer = func(addr *mgo.ServerAddr) (net.Conn, error) {
			return tls.Dial("tcp", addr.String(), &tls.Config{})
		}
	}

	glog.V(2).Infof("Creating MongoDB session (operation timeout %s)", c.DialInfo.Timeout)

	session, err := mgo.DialWithInfo(&c.DialInfo)
	if err != nil {
		return nil, err
	}

	return session, nil
}
