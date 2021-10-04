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
	"context"
	"fmt"
	"io/ioutil"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/cesanta/glog"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type ServerAddr struct {
	// contains filtered or unexported fields
}

type DialInfo struct {
	// Addrs holds the addresses for the seed servers.
	Addrs []string

	// Direct informs whether to establish connections only with the
	// specified seed servers, or to obtain information for the whole
	// cluster and establish connections with further servers too.
	Direct bool

	// Timeout is the amount of time to wait for a server to respond when
	// first connecting and on follow up operations in the session. If
	// timeout is zero, the call may block forever waiting for a connection
	// to be established.
	Timeout time.Duration

	// FailFast will cause connection and query attempts to fail faster when
	// the server is unavailable, instead of retrying until the configured
	// timeout period. Note that an unavailable server may silently drop
	// packets instead of rejecting them, in which case it's impossible to
	// distinguish it from a slow server, so the timeout stays relevant.
	FailFast bool

	// Database is the default database name used when the Session.DB method
	// is called with an empty name, and is also used during the intial
	// authenticatoin if Source is unset.
	Database string

	// Source is the database used to establish credentials and privileges
	// with a MongoDB server. Defaults to the value of Database, if that is
	// set, or "admin" otherwise.
	Source string

	// Service defines the service name to use when authenticating with the GSSAPI
	// mechanism. Defaults to "mongodb".
	Service string

	// Mechanism defines the protocol for credential negotiation.
	// Defaults to "MONGODB-CR".
	Mechanism string

	// Username and Password inform the credentials for the initial authentication
	// done on the database defined by the Source field. See Session.Login.
	Username string
	Password string

	// DialServer optionally specifies the dial function for establishing
	// connections with the MongoDB servers.
	DialServer func(addr *ServerAddr) (net.Conn, error)

	// WARNING: This field is obsolete. See DialServer above.
	Dial func(addr net.Addr) (net.Conn, error)
}

// Config stores how to connect to the MongoDB server and an optional password file
type Config struct {
	DialInfo DialInfo `yaml:",inline"`

	PasswordFile string `yaml:"password_file,omitempty"`
	EnableTLS    bool   `yaml:"enable_tls,omitempty"`
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

var retClient *mongo.Client = nil

func New(c *Config) (*mongo.Client, error) {

	if nil == retClient {
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

		glog.V(2).Infof("Creating MongoDB session (operation timeout %s)", c.DialInfo.Timeout)

		session, err := DialWithInfo(&c.DialInfo, c.EnableTLS)
		retClient = session
		if err != nil {
			return nil, err
		}
	}

	return retClient, nil
}

func DialWithInfo(info *DialInfo, enableTLS bool) (*mongo.Client, error) {

	sslActivationString := "ssl=false"
	if enableTLS {
		sslActivationString = "ssl=true"
	}

	// Connect
	username := url.QueryEscape(info.Username)
	password := url.QueryEscape(info.Password)
	uri := "mongodb://" + username + ":" + password + "@" + info.Addrs[0] + "/?authSource=admin&" + sslActivationString

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(uri))
	if err != nil {
		panic(err)
	} else {
		fmt.Println("Successfully connected!")
	}
	return client, err
}
