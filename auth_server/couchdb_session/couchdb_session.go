package couchdb_session

import (
	"fmt"
	"time"

	"github.com/golang/glog"
	"github.com/zemirco/couchdb"
)

// Config stores how to connect to the CouchDB server
type Config struct {
	DialInfo DialInfo `yaml:",inline"`
}

// DialInfo holds options for establishing a session with a CouchDB cluster.
type DialInfo struct {
	// Addrs holds the addresses for the seed servers.
	// example: [127.0.0.1:5984, db.yourhost.com]
	Addrs []string

	// Timeout is the amount of time to wait for a server to respond when
	// first connecting and on follow up operations in the session. If
	// timeout is zero, the call may block forever waiting for a connection
	// to be established.
	Timeout time.Duration

	// Database is the default database name used during the initial authentication
	Database string

	// Name of Design document in that databse.
	// http://guide.couchdb.org/draft/design.html
	Design string

	// Name of View.
	// http://guide.couchdb.org/draft/views.html
	View string
	// Username and Password inform the credentials for the initial authentication
	// done on the database.
	Username string
	Password string
}

// Validate ensures the most common fields inside the CouchDB portion of
// a Config are set correctly as well as other fields inside the Config itself.
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
	if c.DialInfo.Design == "" {
		return fmt.Errorf("%s.dial_info.design is required", configKey)
	}
	if c.DialInfo.View == "" {
		return fmt.Errorf("%s.dial_info.view is required", configKey)
	}
	return nil
}

// New attempts to create a CouchDB client which we can re-use when handling
// multiple requests.
func New(c *Config) (client *couchdb.Client, err error) {
	// Multiple addresses is supported, first available CouchDB will be choosen
	// addrs: ["192.168.10.187:5984","your.couchdb.io"]
	for _, addr := range c.DialInfo.Addrs {
		glog.V(2).Infof("Connecting to CouchDB %s (with timeout %s)...", addr, c.DialInfo.Timeout)

		url := fmt.Sprintf("http://%s/", addr)
		if len(c.DialInfo.Username) > 0 && len(c.DialInfo.Password) > 0 {
			client, err = couchdb.NewAuthClient(c.DialInfo.Username, c.DialInfo.Password, url)
		} else {
			client, err = couchdb.NewClient(url)
		}
		if err != nil {
			// try next addr
			glog.V(2).Infof("Create client error: %v\n", err)
			continue
		} else if client != nil {
			glog.V(2).Infof("Client created to CouchDB %s", addr)
		}

		// Ping
		glog.V(2).Infof("Fetch CouchDB %s info ...", addr)
		info, errInfo := client.Info()
		if err != nil {
			// try next addr
			glog.V(2).Infof("Fetch CouchDB info error: %v\n", errInfo)
			continue
		} else if info != nil {
			glog.V(2).Infof("Fetched CouchDB info %v", info)
			return client, nil
		}
	}
	glog.V(2).Infoln("All CouchDB addresses have been tried, none of them work")
	return
}
