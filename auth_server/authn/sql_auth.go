/*
   Copyright 2015 Cesanta Software Ltd.

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

package authn

import (
	"database/sql"
	"fmt"
	"strings"

	_ "github.com/go-sql-driver/mysql"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"

	"github.com/cesanta/docker_auth/auth_server/api"
	"github.com/cesanta/glog"
)

// SQLAuthConfig is the configuration for the SQLAuth plugin.
//
// Note: Table and columns must exist before using this plugin
type SQLAuthConfig struct {
	// Database connection string in URI format.
	//
	// Database driver will be automatically selected from the scheme of
	// the DSN connection string (e.g., mysql:// or postgresql://)
	//
	// See https://www.postgresql.org/docs/current/libpq-connect.html#LIBPQ-CONNSTRING
	DSN string `yaml:"dsn,omitempty"`

	// The name of the table that will be used for data lookups
	Table string `yaml:"table,omitempty"`

	// The column that contains the username
	UserColumn string `yaml:"user_column,omitempty"`

	// The column that contains the bcrypt hash of the password
	PasswordColumn string `yaml:"password_column,omitempty"`
}

// SQLAuth is an authentication plugin for SQL data sources
type SQLAuth struct {
	config      *SQLAuthConfig
	db          *sql.DB
	placeholder string
}

// NewSQLAuth returns a new SQL Authenticator instance
func NewSQLAuth(c *SQLAuthConfig) (*SQLAuth, error) {
	glog.V(2).Info("Creating SQLAuth authenticator")

	driver, dsn := parseDSN(c.DSN)

	db, err := sql.Open(driver, dsn)
	if err != nil {
		return nil, fmt.Errorf("sqlauth: open: %s", err)
	}

	// validate DSN manually, because Open doesn't open a connection
	err = db.Ping()
	if err != nil {
		return nil, fmt.Errorf("sqlauth: ping: %s", err)
	}

	// pq does not support the standard placeholder
	var placeholder = "?"
	if driver == "postgres" {
		placeholder = "$1"
	}

	sa := &SQLAuth{
		config:      c,
		db:          db,
		placeholder: placeholder,
	}

	return sa, nil
}

// Authenticate performs authentication against the SQL data source
func (sa *SQLAuth) Authenticate(user string, password api.PasswordString) (bool, api.Labels, error) {
	glog.V(2).Infof("Authenticating user %q against SQL datasource %q", user, sa.config.Table)

	query := fmt.Sprintf(
		"SELECT %s FROM %s WHERE %s = %s",
		sa.config.PasswordColumn,
		sa.config.Table,
		sa.config.UserColumn,
		sa.placeholder,
	)

	var dbpassword string
	if err := sa.db.QueryRow(query, user).Scan(&dbpassword); err != nil {
		if err == sql.ErrNoRows {
			return false, nil, api.NoMatch
		}
		return false, nil, fmt.Errorf("sqlauth: query failed: %s", err)
	}

	if bcrypt.CompareHashAndPassword([]byte(dbpassword), []byte(password)) != nil {
		return false, nil, api.WrongPass
	}

	return true, nil, nil
}

// Stop closes underlying SQL connection
func (sa *SQLAuth) Stop() {
	glog.V(2).Info("Stopping SQLAuth authenticator")
	sa.db.Close()
}

// Name returns a human readable name of the authenticator
func (sa *SQLAuth) Name() string {
	return "SQL"
}

// Validate ensures plugin configuration has correct values
func (sac *SQLAuthConfig) Validate() error {
	if sac.DSN == "" {
		return fmt.Errorf("database connection string cannot be empty")
	}
	if !(strings.HasPrefix(sac.DSN, "postgres") || strings.HasPrefix(sac.DSN, "mysql")) {
		return fmt.Errorf("database driver must be specified")
	}
	if sac.Table == "" {
		return fmt.Errorf("table name cannot be empty")
	}
	if sac.UserColumn == "" {
		return fmt.Errorf("user_column cannot be empty")
	}
	if sac.PasswordColumn == "" {
		return fmt.Errorf("password_column cannot be empty")
	}
	return nil
}

// parseDSN returns the SQL driver name and the connection string
func parseDSN(dsn string) (string, string) {
	if strings.HasPrefix(dsn, "postgres") {
		return "postgres", dsn
	}
	return "mysql", strings.TrimPrefix(dsn, "mysql://")
}
