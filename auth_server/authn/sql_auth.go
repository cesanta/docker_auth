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
	"fmt"
	"os"
	"encoding/json"

	"github.com/cesanta/glog"
	"golang.org/x/crypto/bcrypt"
	"database/sql"
	_ "github.com/go-sql-driver/mysql"
	_ "github.com/lib/pq"
)

type SQLAuth struct {
	db      *sql.DB
	config  *SQLAuthConfig
}

type SQLConfig struct {
	Driver          string  `yaml:"driver,omitempty"`
	DataSourceName  string  `yaml:"data_source_name,omitempty"`
}

type SQLAuthConfig struct {
	SQLConfig       *SQLConfig  `yaml:"connection,omitempty"`
	Table           string      `yaml:"table,omitempty"`
	UserColumn      string      `yaml:"user_column,omitempty"`
	PasswordColumn  string      `yaml:"password_column,omitempty"`
	LabelsColumn    string      `yaml:"labels_column,omitempty"`
}

func (c *SQLConfig) Validate(configKey string) error {
	dataSourceName := os.ExpandEnv(c.DataSourceName)
	_, err := sql.Open(c.Driver, dataSourceName) 
	if err != nil {
		return fmt.Errorf("%s.connection incorrect", configKey)
	}

	return nil
}

func (c *SQLAuthConfig) Validate(configKey string) error {
	if err := c.SQLConfig.Validate(configKey); err != nil {
		return err
	}

	if c.Table == "" {
		return fmt.Errorf("%s.table is required", configKey)
	}
	if c.UserColumn == "" {
		return fmt.Errorf("%s.user_column is required", configKey)
	}
	if c.PasswordColumn == "" {
		return fmt.Errorf("%s.password_column is required", configKey)
	}
	if c.LabelsColumn == "" {
		return fmt.Errorf("%s.labels_column is required", configKey)
	}
	return nil
}

func NewSQLAuth(c *SQLAuthConfig) (*SQLAuth, error) {
	db, err := sql.Open(c.SQLConfig.Driver, os.ExpandEnv(c.SQLConfig.DataSourceName)); 
	if err != nil {
		return nil, err
	}

	query := fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (
		%s text PRIMARY KEY,
		%s text NOT NULL,
		%s json
	)`, c.Table, c.UserColumn, c.PasswordColumn, c.LabelsColumn)

	_, err = db.Exec(query)

	if err != nil {
		return nil, err
	}

	return &SQLAuth{
		config: c,
		db: db,
	}, nil
}

func (sqlauth *SQLAuth) Authenticate(account string, password PasswordString) (bool, Labels, error) {
	glog.V(2).Infof("Checking user %s against SQL Users. DB: %s, table:%s",
		account,
		sqlauth.config.SQLConfig.Driver,
		sqlauth.config.Table)

	// Find user in database
	var dbUsername string
	var dbPassword string
	var dbLabels []byte
	var labels Labels
	query := fmt.Sprintf("SELECT %s, %s, %s FROM %s WHERE username = $1", 
		sqlauth.config.UserColumn,
		sqlauth.config.PasswordColumn,
		sqlauth.config.LabelsColumn,
		sqlauth.config.Table)
	if err := sqlauth.db.QueryRow(query, account).Scan(&dbUsername, &dbPassword, &dbLabels); err != nil {
		if err == sql.ErrNoRows {
			return false, nil, NoMatch
		} else {
			return false, nil, err
		}
	}

	if dbLabels != nil {
		if err := json.Unmarshal(dbLabels, &labels); err != nil {
			return false, nil, err
		}
	}

	// Check password
	if dbPassword != "" {
		if bcrypt.CompareHashAndPassword([]byte(dbPassword), []byte(password)) != nil {
			return false, nil, WrongPass
		}
	}

	// Auth success
	return true, labels, nil
}

func (sqla *SQLAuth) Stop() {
	if sqla.db != nil {
		sqla.db.Close()
	}
}

func (sqla *SQLAuth) Name() string {
	return sqla.config.SQLConfig.Driver
}
