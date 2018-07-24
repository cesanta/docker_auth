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

package server

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"time"

	"github.com/cesanta/docker_auth/auth_server/authn"
	"github.com/cesanta/docker_auth/auth_server/authz"
	. "github.com/cesanta/docker_auth/auth_server/common"
	yaml "gopkg.in/yaml.v2"
)

type Config struct {
	Server      ServerConfig                   `yaml:"server"`
	Token       TokenConfig                    `yaml:"token"`
	Users       map[string]*authn.Requirements `yaml:"users,omitempty"`
	GoogleAuth  *authn.GoogleAuthConfig        `yaml:"google_auth,omitempty"`
	GitHubAuth  *authn.GitHubAuthConfig        `yaml:"github_auth,omitempty"`
	LDAPAuth    *authn.LDAPAuthConfig          `yaml:"ldap_auth,omitempty"`
	MongoAuth   *authn.MongoAuthConfig         `yaml:"mongo_auth,omitempty"`
	ExtAuth     *authn.ExtAuthConfig           `yaml:"ext_auth,omitempty"`
	ACL         authz.ACL                      `yaml:"acl,omitempty"`
	ACLMongo    *authz.ACLMongoConfig          `yaml:"acl_mongo,omitempty"`
	ExtAuthz    *authz.ExtAuthzConfig          `yaml:"ext_authz,omitempty"`
	LetsEncrypt LetsEncryptConfig              `yaml:"letsencrypt,omitempty"`
}

type LetsEncryptConfig struct {
	Host     string `yaml:"host,omitempty"`
	Email    string `yaml:"email,omitempty"`
	CacheDir string `yaml:"cache_dir,omitempty"`
}

func validate(c *Config) error {
	if c.Server.ListenAddress == "" {
		return errors.New("server.addr is required")
	}
	if c.Server.PathPrefix != "" && !strings.HasPrefix(c.Server.PathPrefix, "/") {
		return errors.New("server.path_prefix must be an absolute path")
	}

	if c.Token.Issuer == "" {
		return errors.New("token.issuer is required")
	}
	if c.Token.Expiration <= 0 {
		return fmt.Errorf("expiration must be positive, got %d", c.Token.Expiration)
	}
	if c.Users == nil && c.ExtAuth == nil && c.GoogleAuth == nil && c.GitHubAuth == nil && c.LDAPAuth == nil && c.MongoAuth == nil {
		return errors.New("no auth methods are configured, this is probably a mistake. Use an empty user map if you really want to deny everyone.")
	}
	if c.MongoAuth != nil {
		if err := c.MongoAuth.Validate("mongo_auth"); err != nil {
			return err
		}
	}
	if gac := c.GoogleAuth; gac != nil {
		if gac.ClientSecretFile != "" {
			contents, err := ioutil.ReadFile(gac.ClientSecretFile)
			if err != nil {
				return fmt.Errorf("could not read %s: %s", gac.ClientSecretFile, err)
			}
			gac.ClientSecret = strings.TrimSpace(string(contents))
		}
		if gac.ClientId == "" || gac.ClientSecret == "" || gac.TokenDB == "" {
			return errors.New("google_auth.{client_id,client_secret,token_db} are required.")
		}
		if gac.HTTPTimeout <= 0 {
			gac.HTTPTimeout = 10
		}
	}
	if ghac := c.GitHubAuth; ghac != nil {
		if ghac.ClientSecretFile != "" {
			contents, err := ioutil.ReadFile(ghac.ClientSecretFile)
			if err != nil {
				return fmt.Errorf("could not read %s: %s", ghac.ClientSecretFile, err)
			}
			ghac.ClientSecret = strings.TrimSpace(string(contents))
		}
		if ghac.ClientId == "" || ghac.ClientSecret == "" || (ghac.TokenDB == "" && ghac.GCSTokenDB == nil) {
			return errors.New("github_auth.{client_id,client_secret,token_db} are required")
		}

		if ghac.ClientId == "" || ghac.ClientSecret == "" || (ghac.GCSTokenDB != nil && (ghac.GCSTokenDB.Bucket == "" || ghac.GCSTokenDB.ClientSecretFile == "")) {
			return errors.New("github_auth.{client_id,client_secret,gcs_token_db{bucket,client_secret_file}} are required")
		}
		if ghac.HTTPTimeout <= 0 {
			ghac.HTTPTimeout = time.Duration(10 * time.Second)
		}
		if ghac.RevalidateAfter == 0 {
			// Token expires after 1 hour by default
			ghac.RevalidateAfter = time.Duration(1 * time.Hour)
		}
	}
	if c.ExtAuth != nil {
		if err := c.ExtAuth.Validate(); err != nil {
			return fmt.Errorf("bad ext_auth config: %s", err)
		}
	}
	if c.ACL == nil && c.ACLMongo == nil && c.ExtAuthz == nil {
		return errors.New("ACL is empty, this is probably a mistake. Use an empty list if you really want to deny all actions")
	}

	if c.ACL != nil {
		if err := authz.ValidateACL(c.ACL); err != nil {
			return fmt.Errorf("invalid ACL: %s", err)
		}
	}
	if c.ACLMongo != nil {
		if err := c.ACLMongo.Validate("acl_mongo"); err != nil {
			return err
		}
	}
	if c.ExtAuthz != nil {
		if err := c.ExtAuthz.Validate(); err != nil {
			return err
		}
	}
	return nil
}

func LoadConfig(fileName string) (*Config, error) {
	contents, err := ioutil.ReadFile(fileName)
	if err != nil {
		return nil, fmt.Errorf("could not read %s: %s", fileName, err)
	}
	c := &Config{}
	if err = yaml.Unmarshal(contents, c); err != nil {
		return nil, fmt.Errorf("could not parse config: %s", err)
	}
	if err = validate(c); err != nil {
		return nil, fmt.Errorf("invalid config: %s", err)
	}
	serverConfigured := false
	if c.Server.CertFile != "" || c.Server.KeyFile != "" {
		// Check for partial configuration.
		if c.Server.CertFile == "" || c.Server.KeyFile == "" {
			return nil, fmt.Errorf("failed to load server cert and key: both were not provided")
		}
		c.Server.PublicKey, c.Server.PrivateKey, err = LoadCertAndKey(c.Server.CertFile, c.Server.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load server cert and key: %s", err)
		}
		serverConfigured = true
	}
	tokenConfigured := false
	if c.Token.CertFile != "" || c.Token.KeyFile != "" {
		// Check for partial configuration.
		if c.Token.CertFile == "" || c.Token.KeyFile == "" {
			return nil, fmt.Errorf("failed to load token cert and key: both were not provided")
		}
		c.Token.PublicKey, c.Token.PrivateKey, err = LoadCertAndKey(c.Token.CertFile, c.Token.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load token cert and key: %s", err)
		}
		tokenConfigured = true
	}

	if serverConfigured && !tokenConfigured {
		c.Token.PublicKey, c.Token.PrivateKey = c.Server.PublicKey, c.Server.PrivateKey
		tokenConfigured = true
	}

	if !tokenConfigured {
		return nil, fmt.Errorf("failed to load token cert and key: none provided")
	}

	if !serverConfigured && c.LetsEncrypt.Email != "" {
		if c.LetsEncrypt.CacheDir == "" {
			return nil, fmt.Errorf("server.letsencrypt.cache_dir is required")
		}
		// We require that LetsEncrypt is an existing directory, because we really don't want it
		// to be misconfigured and obtained certificates to be lost.
		fi, err := os.Stat(c.LetsEncrypt.CacheDir)
		if err != nil || !fi.IsDir() {
			return nil, fmt.Errorf("server.letsencrypt.cache_dir (%s) does not exist or is not a directory", c.LetsEncrypt.CacheDir)
		}
	}

	return c, nil
}
