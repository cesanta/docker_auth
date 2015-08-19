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
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/brandnetworks/docker_auth/auth_server/authn"
	mapset "github.com/deckarep/golang-set"
	"github.com/docker/libtrust"
	yaml "gopkg.in/yaml.v2"
)

type Config struct {
	Server     ServerConfig                   `yaml:"server"`
	Token      TokenConfig                    `yaml:"token"`
	Users      map[string]*authn.Requirements `yaml:"users,omitempty"`
	GoogleAuth *authn.GoogleAuthConfig        `yaml:"google_auth,omitempty"`
	Ldap       *authn.LdapAuthConfig        `yaml:"ldap,omitempty"`
	ACL        []*ACLEntry                    `yaml:"acl"`
}

type ServerConfig struct {
	ListenAddress string `yaml:"addr,omitempty"`
	CertFile      string `yaml:"certificate,omitempty"`
	KeyFile       string `yaml:"key,omitempty"`

	publicKey  libtrust.PublicKey
	privateKey libtrust.PrivateKey
}

type TokenConfig struct {
	Issuer     string `yaml:"issuer,omitempty"`
	CertFile   string `yaml:"certificate,omitempty"`
	KeyFile    string `yaml:"key,omitempty"`
	Expiration int64  `yaml:"expiration,omitempty"`

	publicKey  libtrust.PublicKey
	privateKey libtrust.PrivateKey
}

type ACLEntry struct {
	Match   *MatchConditions `yaml:"match"`
	Actions *[]string        `yaml:"actions,flow"`
}

type MatchConditions struct {
	Account *string `yaml:"account,omitempty" json:"account,omitempty"`
	Type    *string `yaml:"type,omitempty" json:"type,omitempty"`
	Name    *string `yaml:"name,omitempty" json:"name,omitempty"`
}

type aclEntryJSON *ACLEntry

func (e ACLEntry) String() string {
	b, _ := json.Marshal(e)
	return string(b)
}

func matchString(pp *string, s string) bool {
	if pp == nil {
		return true
	}
	p := *pp
	var matched bool
	var err error
	if len(p) > 2 && p[0] == '/' && p[len(p)-1] == '/' {
		matched, err = regexp.Match(p[1:len(p)-1], []byte(s))
	} else {
		matched, err = path.Match(p, s)
	}
	return err == nil && matched
}

func (e *ACLEntry) Matches(rq *AuthRequest) bool {
	if matchString(e.Match.Account, rq.Account) &&
		matchString(e.Match.Type, rq.Type) &&
		matchString(e.Match.Name, rq.Name) {
		return true
	}
	return false
}

func makeSet(ss []string) mapset.Set {
	set := mapset.NewSet()
	for _, s := range ss {
		set.Add(s)
	}
	return set
}

func (e *ACLEntry) Check(rq *AuthRequest) error {
	if len(*e.Actions) == 1 && (*e.Actions)[0] == "*" {
		return nil
	}
	requested := makeSet(rq.Actions)
	allowed := makeSet(*e.Actions)
	missing := requested.Difference(allowed)
	if missing.Cardinality() == 0 {
		return nil
	}
	missingStr := []string{}
	for e := range missing.Iter() {
		missingStr = append(missingStr, fmt.Sprintf("%q", e.(string)))
	}
	sort.Strings(missingStr)
	return fmt.Errorf("%s not allowed", strings.Join(missingStr, ","))
}

func validate(c *Config) error {
	if c.Server.ListenAddress == "" {
		return errors.New("server.addr is required")
	}
	if c.Server.CertFile == "" || c.Server.KeyFile == "" {
		return errors.New("server certificate and key are required")
	}

	if c.Token.Issuer == "" {
		return errors.New("token.issuer is required")
	}
	if c.Token.Expiration <= 0 {
		return fmt.Errorf("expiration must be positive, got %d", c.Token.Expiration)
	}

	if c.Users == nil && c.GoogleAuth == nil {
		return errors.New("no auth methods are configured, this is probably a mistake. Use an empty user map if you really want to deny everyone.")
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
	if c.ACL == nil {
		return errors.New("ACL is empty, this is probably a mistake. Use an empty list if you really want to deny all actions.")
	}
	return nil
}

func loadCertAndKey(certFile, keyFile string) (pk libtrust.PublicKey, prk libtrust.PrivateKey, err error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return
	}
	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return
	}
	pk, err = libtrust.FromCryptoPublicKey(x509Cert.PublicKey)
	if err != nil {
		return
	}
	prk, err = libtrust.FromCryptoPrivateKey(cert.PrivateKey)
	return
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
	c.Server.publicKey, c.Server.privateKey, err = loadCertAndKey(c.Server.CertFile, c.Server.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load server cert and key: %s", err)
	}
	if c.Token.CertFile != "" && c.Token.KeyFile != "" {
		c.Token.publicKey, c.Token.privateKey, err = loadCertAndKey(c.Token.CertFile, c.Token.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load token cert and key: %s", err)
		}
	} else {
		c.Token.publicKey, c.Token.privateKey = c.Server.publicKey, c.Server.privateKey
	}
	return c, nil
}
