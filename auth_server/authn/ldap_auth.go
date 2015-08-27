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
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"strings"

	"github.com/go-ldap/ldap"
	"github.com/golang/glog"
)

type LdapAuthConfig struct {
	Domain          string   `yaml:"domain,omitempty"`
	Port            uint16   `yaml:"port,omitempty"`
	StartTLS        bool     `yaml:"startTLS,omitempty"`
	BaseDN          string   `yaml:"baseDN,omitempty"`
	LoginAttributes []string `yaml:"loginAttribute,omitempty"`
	GroupBaseDN     string   `yaml:"groupBaseDN,omitempty"`
	GroupAttribute  string   `yaml:"groupAttribute,omitempty"`
}

type LdapAuth struct {
	config *LdapAuthConfig
}

func NewLdapAuth(c *LdapAuthConfig) (*LdapAuth, error) {
	return &LdapAuth{
		config: c,
	}, nil
}

func (la *LdapAuth) Authenticate(user string, password PasswordString) (bool, error) {
	if user == "" {
		return true, nil
	}
	l, err := la.ldapConnection()
	if err != nil {
		return false, err
	}
	defer l.Close()
	//l.Debug = true
	filter := la.getLoginFilter(user)
	userEntryDN, uSearchErr := la.ldapSearch(l, &la.config.BaseDN, &filter, &[]string{})
	if uSearchErr != nil {
		return false, uSearchErr
	}
	if len(userEntryDN) > 0 {
		err := l.Bind(userEntryDN, string(password))
		if err != nil {
			return false, err
		}
	}
	return true, nil
}

func (la *LdapAuth) Name() string {
	return "Ldap"
}

func (la *LdapAuth) ldapConnection() (*ldap.Conn, error) {
	glog.V(2).Infof("Dial: starting...%s:%d", la.config.Domain, la.config.Port)
	l, err := ldap.Dial("tcp", fmt.Sprintf("%s:%d", la.config.Domain, la.config.Port))
	if err != nil {
		return nil, err
	}
	if la.config.StartTLS {
		glog.V(2).Infof("StartTLS...")
		err = l.StartTLS(&tls.Config{InsecureSkipVerify: true})
		if err != nil {
			return nil, err
		}
	}
	return l, nil
}

//make filter by login attributes, e.g. login in by ['cn', 'uid']
//the filter will be '(|(cn=account)(uid=account))'
func (la *LdapAuth) getLoginFilter(user string) string {
	var buffer bytes.Buffer
	buffer.WriteString("(|")
	for _, attr := range la.config.LoginAttributes {
		buffer.WriteString(fmt.Sprintf("(%s=%s)", attr, user))
	}
	buffer.WriteString(")")
	return fmt.Sprintf(buffer.String())
}

//ldap search and return required attributes' value from searched entries
//default return entry's DN value if you leave attrs array empty
func (la *LdapAuth) ldapSearch(l *ldap.Conn, baseDN *string, filter *string, attrs *[]string) (string, error) {
	if l == nil {
		return "", errors.New("No ldap connection!")
	}
	glog.V(2).Infof("Searching...basedDN:%s, filter:%s", *baseDN, *filter)
	searchRequest := ldap.NewSearchRequest(
		*baseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		*filter,
		*attrs,
		nil)
	sr, err := l.Search(searchRequest)
	if err != nil {
		return "", err
	}

	if len(sr.Entries) != 1 {
		return "", errors.New("Error...Search Result number != 1\n")
	}

	var buffer bytes.Buffer
	for _, entry := range sr.Entries {
		if len(*attrs) == 0 {
			glog.V(2).Infof("Entry DN = %s", entry.DN)
			buffer.WriteString(entry.DN)
		} else {
			for _, attr := range *attrs {
				values := strings.Join(entry.GetAttributeValues(attr), " ")
				glog.V(2).Infof("Entry %s = %s", attr, values)
				buffer.WriteString(values)
			}
		}
	}

	return buffer.String(), nil
}

func (la *LdapAuth) Stop() {
}
