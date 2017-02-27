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
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"strings"

	"github.com/go-ldap/ldap"
	"github.com/golang/glog"
)

type LDAPAuthConfig struct {
	Addr                  string `yaml:"addr,omitempty"`
	TLS                   string `yaml:"tls,omitempty"`
	InsecureTLSSkipVerify bool   `yaml:"insecure_tls_skip_verify,omitempty"`
	Base                  string `yaml:"base,omitempty"`
	Filter                string `yaml:"filter,omitempty"`
	BindDN                string `yaml:"bind_dn,omitempty"`
	BindPasswordFile      string `yaml:"bind_password_file,omitempty"`
	GroupBaseDN           string `yaml:"group_base_dn,omitempty"`
	GroupFilter           string `yaml:"group_filter,omitempty"`
}

type LDAPAuth struct {
	config *LDAPAuthConfig
}

func NewLDAPAuth(c *LDAPAuthConfig) (*LDAPAuth, error) {
	if c.TLS == "" && strings.HasSuffix(c.Addr, ":636") {
		c.TLS = "always"
	}
	return &LDAPAuth{
		config: c,
	}, nil
}

//How to authenticate user, please refer to https://github.com/go-ldap/ldap/blob/master/example_test.go#L166
func (la *LDAPAuth) Authenticate(account string, password PasswordString) (bool, Labels, error) {
	if account == "" || password == "" {
		return false, nil, NoMatch
	}
	l, err := la.ldapConnection()
	if err != nil {
		return false, nil, err
	}
	defer l.Close()

	// First bind with a read only user, to prevent the following search won't perform any write action
	if bindErr := la.bindReadOnlyUser(l); bindErr != nil {
		return false, nil, bindErr
	}

	account = la.escapeAccountInput(account)

	filter := la.getFilter(account)

	// dnAndGroupAttr := []string{"DN"} // example of no groups mapping attribute
	groupAttribute := "memberOf"
	dnAndGroupAttr := []string{"DN", groupAttribute}

	entryAttrMap, uSearchErr := la.ldapSearch(l, &la.config.Base, &filter, &dnAndGroupAttr)
	if uSearchErr != nil {
		return false, nil, uSearchErr
	}
	if len(entryAttrMap) < 1 || entryAttrMap["DN"] == nil || len(entryAttrMap["DN"]) != 1 {
		return false, nil, NoMatch // User does not exist
	}

	accountEntryDN := entryAttrMap["DN"][0]
	if accountEntryDN == "" {
		return false, nil, NoMatch // User does not exist
	}
	// Bind as the user to verify their password
	if len(accountEntryDN) > 0 {
		err := l.Bind(accountEntryDN, string(password))
		if err != nil {
			if ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
				return false, nil, nil
			}
			return false, nil, err
		}
	}
	// Rebind as the read only user for any futher queries
	if bindErr := la.bindReadOnlyUser(l); bindErr != nil {
		return false, nil, bindErr
	}

	// Extract group names from the attribute values
	if entryAttrMap[groupAttribute] != nil {
		rawGroups := entryAttrMap[groupAttribute]
		labels := make(map[string][]string)
		var groups []string
		for _, value := range rawGroups {
			cn := la.getCNFromDN(value)
			groups = append(groups, cn)
		}
		labels["groups"] = groups

		return true, labels, nil
	}

	return true, nil, nil
}

func (la *LDAPAuth) bindReadOnlyUser(l *ldap.Conn) error {
	if la.config.BindDN != "" {
		password, err := ioutil.ReadFile(la.config.BindPasswordFile)
		if err != nil {
			return err
		}
		password_str := strings.TrimSpace(string(password))
		glog.V(2).Infof("Bind read-only user (DN = %s)", la.config.BindDN)
		err = l.Bind(la.config.BindDN, password_str)
		if err != nil {
			return err
		}
	}
	return nil
}

//To prevent LDAP injection, some characters must be escaped for searching
//e.g. char '\' will be replaced by hex '\5c'
//Filter meta chars are choosen based on filter complier code
//https://github.com/go-ldap/ldap/blob/master/filter.go#L159
func (la *LDAPAuth) escapeAccountInput(account string) string {
	r := strings.NewReplacer(
		`\`, `\5c`,
		`(`, `\28`,
		`)`, `\29`,
		`!`, `\21`,
		`*`, `\2a`,
		`&`, `\26`,
		`|`, `\7c`,
		`=`, `\3d`,
		`>`, `\3e`,
		`<`, `\3c`,
		`~`, `\7e`,
	)
	return r.Replace(account)
}

func (la *LDAPAuth) ldapConnection() (*ldap.Conn, error) {
	var l *ldap.Conn
	var err error

	tlsConfig := &tls.Config{InsecureSkipVerify: true}
	if !la.config.InsecureTLSSkipVerify {
		addr := strings.Split(la.config.Addr, ":")
		tlsConfig = &tls.Config{InsecureSkipVerify: false, ServerName: addr[0]}
	}

	if la.config.TLS == "" || la.config.TLS == "none" || la.config.TLS == "starttls" {
		glog.V(2).Infof("Dial: starting...%s", la.config.Addr)
		l, err = ldap.Dial("tcp", fmt.Sprintf("%s", la.config.Addr))
		if err == nil && la.config.TLS == "starttls" {
			glog.V(2).Infof("StartTLS...")
			if tlserr := l.StartTLS(tlsConfig); tlserr != nil {
				return nil, tlserr
			}
		}
	} else if la.config.TLS == "always" {
		glog.V(2).Infof("DialTLS: starting...%s", la.config.Addr)
		l, err = ldap.DialTLS("tcp", fmt.Sprintf("%s", la.config.Addr), tlsConfig)
	}
	if err != nil {
		return nil, err
	}
	return l, nil
}

func (la *LDAPAuth) getFilter(account string) string {
	filter := strings.NewReplacer("${account}", account).Replace(la.config.Filter)
	glog.V(2).Infof("search filter is %s", filter)
	return filter
}

//ldap search and return required attributes' value from searched entries
//default return entry's DN value if you leave attrs array empty
func (la *LDAPAuth) ldapSearch(l *ldap.Conn, baseDN *string, filter *string, attrs *[]string) (map[string][]string, error) {
	if l == nil {
		return nil, fmt.Errorf("No ldap connection!")
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
		return nil, err
	}

	if len(sr.Entries) == 0 {
		return nil, nil // User does not exist
	} else if len(sr.Entries) > 1 {
		return nil, fmt.Errorf("Too many entries returned.")
	}

	result := make(map[string][]string)
	for _, entry := range sr.Entries {

		if len(*attrs) == 0 {
			glog.V(2).Infof("Entry DN = %s", entry.DN)
			result["DN"] = []string{entry.DN}
		} else {
			for _, attr := range *attrs {
				var values []string
				if attr == "DN" {
					// DN is excluded from attributes
					values = []string{entry.DN}
				} else {
					values = entry.GetAttributeValues(attr)
				}
				valuesString := strings.Join(values, "\n")
				glog.V(2).Infof("Entry %s = %s", attr, valuesString)
				result[attr] = values
			}
		}
	}

	return result, nil
}

func (la *LDAPAuth) getCNFromDN(dn string) string {
	parsedDN, err := ldap.ParseDN(dn)
	if err != nil || len(parsedDN.RDNs) > 0 {
		for _, rdn := range parsedDN.RDNs {
			for _, rdnAttr := range rdn.Attributes {
				if rdnAttr.Type == "CN" {
					return rdnAttr.Value
				}
			}
		}
	}

	// else try using raw DN
	return dn
}

func (la *LDAPAuth) Stop() {
}

func (la *LDAPAuth) Name() string {
	return "LDAP"
}
