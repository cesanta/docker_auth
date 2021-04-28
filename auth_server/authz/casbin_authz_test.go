// Copyright 2021 The casbin Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package authz

import (
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/util"
	"github.com/cesanta/docker_auth/auth_server/api"
)

func requestToString(ai api.AuthRequestInfo) string {
	return fmt.Sprintf("{%s | %s | %s | %s | %s | %s | %s}", ai.Account, ai.Type, ai.Name, ai.Service, ai.IP.String(), strings.Join(ai.Actions, ","), labelsToString(ai.Labels))
}

func testRequest(t *testing.T, a api.Authorizer, account string, typ string, name string, service string, ip string, labels map[string][]string, actions []string, res []string) {
	ai := api.AuthRequestInfo{
		Account: account,
		Type:    typ,
		Name:    name,
		Service: service,
		IP:      net.ParseIP(ip),
		Actions: actions,
		Labels:  labels}

	actions, err := a.Authorize(&ai)
	if err != nil {
		t.Error("Casbin authorizer fails to authorize.")
		return
	}

	if !util.ArrayEquals(actions, res) {
		t.Errorf("%s: %s, supposed to be %s", requestToString(ai), actions, res)
	}
}

func TestLabelsToString(t *testing.T) {
	label := map[string][]string{"a": {"b", "c"}, "d": {"e"}}
	labelStr := labelsToString(label)
	if labelStr != "{\"a\":[\"b\",\"c\"],\"d\":[\"e\"]}" {
		t.Errorf("%s: %s, supposed to be %s", label, labelStr, "{\"a\":[\"b\",\"c\"],\"d\":[\"e\"]}")
	}

	labelNew := stringToLabels(labelStr)
	if !labelMatch(label, labelNew) {
		t.Errorf("%s: %s, supposed to be %s", label, labelNew, label)
	}
}

func testLabels(t *testing.T, lbl1 api.Labels, lbl2 api.Labels, res bool) {
	myRes := labelMatch(lbl1, lbl2)
	if myRes != res {
		t.Errorf("%s matches %s: %v, supposed to be %v", lbl1, lbl2, myRes, res)
	}
}

func TestLabels(t *testing.T) {
	testLabels(t, map[string][]string{"a": {"b"}}, map[string][]string{"a": {"b"}}, true)
	testLabels(t, map[string][]string{"a": {"b"}}, map[string][]string{"a": {"c"}}, false)
	testLabels(t, map[string][]string{"a": {"b", "c"}}, map[string][]string{"a": {"b"}}, true)
	testLabels(t, map[string][]string{"a": {"b"}}, map[string][]string{"a": {"b", "c"}}, false)
	testLabels(t, map[string][]string{"a": {"b", "c"}, "d": {"e"}}, map[string][]string{"a": {"b", "c"}}, true)
	testLabels(t, map[string][]string{"a": {"b"}}, map[string][]string{"a": {"b", "c"}, "d": {"f"}}, false)
}

func TestPermissions(t *testing.T) {
	e, err := casbin.NewEnforcer("../../examples/casbin_authz_model.conf",
		"../../examples/casbin_authz_policy.csv")
	if err != nil {
		t.Errorf("Enforcer fails to create: %v", err)
	}
	a, err := NewCasbinAuthorizer(e)
	if err != nil {
		t.Error("Casbin authorizer fails to create.")
	}

	// alice is a user.
	testRequest(t, a, "alice", "book", "book1", "bookstore1", "1.2.3.4", map[string][]string{"a": {"b"}}, []string{"write", "read", "delete"}, []string{"write", "read"})
	testRequest(t, a, "alice", "book", "book1", "bookstore1", "1.2.3.3", map[string][]string{"a": {"b"}}, []string{"write", "read", "delete"}, []string{})
	testRequest(t, a, "alice", "book", "book2", "bookstore2", "1.2.3.4", map[string][]string{"a": {"b"}}, []string{"write", "read", "delete"}, []string{})
	testRequest(t, a, "alice", "pen", "book1", "bookstore1", "1.2.3.4", map[string][]string{"a": {"b"}}, []string{"write", "read", "delete"}, []string{})
	testRequest(t, a, "alice", "book", "book1", "bookstore1", "1.2.3.4", map[string][]string{"a": {"c"}}, []string{"write", "read", "delete"}, []string{})
	testRequest(t, a, "alice", "book", "book1", "bookstore1", "1.2.3.4", map[string][]string{"a": {"b", "c"}}, []string{"write", "read", "delete"}, []string{"write", "read"})

	// bob is a member of role1, so bob will have all permissions of role1.
	testRequest(t, a, "bob", "book", "book2", "bookstore1", "192.168.1.123", map[string][]string{"a": {"b", "c"}, "d": {"e"}}, []string{"write", "read", "delete"}, []string{"read"})
	testRequest(t, a, "bob", "book", "book2", "bookstore1", "192.168.1.123", map[string][]string{"a": {"b"}, "d": {"e"}}, []string{"write", "read", "delete"}, []string{})
	testRequest(t, a, "bob", "book", "book2", "bookstore1", "192.168.0.123", map[string][]string{"a": {"b", "c"}, "d": {"e"}}, []string{"write", "read", "delete"}, []string{})
	testRequest(t, a, "bob", "book", "book2", "bookstore1", "192.168.1.123", map[string][]string{"a": {"b", "c"}}, []string{"write", "read", "delete"}, []string{"read"})
	testRequest(t, a, "bob", "book", "book2", "restaurant", "192.168.1.123", map[string][]string{"a": {"b", "c"}, "d": {"e"}}, []string{"write", "read", "delete"}, []string{})

	// admin is the administrator, so he can do anything without restriction.
	testRequest(t, a, "admin", "book", "book1", "bookstore1", "1.2.3.4", map[string][]string{"a": {"b"}}, []string{"write", "read", "delete"}, []string{"write", "read", "delete"})
	testRequest(t, a, "admin", "book", "book1", "bookstore1", "1.2.3.3", map[string][]string{"a": {"b"}}, []string{"write", "read", "delete"}, []string{"write", "read", "delete"})
	testRequest(t, a, "admin", "book", "book2", "bookstore2", "1.2.3.4", map[string][]string{"a": {"b"}}, []string{"write", "read", "delete"}, []string{"write", "read", "delete"})
	testRequest(t, a, "admin", "pen", "book1", "bookstore1", "1.2.3.4", map[string][]string{"a": {"b"}}, []string{"write", "read", "delete"}, []string{"write", "read", "delete"})
	testRequest(t, a, "admin", "book", "book1", "bookstore1", "1.2.3.4", map[string][]string{"a": {"c"}}, []string{"write", "read", "delete"}, []string{"write", "read", "delete"})
	testRequest(t, a, "admin", "book", "book1", "bookstore1", "1.2.3.4", map[string][]string{"a": {"b", "c"}}, []string{"write", "read", "delete"}, []string{"write", "read", "delete"})
}
