package authz

import (
	"net"
	"testing"

	"github.com/cesanta/docker_auth/auth_server/api"
)

func sp(s string) *string {
	return &s
}

func TestValidation(t *testing.T) {
	cases := []struct {
		mc MatchConditions
		ok bool
	}{
		// Valid stuff
		{MatchConditions{}, true},
		{MatchConditions{Account: sp("foo")}, true},
		{MatchConditions{Account: sp("foo?*")}, true},
		{MatchConditions{Account: sp("/foo.*/")}, true},
		{MatchConditions{Type: sp("foo")}, true},
		{MatchConditions{Type: sp("foo?*")}, true},
		{MatchConditions{Type: sp("/foo.*/")}, true},
		{MatchConditions{Name: sp("foo")}, true},
		{MatchConditions{Name: sp("foo?*")}, true},
		{MatchConditions{Name: sp("/foo.*/")}, true},
		{MatchConditions{Service: sp("foo")}, true},
		{MatchConditions{Service: sp("foo?*")}, true},
		{MatchConditions{Service: sp("/foo.*/")}, true},
		{MatchConditions{IP: sp("192.168.0.1")}, true},
		{MatchConditions{IP: sp("192.168.0.0/16")}, true},
		{MatchConditions{IP: sp("2001:db8::1")}, true},
		{MatchConditions{IP: sp("2001:db8::/48")}, true},
		{MatchConditions{Labels: map[string]string{"foo": "bar"}}, true},
		// Invalid stuff
		{MatchConditions{Account: sp("/foo?*/")}, false},
		{MatchConditions{Type: sp("/foo?*/")}, false},
		{MatchConditions{Name: sp("/foo?*/")}, false},
		{MatchConditions{Service: sp("/foo?*/")}, false},
		{MatchConditions{IP: sp("192.168.0.1/100")}, false},
		{MatchConditions{IP: sp("192.168.0.*")}, false},
		{MatchConditions{IP: sp("foo")}, false},
		{MatchConditions{IP: sp("2001:db8::/222")}, false},
		{MatchConditions{Labels: map[string]string{"foo": "/bar?*/"}}, false},
	}
	for i, c := range cases {
		result := validateMatchConditions(&c.mc)
		if c.ok && result != nil {
			t.Errorf("%d: %v: expected to pass, got %s", i, c.mc, result)
		} else if !c.ok && result == nil {
			t.Errorf("%d: %v: expected to fail, but it passed", i, c.mc)
		}
	}
}

func TestMatching(t *testing.T) {
	ai1 := api.AuthRequestInfo{Account: "foo", Type: "bar", Name: "baz", Service: "notary"}
	ai2 := api.AuthRequestInfo{Account: "foo", Type: "bar", Name: "baz", Service: "notary",
		Labels: map[string][]string{"group": []string{"admins", "VIP"}}}
	ai3 := api.AuthRequestInfo{Account: "foo", Type: "bar", Name: "admins/foo", Service: "notary",
		Labels: map[string][]string{"group": []string{"admins", "VIP"}}}
	ai4 := api.AuthRequestInfo{Account: "foo", Type: "bar", Name: "VIP/api", Service: "notary",
		Labels: map[string][]string{"group": []string{"admins", "VIP"}, "project": []string{"api", "frontend"}}}
	ai5 := api.AuthRequestInfo{Account: "foo", Type: "bar", Name: "devs/api", Service: "notary",
		Labels: map[string][]string{"group": []string{"admins", "VIP"}, "project": []string{"api", "frontend"}}}
	cases := []struct {
		mc      MatchConditions
		ai      api.AuthRequestInfo
		matches bool
	}{
		{MatchConditions{}, ai1, true},
		{MatchConditions{Account: sp("foo")}, ai1, true},
		{MatchConditions{Account: sp("foo"), Type: sp("bar")}, ai1, true},
		{MatchConditions{Account: sp("foo"), Type: sp("baz")}, ai1, false},
		{MatchConditions{Account: sp("fo?"), Type: sp("b*"), Name: sp("/z$/")}, ai1, true},
		{MatchConditions{Account: sp("fo?"), Type: sp("b*"), Name: sp("/^z/")}, ai1, false},
		{MatchConditions{Name: sp("${account}")}, api.AuthRequestInfo{Account: "foo", Name: "foo"}, true}, // Var subst
		{MatchConditions{Name: sp("/${account}_.*/")}, api.AuthRequestInfo{Account: "foo", Name: "foo_x"}, true},
		{MatchConditions{Name: sp("/${account}_.*/")}, api.AuthRequestInfo{Account: ".*", Name: "foo_x"}, false}, // Quoting
		{MatchConditions{Account: sp(`/^(.+)@test\.com$/`), Name: sp(`${account:1}/*`)}, api.AuthRequestInfo{Account: "john.smith@test.com", Name: "john.smith/test"}, true},
		{MatchConditions{Account: sp(`/^(.+)@test\.com$/`), Name: sp(`${account:3}/*`)}, api.AuthRequestInfo{Account: "john.smith@test.com", Name: "john.smith/test"}, false},
		{MatchConditions{Account: sp(`/^(.+)@(.+?).test\.com$/`), Name: sp(`${account:1}-${account:2}/*`)}, api.AuthRequestInfo{Account: "john.smith@it.test.com", Name: "john.smith-it/test"}, true},
		{MatchConditions{Service: sp("notary"), Type: sp("bar")}, ai1, true},
		{MatchConditions{Service: sp("notary"), Type: sp("baz")}, ai1, false},
		{MatchConditions{Service: sp("notary1"), Type: sp("bar")}, ai1, false},
		// IP matching
		{MatchConditions{IP: sp("127.0.0.1")}, api.AuthRequestInfo{IP: nil}, false},
		{MatchConditions{IP: sp("127.0.0.1")}, api.AuthRequestInfo{IP: net.IPv4(127, 0, 0, 1)}, true},
		{MatchConditions{IP: sp("127.0.0.1")}, api.AuthRequestInfo{IP: net.IPv4(127, 0, 0, 2)}, false},
		{MatchConditions{IP: sp("127.0.0.2")}, api.AuthRequestInfo{IP: net.IPv4(127, 0, 0, 1)}, false},
		{MatchConditions{IP: sp("127.0.0.0/8")}, api.AuthRequestInfo{IP: net.IPv4(127, 0, 0, 1)}, true},
		{MatchConditions{IP: sp("127.0.0.0/8")}, api.AuthRequestInfo{IP: net.IPv4(127, 0, 0, 2)}, true},
		{MatchConditions{IP: sp("2001:db8::1")}, api.AuthRequestInfo{IP: nil}, false},
		{MatchConditions{IP: sp("2001:db8::1")}, api.AuthRequestInfo{IP: net.ParseIP("2001:db8::1")}, true},
		{MatchConditions{IP: sp("2001:db8::1")}, api.AuthRequestInfo{IP: net.ParseIP("2001:db8::2")}, false},
		{MatchConditions{IP: sp("2001:db8::2")}, api.AuthRequestInfo{IP: net.ParseIP("2001:db8::1")}, false},
		{MatchConditions{IP: sp("2001:db8::/48")}, api.AuthRequestInfo{IP: net.ParseIP("2001:db8::1")}, true},
		{MatchConditions{IP: sp("2001:db8::/48")}, api.AuthRequestInfo{IP: net.ParseIP("2001:db8::2")}, true},
		// Label matching
		{MatchConditions{Labels: map[string]string{"foo": "bar"}}, ai1, false},
		{MatchConditions{Labels: map[string]string{"foo": "bar"}}, ai2, false},
		{MatchConditions{Labels: map[string]string{"group": "admins"}}, ai2, true},
		{MatchConditions{Labels: map[string]string{"foo": "bar", "group": "admins"}}, ai2, false}, // "and" logic
		{MatchConditions{Labels: map[string]string{"group": "VIP"}}, ai2, true},
		{MatchConditions{Labels: map[string]string{"group": "a*"}}, ai2, true},
		{MatchConditions{Labels: map[string]string{"group": "/(admins|VIP)/"}}, ai2, true},
		// // Label placeholder matching
		{MatchConditions{Name: sp("${labels:group}/*")}, ai1, false},                 // no labels
		{MatchConditions{Name: sp("${labels:noexist}/*")}, ai2, false},               // wrong labels
		{MatchConditions{Name: sp("${labels:group}/*")}, ai3, true},                  // match label
		{MatchConditions{Name: sp("${labels:noexist}/*")}, ai3, false},               // missing label
		{MatchConditions{Name: sp("${labels:group}/${labels:project}")}, ai4, true},  // multiple label match success
		{MatchConditions{Name: sp("${labels:group}/${labels:noexist}")}, ai4, false}, // multiple label match fail
		{MatchConditions{Name: sp("${labels:group}/${labels:project}")}, ai4, true},  // multiple label match success
		{MatchConditions{Name: sp("${labels:group}/${labels:noexist}")}, ai4, false}, // multiple label match fail wrong label
		{MatchConditions{Name: sp("${labels:group}/${labels:project}")}, ai5, false}, // multiple label match fail. right label, wrong value
	}
	for i, c := range cases {
		if result := c.mc.Matches(&c.ai); result != c.matches {
			t.Errorf("%d: %#v vs %#v: expected %t, got %t", i, c.mc, c.ai, c.matches, result)
		}
	}
}
