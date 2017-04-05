package authz

import (
	"net"
	"testing"
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
			t.Errorf("%d: %q: expected to pass, got %s", i, c.mc, result)
		} else if !c.ok && result == nil {
			t.Errorf("%d: %q: expected to fail, but it passed", i, c.mc)
		}
	}
}

func TestMatching(t *testing.T) {
	ai1 := AuthRequestInfo{Account: "foo", Type: "bar", Name: "baz", Service: "notary"}
	ai2 := AuthRequestInfo{Account: "foo", Type: "bar", Name: "baz", Service: "notary",
		Labels: map[string][]string{"group": []string{"admins", "VIP"}}}
	cases := []struct {
		mc      MatchConditions
		ai      AuthRequestInfo
		matches bool
	}{
		{MatchConditions{}, ai1, true},
		{MatchConditions{Account: sp("foo")}, ai1, true},
		{MatchConditions{Account: sp("foo"), Type: sp("bar")}, ai1, true},
		{MatchConditions{Account: sp("foo"), Type: sp("baz")}, ai1, false},
		{MatchConditions{Account: sp("fo?"), Type: sp("b*"), Name: sp("/z$/")}, ai1, true},
		{MatchConditions{Account: sp("fo?"), Type: sp("b*"), Name: sp("/^z/")}, ai1, false},
		{MatchConditions{Name: sp("${account}")}, AuthRequestInfo{Account: "foo", Name: "foo"}, true}, // Var subst
		{MatchConditions{Name: sp("/${account}_.*/")}, AuthRequestInfo{Account: "foo", Name: "foo_x"}, true},
		{MatchConditions{Name: sp("/${account}_.*/")}, AuthRequestInfo{Account: ".*", Name: "foo_x"}, false}, // Quoting
		{MatchConditions{Account: sp(`/^(.+)@test\.com$/`), Name: sp(`${account:1}/*`)}, AuthRequestInfo{Account: "john.smith@test.com", Name: "john.smith/test"}, true},
		{MatchConditions{Account: sp(`/^(.+)@test\.com$/`), Name: sp(`${account:3}/*`)}, AuthRequestInfo{Account: "john.smith@test.com", Name: "john.smith/test"}, false},
		{MatchConditions{Account: sp(`/^(.+)@(.+?).test\.com$/`), Name: sp(`${account:1}-${account:2}/*`)}, AuthRequestInfo{Account: "john.smith@it.test.com", Name: "john.smith-it/test"}, true},
		{MatchConditions{Service: sp("notary"), Type: sp("bar")}, ai1, true},
		{MatchConditions{Service: sp("notary"), Type: sp("baz")}, ai1, false},
		{MatchConditions{Service: sp("notary1"), Type: sp("bar")}, ai1, false},
		// IP matching
		{MatchConditions{IP: sp("127.0.0.1")}, AuthRequestInfo{IP: nil}, false},
		{MatchConditions{IP: sp("127.0.0.1")}, AuthRequestInfo{IP: net.IPv4(127, 0, 0, 1)}, true},
		{MatchConditions{IP: sp("127.0.0.1")}, AuthRequestInfo{IP: net.IPv4(127, 0, 0, 2)}, false},
		{MatchConditions{IP: sp("127.0.0.2")}, AuthRequestInfo{IP: net.IPv4(127, 0, 0, 1)}, false},
		{MatchConditions{IP: sp("127.0.0.0/8")}, AuthRequestInfo{IP: net.IPv4(127, 0, 0, 1)}, true},
		{MatchConditions{IP: sp("127.0.0.0/8")}, AuthRequestInfo{IP: net.IPv4(127, 0, 0, 2)}, true},
		{MatchConditions{IP: sp("2001:db8::1")}, AuthRequestInfo{IP: nil}, false},
		{MatchConditions{IP: sp("2001:db8::1")}, AuthRequestInfo{IP: net.ParseIP("2001:db8::1")}, true},
		{MatchConditions{IP: sp("2001:db8::1")}, AuthRequestInfo{IP: net.ParseIP("2001:db8::2")}, false},
		{MatchConditions{IP: sp("2001:db8::2")}, AuthRequestInfo{IP: net.ParseIP("2001:db8::1")}, false},
		{MatchConditions{IP: sp("2001:db8::/48")}, AuthRequestInfo{IP: net.ParseIP("2001:db8::1")}, true},
		{MatchConditions{IP: sp("2001:db8::/48")}, AuthRequestInfo{IP: net.ParseIP("2001:db8::2")}, true},
		// Label matching
		{MatchConditions{Labels: map[string]string{"foo": "bar"}}, ai1, false},
		{MatchConditions{Labels: map[string]string{"foo": "bar"}}, ai2, false},
		{MatchConditions{Labels: map[string]string{"group": "admins"}}, ai2, true},
		{MatchConditions{Labels: map[string]string{"foo": "bar", "group": "admins"}}, ai2, false}, // "and" logic
		{MatchConditions{Labels: map[string]string{"group": "VIP"}}, ai2, true},
		{MatchConditions{Labels: map[string]string{"group": "a*"}}, ai2, true},
		{MatchConditions{Labels: map[string]string{"group": "/(admins|VIP)/"}}, ai2, true},
	}
	for i, c := range cases {
		if result := c.mc.Matches(&c.ai); result != c.matches {
			t.Errorf("%d: %#v vs %#v: expected %t, got %t", i, c.mc, c.ai, c.matches, result)
		}
	}
}
