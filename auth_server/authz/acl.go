package authz

import (
	"encoding/json"
	"path"
	"regexp"
	"strings"

	"github.com/golang/glog"
)

type ACL []ACLEntry

type ACLEntry struct {
	Match   *MatchConditions `yaml:"match"`
	Actions *[]string        `yaml:"actions,flow"`
	Comment *string          `yaml:"comment,omitempty"`
}

type MatchConditions struct {
	Account *string `yaml:"account,omitempty" json:"account,omitempty"`
	Type    *string `yaml:"type,omitempty" json:"type,omitempty"`
	Name    *string `yaml:"name,omitempty" json:"name,omitempty"`
}

type aclAuthorizer struct {
	acl ACL
}

// NewACLAuthorizer Creates a new static authorizer with ACL that have been read from the config file
func NewACLAuthorizer(acl ACL) (Authorizer, error) {
	glog.V(1).Infof("Created ACL Authorizer with %d entries", len(acl))
	return &aclAuthorizer{acl: acl}, nil
}

func (aa *aclAuthorizer) Authorize(ai *AuthRequestInfo) ([]string, error) {
	for _, e := range aa.acl {
		matched := e.Matches(ai)
		if matched {
			glog.V(2).Infof("%s matched %s (Comment: %s)", ai, e, e.Comment)
			if len(*e.Actions) == 1 && (*e.Actions)[0] == "*" {
				return ai.Actions, nil
			}
			return StringSetIntersection(ai.Actions, *e.Actions), nil
		}
	}
	return nil, NoMatch
}

func (aa *aclAuthorizer) Stop() {
	// Nothing to do.
}

func (aa *aclAuthorizer) Name() string {
	return "static ACL"
}

type aclEntryJSON *ACLEntry

func (e ACLEntry) String() string {
	b, _ := json.Marshal(e)
	return string(b)
}

func matchString(pp *string, s string, vars []string) bool {
	if pp == nil {
		return true
	}
	p := strings.NewReplacer(vars...).Replace(*pp)

	var matched bool
	var err error
	if len(p) > 2 && p[0] == '/' && p[len(p)-1] == '/' {
		matched, err = regexp.Match(p[1:len(p)-1], []byte(s))
	} else {
		matched, err = path.Match(p, s)
	}
	return err == nil && matched
}

func (e *ACLEntry) Matches(ai *AuthRequestInfo) bool {
	vars := []string{
		"${account}", regexp.QuoteMeta(ai.Account),
		"${type}", regexp.QuoteMeta(ai.Type),
		"${name}", regexp.QuoteMeta(ai.Name),
		"${service}", regexp.QuoteMeta(ai.Service),
	}
	if matchString(e.Match.Account, ai.Account, vars) &&
		matchString(e.Match.Type, ai.Type, vars) &&
		matchString(e.Match.Name, ai.Name, vars) {
		return true
	}
	return false
}
