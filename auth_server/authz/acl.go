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
}

type MatchConditions struct {
	Account *string `yaml:"account,omitempty" json:"account,omitempty"`
	Type    *string `yaml:"type,omitempty" json:"type,omitempty"`
	Name    *string `yaml:"name,omitempty" json:"name,omitempty"`
}

type aclAuthorizer struct {
	acl ACL
}

func NewACLAuthorizer(acl ACL) Authorizer {
	return &aclAuthorizer{acl: acl}
}

func (aa *aclAuthorizer) Authorize(ai *AuthRequestInfo) ([]string, error) {
	for _, e := range aa.acl {
		matched := e.Matches(ai)
		if matched {
			glog.V(2).Infof("%s matched %s", ai, e)
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

func matchString(pp *string, s string, ai *AuthRequestInfo) bool {
	if pp == nil {
		return true
	}
	p := *pp
	var matched bool
	var err error
	
	// replace each known variable
	r := strings.NewReplacer("${account}",ai.Account,"${type}",ai.Type,"${name}",ai.Name,"${service}",ai.Service)
	p = r.Replace(p)
		
		
	if len(p) > 2 && p[0] == '/' && p[len(p)-1] == '/' {
		matched, err = regexp.Match(p[1:len(p)-1], []byte(s))
	} else {
		matched, err = path.Match(p, s)
	}
	return err == nil && matched
}

func (e *ACLEntry) Matches(ai *AuthRequestInfo) bool {
	if matchString(e.Match.Account, ai.Account, ai) &&
		matchString(e.Match.Type, ai.Type, ai) &&
		matchString(e.Match.Name, ai.Name, ai) {
		return true
	}
	return false
}
