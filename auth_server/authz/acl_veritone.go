package authz

import (
	"github.com/golang/glog"
)

type VeritoneAuthorizer struct {
	acl ACL
}

// NewVeritoneAuthorizer Creates a new veritone authorizer
func NewVeritoneAuthorizer() *VeritoneAuthorizer {
	glog.V(1).Info("Created Veritone Authorizer")
	return &VeritoneAuthorizer{acl: ACL{}}
}

func (va *VeritoneAuthorizer) Authorize(ai *AuthRequestInfo) ([]string, error) {
	for _, e := range va.acl {
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

func (va *VeritoneAuthorizer) Add(e ACLEntry) {
	va.acl = append(va.acl, e)
}

func (va *VeritoneAuthorizer) Stop() {
	// Nothing to do.
}

func (va *VeritoneAuthorizer) Name() string {
	return "Veritone Authorizer"
}
