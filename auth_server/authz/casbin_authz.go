package authz

import (
	"encoding/json"
	"fmt"

	"github.com/casbin/casbin"
	"github.com/cesanta/docker_auth/auth_server/authn"
)

// labelMatch determines whether lbl1 matches lbl2.
func labelMatch(lbl1 authn.Labels, lbl2 authn.Labels) bool {
	for label := range lbl2 {
		lbl1Values := lbl1[label]
		lbl2Values := lbl2[label]

		for _, val2 := range lbl2Values {
			matched := false
			for _, val1 := range lbl1Values {
				if val1 == val2 {
					matched = true
					break
				}
			}

			if !matched {
				return false
			}
		}
	}
	return true
}

// labelMatchFunc is the wrapper for labelMatch.
func labelMatchFunc(args ...interface{}) (interface{}, error) {
	fmt.Println(args[0].(string))
	lbl1 := stringToLabels(args[0].(string))
	fmt.Println(labelsToString(lbl1))
	lbl2 := stringToLabels(args[1].(string))

	return (bool)(labelMatch(lbl1, lbl2)), nil
}

func labelsToString(labels authn.Labels) string {
	labels_str, err := json.Marshal(labels)
	if err != nil {
		return ""
	}

	return string(labels_str)
}

func stringToLabels(str string) authn.Labels {
	labels := authn.Labels{}
	err := json.Unmarshal([]byte(str), &labels)
	if err != nil {
		return nil
	}

	return labels
}

type casbinAuthorizer struct {
	enforcer *casbin.Enforcer
	acl ACL
}

// NewCasbinAuthorizer creates a new casbin authorizer.
func NewCasbinAuthorizer(enforcer *casbin.Enforcer) (Authorizer, error) {
	enforcer.AddFunction("labelMatch", labelMatchFunc)
	return &casbinAuthorizer{enforcer: enforcer}, nil
}

// Authorize determines whether to allow the actions.
func (a *casbinAuthorizer) Authorize(ai *AuthRequestInfo) ([]string, error) {
	actions := []string{}

	for _, action := range ai.Actions {
		if a.enforcer.Enforce(ai.Account, ai.Type, ai.Name, ai.Service, ai.IP.String(), action, labelsToString(ai.Labels)) {
			actions = append(actions, action)
		}
	}
	return actions, nil

	// return nil, NoMatch
}

// Stop stops the middleware.
func (a *casbinAuthorizer) Stop() {
	// Nothing to do.
}

// Name returns the name of the middleware.
func (a *casbinAuthorizer) Name() string {
	return "Casbin Authorizer"
}
