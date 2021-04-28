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
	"encoding/json"
	"fmt"

	"github.com/casbin/casbin/v2"
	"github.com/cesanta/docker_auth/auth_server/api"
)

type CasbinAuthzConfig struct {
	ModelFilePath  string `yaml:"model_path"`
	PolicyFilePath string `yaml:"policy_path"`
}

// labelMatch determines whether lbl1 matches lbl2.
func labelMatch(lbl1 api.Labels, lbl2 api.Labels) bool {
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
	fmt.Println(lbl2)

	return (bool)(labelMatch(lbl1, lbl2)), nil
}

func labelsToString(labels api.Labels) string {
	labelsStr, err := json.Marshal(labels)
	if err != nil {
		return ""
	}

	return string(labelsStr)
}

func stringToLabels(str string) api.Labels {
	labels := api.Labels{}
	err := json.Unmarshal([]byte(str), &labels)
	if err != nil {
		return nil
	}

	return labels
}

type casbinAuthorizer struct {
	enforcer *casbin.Enforcer
	acl      ACL
}

// NewCasbinAuthorizer creates a new casbin authorizer.
func NewCasbinAuthorizer(enforcer *casbin.Enforcer) (api.Authorizer, error) {
	enforcer.AddFunction("labelMatch", labelMatchFunc)
	return &casbinAuthorizer{enforcer: enforcer}, nil
}

// Authorize determines whether to allow the actions.
func (a *casbinAuthorizer) Authorize(ai *api.AuthRequestInfo) ([]string, error) {
	actions := []string{}

	for _, action := range ai.Actions {
		if ok, _ := a.enforcer.Enforce(ai.Account, ai.Type, ai.Name, ai.Service, ai.IP.String(), action, labelsToString(ai.Labels)); ok {
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
