package authn

import (
	"context"
	"errors"

	"github.com/golang/glog"
	"github.com/veritone/docker_auth/auth_server/authz"

	veritoneAPI "github.com/veritone/go-veritone-api"
)

type VeritoneAuth struct {
	Config *veritoneAPI.APIConfig
	ACL    *authz.VeritoneAuthorizer
}

func NewVeritoneAuth(c *veritoneAPI.APIConfig, acl *authz.VeritoneAuthorizer) (*VeritoneAuth, error) {
	if c == nil || c.BaseURI == "" || c.Version == "" {
		return nil, errors.New("Invalid Veritone API config")
	}
	return &VeritoneAuth{
		Config: c,
		ACL:    acl,
	}, nil
}

func (vauth *VeritoneAuth) Authenticate(account string, password PasswordString) (bool, authz.Labels, error) {
	info := &veritoneAPI.LoginInfo{
		Username: account,
		Password: string(password),
	}
	resp, err := veritoneAPI.TryLogin(context.Background(), vauth.Config, info)
	if err != nil {
		return false, nil, errors.New("Veritone API authentication failed")
	}
	// add authorizer entries if configured
	if vauth.ACL != nil {
		if perm, _ := resp.HasPermission("superadmin"); perm {
			glog.V(2).Info("superadmin!")

			match := &authz.MatchConditions{
				Account: &account,
			}
			actions := []string{"*"}
			comment := "User is superadmin"
			e := authz.ACLEntry{
				Match:   match,
				Actions: &actions,
				Comment: &comment,
			}
			vauth.ACL.Add(e)
		}
	}

	return true, nil, nil
}

func (vauth *VeritoneAuth) Stop() {
	return
}

func (vauth *VeritoneAuth) Name() string {
	return "Veritone API"
}
