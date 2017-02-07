package authn

import (
	"context"
	"errors"

	veritoneAPI "github.com/veritone/go-veritone-api"
)

type VeritoneAuth struct {
	Config *veritoneAPI.APIConfig
}

func NewVeritoneAuth(c *veritoneAPI.APIConfig) (*VeritoneAuth, error) {
	if c == nil || c.BaseURI == "" || c.Version == "" {
		return nil, errors.New("Invalid Veritone API config")
	}
	return &VeritoneAuth{
		Config: c,
	}, nil
}

func (vauth *VeritoneAuth) Authenticate(account string, password PasswordString) (bool, Labels, error) {
	info := &veritoneAPI.LoginInfo{
		Username: account,
		Password: string(password),
	}
	_, err := veritoneAPI.TryLogin(context.Background(), vauth.Config, info)
	if err != nil {
		return false, nil, errors.New("Veritone API authentication failed")
	}
	return true, nil, nil
}

func (vauth *VeritoneAuth) Stop() {
	return
}

func (vauth *VeritoneAuth) Name() string {
	return "Veritone API"
}
