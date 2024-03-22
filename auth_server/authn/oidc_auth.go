/*
   Copyright 2015 Cesanta Software Ltd.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       https://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

package authn

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"golang.org/x/oauth2"

	"github.com/coreos/go-oidc/v3/oidc"

	"github.com/cesanta/glog"

	"github.com/cesanta/docker_auth/auth_server/api"
)

// All configuration options
type OIDCAuthConfig struct {
	// --- necessary ---
	// URL of the authentication provider. Must be able to serve the /.well-known/openid-configuration
	Issuer           string            `yaml:"issuer,omitempty"`
	// URL of the auth server. Has to end with /oidc_auth
	RedirectURL      string            `yaml:"redirect_url,omitempty"`
	// ID and secret, priovided by the OIDC provider after registration of the auth server
	ClientId         string            `yaml:"client_id,omitempty"`
	ClientSecret     string            `yaml:"client_secret,omitempty"`
	ClientSecretFile string            `yaml:"client_secret_file,omitempty"`
	// path where the tokendb should be stored within the container
	LevelTokenDB     *LevelDBStoreConfig `yaml:"level_token_db,omitempty"`
	GCSTokenDB       *GCSStoreConfig     `yaml:"gcs_token_db,omitempty"`
	RedisTokenDB     *RedisStoreConfig   `yaml:"redis_token_db,omitempty"`
	// --- optional ---
	HTTPTimeout      time.Duration     `yaml:"http_timeout,omitempty"`
	// the URL of the docker registry. Used to generate a full docker login command after authentication
	RegistryURL      string            `yaml:"registry_url,omitempty"`
	// --- optional ---
	// String claim to use for the username
	UserClaim        string            `yaml:"user_claim,omitempty"`
	// --- optional ---
	// []string to add as labels.
	LabelsClaims     []string          `yaml:"labels_claims,omitempty"`
	// --- optional ---
	Scopes           []string          `yaml:"scopes,omitempty"`
}

// OIDCRefreshTokenResponse is sent by OIDC provider in response to the grant_type=refresh_token request.
type OIDCRefreshTokenResponse struct {
	AccessToken  string `json:"access_token,omitempty"`
	ExpiresIn    int64  `json:"expires_in,omitempty"`
	TokenType    string `json:"token_type,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`

	// Returned in case of error.
	Error            string `json:"error,omitempty"`
	ErrorDescription string `json:"error_description,omitempty"`
}

// The specific OIDC authenticator
type OIDCAuth struct {
	config     *OIDCAuthConfig
	db         TokenDB
	client     *http.Client
	tmpl       *template.Template
	tmplResult *template.Template
	ctx        context.Context
	provider   *oidc.Provider
	verifier   *oidc.IDTokenVerifier
	oauth      oauth2.Config
}

/*
Creates everything necessary for OIDC auth.
*/
func NewOIDCAuth(c *OIDCAuthConfig) (*OIDCAuth, error) {
	var db TokenDB
	var err error
	var dbName string

	switch {
	case c.GCSTokenDB != nil:
		db, err = NewGCSTokenDB(c.GCSTokenDB)
		dbName = "GCS: " + c.GCSTokenDB.Bucket
	case c.RedisTokenDB != nil:
		db, err = NewRedisTokenDB(c.RedisTokenDB)
		dbName = db.(*redisTokenDB).String()
	default:
		db, err = NewTokenDB(c.LevelTokenDB)
		dbName = c.LevelTokenDB.Path
	}

	if err != nil {
		return nil, err
	}
	glog.Infof("OIDC auth token DB at %s", dbName)
	ctx := context.Background()
	oidcAuth, _ := static.ReadFile("data/oidc_auth.tmpl")
	oidcAuthResult, _ := static.ReadFile("data/oidc_auth_result.tmpl")

	prov, err := oidc.NewProvider(ctx, c.Issuer)
	if err != nil {
		return nil, err
	}
	conf := oauth2.Config{
		ClientID:     c.ClientId,
		ClientSecret: c.ClientSecret,
		Endpoint:     prov.Endpoint(),
		RedirectURL:  c.RedirectURL,
		Scopes:       c.Scopes,
	}
	return &OIDCAuth{
		config:     c,
		db:         db,
		client:     &http.Client{Timeout: c.HTTPTimeout},
		tmpl:       template.Must(template.New("oidc_auth").Parse(string(oidcAuth))),
		tmplResult: template.Must(template.New("oidc_auth_result").Parse(string(oidcAuthResult))),
		ctx:        ctx,
		provider:   prov,
		verifier:   prov.Verifier(&oidc.Config{ClientID: conf.ClientID}),
		oauth:      conf,
	}, nil
}

/*
This function will be used by the server if the OIDC auth method is selected. It starts the page for OIDC login or
requests an access token by using the code given by the OIDC provider.
*/
func (ga *OIDCAuth) DoOIDCAuth(rw http.ResponseWriter, req *http.Request) {
	code := req.URL.Query().Get("code")
	if code != "" {
		ga.doOIDCAuthCreateToken(rw, code)
	} else if req.Method == "GET" {
		ga.doOIDCAuthPage(rw)
	} else {
		http.Error(rw, "Invalid auth request", http.StatusBadRequest)
	}
}

/*
Executes tmpl for the OIDC login page.
*/
func (ga *OIDCAuth) doOIDCAuthPage(rw http.ResponseWriter) {
	if err := ga.tmpl.Execute(rw, struct {
		AuthEndpoint, RedirectURI, ClientId, Scope string
	}{
		AuthEndpoint: ga.provider.Endpoint().AuthURL,
		RedirectURI:  ga.oauth.RedirectURL,
		ClientId:     ga.oauth.ClientID,
		Scope:        strings.Join(ga.config.Scopes, " "),
	}); err != nil {
		http.Error(rw, fmt.Sprintf("Template error: %s", err), http.StatusInternalServerError)
	}
}

/*
Executes tmplResult for the result of the login process.
*/
func (ga *OIDCAuth) doOIDCAuthResultPage(rw http.ResponseWriter, un string, pw string) {
	if err := ga.tmplResult.Execute(rw, struct {
		Username, Password, RegistryUrl string
	}{
		Username:    un,
		Password:    pw,
		RegistryUrl: ga.config.RegistryURL,
	}); err != nil {
		http.Error(rw, fmt.Sprintf("Template error: %s", err), http.StatusInternalServerError)
	}
}

/*
Requests an OIDC token by using the code that was provided by the OIDC provider. If it was successfull,
the access token and refresh token is used to create a new token for the users mail address, which is taken from the ID
token.
*/
func (ga *OIDCAuth) doOIDCAuthCreateToken(rw http.ResponseWriter, code string) {

	tok, err := ga.oauth.Exchange(ga.ctx, code)
	if err != nil {
		http.Error(rw, fmt.Sprintf("Error talking to OIDC auth backend: %s", err), http.StatusInternalServerError)
		return
	}
	rawIdTok, ok := tok.Extra("id_token").(string)
	if !ok {
		http.Error(rw, "No id_token field in oauth2 token.", http.StatusInternalServerError)
		return
	}
	idTok, err := ga.verifier.Verify(ga.ctx, rawIdTok)
	if err != nil {
		http.Error(rw, fmt.Sprintf("Failed to verify ID token: %s", err), http.StatusInternalServerError)
		return
	}
	var claims map[string]interface{}
	if err := idTok.Claims(&claims); err != nil {
		http.Error(rw, fmt.Sprintf("Failed to get claims from ID token: %s", err), http.StatusInternalServerError)
		return
	}
	username, _ := claims[ga.config.UserClaim].(string)
	if username == "" {
		http.Error(rw, fmt.Sprintf("No %q claim in ID token", ga.config.UserClaim), http.StatusInternalServerError)
		return
	}

	glog.V(2).Infof("New OIDC auth token for %s (Current time: %s, expiration time: %s)", username, time.Now().String(), tok.Expiry.String())

	dbVal := &TokenDBValue{
		TokenType:    tok.TokenType,
		AccessToken:  tok.AccessToken,
		RefreshToken: tok.RefreshToken,
		ValidUntil:   tok.Expiry.Add(time.Duration(-30) * time.Second),
		Labels:       ga.getLabels(claims),
	}
	dp, err := ga.db.StoreToken(username, dbVal, true)
	if err != nil {
		glog.Errorf("Failed to record server token: %s", err)
		http.Error(rw, "Failed to record server token: %s", http.StatusInternalServerError)
		return
	}

	ga.doOIDCAuthResultPage(rw, username, dp)
}

func (ga *OIDCAuth) getLabels(claims map[string]interface{}) api.Labels {
	labels := make(api.Labels, len(ga.config.LabelsClaims))
	for _, claim := range ga.config.LabelsClaims {
		values, _ := claims[claim].([]interface{})
		for _, v := range values {
			if str, _ := v.(string); str != "" {
				labels[claim] = append(labels[claim], str)
			}
		}
	}
	return labels
}

/*
Refreshes the access token of the user. Not usable with all OIDC provider, since not all provide refresh tokens.
*/
func (ga *OIDCAuth) refreshAccessToken(refreshToken string) (rtr OIDCRefreshTokenResponse, err error) {

	url := ga.provider.Endpoint().TokenURL
	pl := strings.NewReader(fmt.Sprintf(
		"grant_type=refresh_token&client_id=%s&client_secret=%s&refresh_token=%s",
		ga.oauth.ClientID, ga.oauth.ClientSecret, refreshToken))
	req, err := http.NewRequest("POST", url, pl)
	if err != nil {
		err = fmt.Errorf("could not create refresh request: %s", err)
		return
	}
	req.Header.Add("content-type", "application/x-www-form-urlencoded")

	resp, err := ga.client.Do(req)
	if err != nil {
		err = fmt.Errorf("error talking to OIDC auth backend: %s", err)
		return
	}
	respStr, _ := ioutil.ReadAll(resp.Body)
	glog.V(2).Infof("Refresh token resp: %s", strings.Replace(string(respStr), "\n", " ", -1))

	err = json.Unmarshal(respStr, &rtr)
	if err != nil {
		err = fmt.Errorf("error in reading response of refresh request: %s", err)
		return
	}
	if rtr.Error != "" || rtr.ErrorDescription != "" {
		err = fmt.Errorf("%s: %s", rtr.Error, rtr.ErrorDescription)
		return
	}
	return rtr, err
}

/*
In case the DB token is expired, this function uses the refresh token and tries to refresh the access token stored in the
DB. Afterwards, checks if the access token really authenticates the user trying to log in.
*/
func (ga *OIDCAuth) validateServerToken(user string) (*TokenDBValue, error) {
	v, err := ga.db.GetValue(user)
	if err != nil || v == nil {
		if err == nil {
			err = errors.New("no db value, please sign out and sign in again")
		}
		return nil, err
	}
	if v.RefreshToken == "" {
		return nil, errors.New("refresh of your session is not possible. Please sign out and sign in again")
	}

	glog.V(2).Infof("Refreshing token for %s", user)
	rtr, err := ga.refreshAccessToken(v.RefreshToken)
	if err != nil {
		glog.Warningf("Failed to refresh token for %q: %s", user, err)
		return nil, fmt.Errorf("failed to refresh token: %s", err)
	}
	v.AccessToken = rtr.AccessToken
	v.ValidUntil = time.Now().Add(time.Duration(rtr.ExpiresIn-30) * time.Second)
	glog.Infof("Refreshed auth token for %s (exp %d)", user, rtr.ExpiresIn)
	_, err = ga.db.StoreToken(user, v, false)
	if err != nil {
		glog.Errorf("Failed to record refreshed token: %s", err)
		return nil, fmt.Errorf("failed to record refreshed token: %s", err)
	}
	tokUser, err := ga.provider.UserInfo(ga.ctx, oauth2.StaticTokenSource(&oauth2.Token{AccessToken: v.AccessToken,
		TokenType:    v.TokenType,
		RefreshToken: v.RefreshToken,
		Expiry:       v.ValidUntil,
	}))
	if err != nil {
		glog.Warningf("Token for %q failed validation: %s", user, err)
		return nil, fmt.Errorf("server token invalid: %s", err)
	}

	var claims map[string]interface{}
	if err := tokUser.Claims(&claims); err != nil {
		glog.Errorf("error retrieving claims: %v", err)
		return nil, fmt.Errorf("error retrieving claims: %w", err)
	}
	claimUsername, _ := claims[ga.config.UserClaim].(string)
	if claimUsername != user {
		glog.Errorf("token for wrong user: expected %s, found %s", user, claimUsername)
		return nil, fmt.Errorf("found token for wrong user")
	}
	texp := v.ValidUntil.Sub(time.Now())
	glog.V(1).Infof("Validated OIDC auth token for %s (exp %d)", user, int(texp.Seconds()))
	return v, nil
}

/*
First checks if OIDC token is valid. Then delete the corresponding DB token from the database. The user is now signed out
Not deleted because maybe it will be implemented in the future.
*/
//func (ga *OIDCAuth) doOIDCAuthSignOut(rw http.ResponseWriter, token string) {
//	// Authenticate web user.
//	ui, err := ga.validateIDToken(token)
//	if err != nil || ui == ""{
//		http.Error(rw, fmt.Sprintf("Could not verify user token: %s", err), http.StatusBadRequest)
//		return
//	}
//	err = ga.db.DeleteToken(ui)
//	if err != nil {
//		glog.Error(err)
//	}
//	fmt.Fprint(rw, "signed out")
//}

/*
Called by server. Authenticates user with credentials that were given in the docker login command. If the token in the
DB is expired, the OIDC access token is validated and, if possible, refreshed.
*/
func (ga *OIDCAuth) Authenticate(user string, password api.PasswordString) (bool, api.Labels, error) {
	err := ga.db.ValidateToken(user, password)
	if err == ExpiredToken {
		_, err = ga.validateServerToken(user)
		if err != nil {
			return false, nil, err
		}
	} else if err != nil {
		return false, nil, err
	}

	v, err := ga.db.GetValue(user)
	if err != nil || v == nil {
		if err == nil {
			err = errors.New("no db value, please sign out and sign in again")
		}
		return false, nil, err
	}
	return true, v.Labels, err
}

func (ga *OIDCAuth) Stop() {
	err := ga.db.Close()
	if err != nil {
		glog.Info("Problems at closing the token DB")
	} else {
		glog.Info("Token DB closed")
	}
}

func (ga *OIDCAuth) Name() string {
	return "OpenID Connect"
}
