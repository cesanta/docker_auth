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
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	oidc "github.com/coreos/go-oidc"

	"github.com/cesanta/glog"

	"github.com/cesanta/docker_auth/auth_server/api"
)

// All configuration options
type OIDCAuthConfig struct {
	// --- necessary ---
	// URL of the authentication provider. Must be able to serve the /.well-known/openid-configuration
	Issuer string `yaml:"issuer,omitempty"`
	// URL of the auth server. Has to end with /oidc_auth
	RedirectURL string `yaml:"redirect_url,omitempty"`
	// ID and secret, priovided by the OIDC provider after registration of the auth server
	ClientId         string `yaml:"client_id,omitempty"`
	ClientSecret     string `yaml:"client_secret,omitempty"`
	ClientSecretFile string `yaml:"client_secret_file,omitempty"`
	// path where the tokendb should be stored within the container
	TokenDB string `yaml:"token_db,omitempty"`
	// --- optional ---
	HTTPTimeout int `yaml:"http_timeout,omitempty"`
	// the URL of the docker registry. Used to generate a full docker login command after authentication
	RegistryURL string `yaml:"registry_url,omitempty"`
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

// ProfileResponse is sent by the /userinfo endpoint.
// We use it to validate access token and (re)verify the email address associated with it.
type OIDCProfileResponse struct {
	Email         string `json:"email,omitempty"`
	VerifiedEmail bool   `json:"verified_email,omitempty"`
	// There are more fields, but we only need email.
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
}

/*
Creates everything necessary for OIDC auth.
*/
func NewOIDCAuth(c *OIDCAuthConfig) (*OIDCAuth, error) {
	db, err := NewTokenDB(c.TokenDB)
	if err != nil {
		return nil, err
	}
	glog.Infof("OIDC auth token DB at %s", c.TokenDB)
	ctx := context.Background()
	prov, err := oidc.NewProvider(ctx, c.Issuer)
	if err != nil {
		return nil, err
	}
	return &OIDCAuth{
		config:     c,
		db:         db,
		client:     &http.Client{Timeout: 10 * time.Second},
		tmpl:       template.Must(template.New("oidc_auth").Parse(string(MustAsset("data/oidc_auth.tmpl")))),
		tmplResult: template.Must(template.New("oidc_auth_result").Parse(string(MustAsset("data/oidc_auth_result.tmpl")))),
		ctx:        ctx,
		provider:   prov,
	}, nil
}

/*
This function will be used by the server if the OIDC auth method is selected. It starts the OIDC auth page or serves the
different actions that are sent by the page to the server by calling the functions.
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
Executes tmpl for the login page of the docker auth server
*/
func (ga *OIDCAuth) doOIDCAuthPage(rw http.ResponseWriter) {
	if err := ga.tmpl.Execute(rw, struct {
		AuthEndpoint, RedirectURI, ClientId string
	}{
		AuthEndpoint: ga.provider.Endpoint().AuthURL,
		RedirectURI:  ga.config.RedirectURL,
		ClientId:     ga.config.ClientId,
	}); err != nil {
		http.Error(rw, fmt.Sprintf("Template error: %s", err), http.StatusInternalServerError)
	}
}

/*
Executes tmplResult for the result of the login process
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
Requests a token from the OIDC provider by reacting to the code that was responded. If token was given by OIDC provider,
new DB token is created based on the information given in the OIDC token
*/
func (ga *OIDCAuth) doOIDCAuthCreateToken(rw http.ResponseWriter, code string) {
	req, _ := http.NewRequest("POST", ga.provider.Endpoint().TokenURL, strings.NewReader(
		url.Values{
			"code":         []string{code},
			"redirect_uri": []string{ga.config.RedirectURL},
			"grant_type":   []string{"authorization_code"},
		}.Encode()))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Authorization",
		"Basic "+base64.StdEncoding.EncodeToString([]byte(ga.config.ClientId+":"+ga.config.ClientSecret)))
	resp, err := ga.client.Do(req)
	if err != nil {
		http.Error(rw, fmt.Sprintf("Error talking to OIDC auth backend: %s", err), http.StatusServiceUnavailable)
		return
	}
	codeResp, _ := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	glog.V(2).Infof("Code to token resp: %s", strings.Replace(string(codeResp), "\n", " ", -1))

	var c2t CodeToTokenResponse
	err = json.Unmarshal(codeResp, &c2t)
	if err != nil || c2t.Error != "" || c2t.ErrorDescription != "" {
		var et string
		if err != nil {
			et = err.Error()
		} else {
			et = fmt.Sprintf("%s: %s", c2t.Error, c2t.ErrorDescription)
		}
		http.Error(rw, fmt.Sprintf("Failed to get token: %s", et), http.StatusBadRequest)
		return
	}

	if c2t.RefreshToken == "" {
		glog.V(2).Infof("No refresh token was send by the OIDC provider")
	}

	if c2t.ExpiresIn < 60 {
		http.Error(rw, "New token is too short-lived", http.StatusInternalServerError)
		return
	}

	valid, err := ga.validateIDToken(c2t.IDToken)
	if err != nil || !valid {
		glog.Errorf("Newly-acquired ID token is invalid: %+v %s", c2t, err)
		http.Error(rw, "Newly-acquired ID token is invalid", http.StatusInternalServerError)
		return
	}

	ui, err := ga.getUserInformation(c2t.TokenType, c2t.AccessToken)
	if err != nil {
		glog.Errorf("Could not get user information from /userinfo endpoint with access token: %s", c2t.AccessToken)
	} else if ui == "" {
		glog.Errorf("There are no information about the users email address at /userinfo endpoint with access token: %s", c2t.AccessToken)
		http.Error(rw, "There are no information about the users email address given by the OIDC provider", http.StatusInternalServerError)
		return
	}

	glog.Infof("New OIDC auth token for %s (exp %d)", ui, c2t.ExpiresIn)

	v := &TokenDBValue{
		TokenType:    c2t.TokenType,
		AccessToken:  c2t.AccessToken,
		RefreshToken: c2t.RefreshToken,
		ValidUntil:   time.Now().Add(time.Duration(c2t.ExpiresIn-30) * time.Second),
	}
	dp, err := ga.db.StoreToken(ui, v, true)
	if err != nil {
		glog.Errorf("Failed to record server token: %s", err)
		http.Error(rw, "Failed to record server token: %s", http.StatusInternalServerError)
		return
	}

	ga.doOIDCAuthResultPage(rw, ui, dp)
}

/*
Validates the ID token and extracts user information (only extraction of email since it is the only necessary information)
*/
func (ga *OIDCAuth) validateIDToken(idToken string) (bool, error) {
	var verifier = ga.provider.Verifier(&oidc.Config{ClientID: ga.config.ClientId})
	_, err := verifier.Verify(ga.ctx, idToken)
	if err != nil {
		return false, fmt.Errorf("could not verify ID token %s. %s", idToken, err)
	}
	return true, nil
}

/*
Refreshs the access token of the user. Not usable with all OIDC provider, since not all provide refresh tokens.
*/
func (ga *OIDCAuth) refreshAccessToken(refreshToken string) (rtr OIDCRefreshTokenResponse, err error) {
	req, _ := http.NewRequest("POST", ga.provider.Endpoint().TokenURL, strings.NewReader(
		url.Values{
			"refresh_token": []string{refreshToken},
			"grant_type":    []string{"refresh_token"},
		}.Encode()))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Authorization",
		"Basic "+base64.StdEncoding.EncodeToString([]byte(ga.config.ClientId+":"+ga.config.ClientSecret)))
	resp, err := ga.client.Do(req)
	if err != nil {
		err = fmt.Errorf("error talking to OIDC auth backend: %s", err)
		return
	}
	respStr, _ := ioutil.ReadAll(resp.Body)
	glog.V(2).Infof("Refresh token resp: %s", strings.Replace(string(respStr), "\n", " ", -1))

	err = json.Unmarshal(respStr, &rtr)
	if err == nil && rtr.Error != "" || rtr.ErrorDescription != "" {
		err = fmt.Errorf("%s: %s", rtr.Error, rtr.ErrorDescription)
	}
	return
}

/*
Validates the access token of the user that is stored in the database against OIDC provider by requesting for user information
at the /userinfo endpoint. Responses the mail information of the user.
*/
func (ga *OIDCAuth) getUserInformation(toktype string, token string) (user string, err error) {
	req, _ := http.NewRequest("GET", ga.config.Issuer+"/userinfo", nil)
	req.Header.Add("Authorization", fmt.Sprintf("%s %s", toktype, token))
	resp, err := ga.client.Do(req)
	if err != nil {
		return
	}
	respStr, _ := ioutil.ReadAll(resp.Body)
	glog.V(2).Infof("Access token validation response: %s", strings.Replace(string(respStr), "\n", " ", -1))
	var pr ProfileResponse
	err = json.Unmarshal(respStr, &pr)
	if err != nil {
		return
	}
	return pr.Email, nil
}

/*
Check if DB token is expired and in case try to refresh it. Secondly check if the user of the DB token is validated against
the OIDC provider.
*/
func (ga *OIDCAuth) validateServerToken(user string) (*TokenDBValue, error) {
	v, err := ga.db.GetValue(user)
	if err != nil || v == nil {
		if err == nil {
			err = errors.New("no db value, please sign out and sign in again")
		}
		return nil, err
	}
	if v.RefreshToken != "" {
		return nil, errors.New("refresh of your session is not possible. Please sign out and sign in again")
	}
	if time.Now().After(v.ValidUntil) {
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
	}
	tokenUser, err := ga.getUserInformation(v.TokenType, v.AccessToken)
	if err != nil {
		glog.Warningf("Token for %q failed validation: %s", user, err)
		return nil, fmt.Errorf("server token invalid: %s", err)
	}
	if tokenUser != user {
		glog.Errorf("token for wrong user: expected %s, found %s", user, tokenUser)
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
Authenticates user with credentials that were given in the docker CLI. If the token in the DB is expired, the access token
is validated and, if possible, refreshed.
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
	return true, nil, nil
}

func (ga *OIDCAuth) Stop() {
	ga.db.Close()
	glog.Info("Token DB closed")
}

func (ga *OIDCAuth) Name() string {
	return "OpenID Connect"
}
