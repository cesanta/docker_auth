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
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/cesanta/glog"
)

type GoogleAuthConfig struct {
	Domain           string `yaml:"domain,omitempty"`
	ClientId         string `yaml:"client_id,omitempty"`
	ClientSecret     string `yaml:"client_secret,omitempty"`
	ClientSecretFile string `yaml:"client_secret_file,omitempty"`
	TokenDB          string `yaml:"token_db,omitempty"`
	HTTPTimeout      int    `yaml:"http_timeout,omitempty"`
}

type GoogleAuthRequest struct {
	Action string `json:"action,omitempty"`
	Code   string `json:"code,omitempty"`
	Token  string `json:"token,omitempty"`
}

// From github.com/google-api-go-client/oauth2/v2/oauth2-gen.go
type GoogleTokenInfo struct {
	// AccessType: The access type granted with this token. It can be
	// offline or online.
	AccessType string `json:"access_type,omitempty"`

	// Audience: Who is the intended audience for this token. In general the
	// same as issued_to.
	Audience string `json:"audience,omitempty"`

	// Email: The email address of the user. Present only if the email scope
	// is present in the request.
	Email string `json:"email,omitempty"`

	// ExpiresIn: The expiry time of the token, as number of seconds left
	// until expiry.
	ExpiresIn int64 `json:"expires_in,omitempty"`

	// IssuedTo: To whom was the token issued to. In general the same as
	// audience.
	IssuedTo string `json:"issued_to,omitempty"`

	// Scope: The space separated list of scopes granted to this token.
	Scope string `json:"scope,omitempty"`

	// TokenHandle: The token handle associated with this token.
	TokenHandle string `json:"token_handle,omitempty"`

	// UserId: The obfuscated user id.
	UserId string `json:"user_id,omitempty"`

	// VerifiedEmail: Boolean flag which is true if the email address is
	// verified. Present only if the email scope is present in the request.
	VerifiedEmail bool `json:"verified_email,omitempty"`

	// Returned in case of error.
	Error            string `json:"error,omitempty"`
	ErrorDescription string `json:"error_description,omitempty"`
}

// CodeToTokenResponse is sent by Google servers in response to the grant_type=authorization_code request.
type CodeToTokenResponse struct {
	IDToken      string `json:"id_token,omitempty"`
	AccessToken  string `json:"access_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	ExpiresIn    int64  `json:"expires_in,omitempty"`
	TokenType    string `json:"token_type,omitempty"`

	// Returned in case of error.
	Error            string `json:"error,omitempty"`
	ErrorDescription string `json:"error_description,omitempty"`
}

// CodeToTokenResponse is sent by Google servers in response to the grant_type=refresh_token request.
type RefreshTokenResponse struct {
	AccessToken string `json:"access_token,omitempty"`
	ExpiresIn   int64  `json:"expires_in,omitempty"`
	TokenType   string `json:"token_type,omitempty"`

	// Returned in case of error.
	Error            string `json:"error,omitempty"`
	ErrorDescription string `json:"error_description,omitempty"`
}

// ProfileResponse is sent by the /userinfo/v2/me endpoint.
// We use it to validate access token and (re)verify the email address associated with it.
type ProfileResponse struct {
	Email         string `json:"email,omitempty"`
	VerifiedEmail bool   `json:"verified_email,omitempty"`
	// There are more fields, but we only need email.
}

type GoogleAuth struct {
	config *GoogleAuthConfig
	db     TokenDB
	client *http.Client
	tmpl   *template.Template
}

func NewGoogleAuth(c *GoogleAuthConfig) (*GoogleAuth, error) {
	db, err := NewTokenDB(c.TokenDB)
	if err != nil {
		return nil, err
	}
	glog.Infof("Google auth token DB at %s", c.TokenDB)
	return &GoogleAuth{
		config: c,
		db:     db,
		client: &http.Client{Timeout: 10 * time.Second},
		tmpl:   template.Must(template.New("google_auth").Parse(string(MustAsset("data/google_auth.tmpl")))),
	}, nil
}

func (ga *GoogleAuth) DoGoogleAuth(rw http.ResponseWriter, req *http.Request) {
	if req.Method == "GET" {
		ga.doGoogleAuthPage(rw, req)
		return
	}
	gauthRequest, _ := ioutil.ReadAll(req.Body)
	glog.V(2).Infof("gauth request: %s", string(gauthRequest))
	var gar GoogleAuthRequest
	err := json.Unmarshal(gauthRequest, &gar)
	if err != nil {
		http.Error(rw, "Invalid auth request", http.StatusBadRequest)
		return
	}
	switch {
	case gar.Action == "sign_in" && gar.Code != "":
		ga.doGoogleAuthCreateToken(rw, gar.Code)
	case gar.Action == "check" && gar.Token != "":
		ga.doGoogleAuthCheck(rw, gar.Token)
	case gar.Action == "sign_out" && gar.Token != "":
		ga.doGoogleAuthSignOut(rw, gar.Token)
	default:
		http.Error(rw, "Invalid auth request", http.StatusBadRequest)
	}
}

func (ga *GoogleAuth) doGoogleAuthPage(rw http.ResponseWriter, req *http.Request) {
	if err := ga.tmpl.Execute(rw, struct{ ClientId string }{ClientId: ga.config.ClientId}); err != nil {
		http.Error(rw, fmt.Sprintf("Template error: %s", err), http.StatusInternalServerError)
	}
}

// https://developers.google.com/identity/protocols/OAuth2WebServer#handlingtheresponse
func (ga *GoogleAuth) doGoogleAuthCreateToken(rw http.ResponseWriter, code string) {
	resp, err := ga.client.PostForm(
		"https://www.googleapis.com/oauth2/v3/token",
		url.Values{
			"code":          []string{string(code)},
			"client_id":     []string{ga.config.ClientId},
			"client_secret": []string{ga.config.ClientSecret},
			"redirect_uri":  []string{"postmessage"},
			"grant_type":    []string{"authorization_code"},
		})
	if err != nil {
		http.Error(rw, fmt.Sprintf("Error talking to Google auth backend: %s", err), http.StatusServiceUnavailable)
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
		http.Error(rw, "Google did not return refresh token, please sign out and sign in again.", http.StatusBadRequest)
		return
	}

	if c2t.ExpiresIn < 60 {
		http.Error(rw, "New token is too short-lived", http.StatusInternalServerError)
		return
	}

	ti, err := ga.getIDTokenInfo(c2t.IDToken)
	if err != nil {
		glog.Errorf("Newly-acquired token is invalid: %+v %s", c2t, err)
		http.Error(rw, "Newly-acquired token is invalid", http.StatusInternalServerError)
		return
	}
	user := ti.Email

	glog.Infof("New Google auth token for %s (exp %d)", user, c2t.ExpiresIn)

	v := &TokenDBValue{
		TokenType:    c2t.TokenType,
		AccessToken:  c2t.AccessToken,
		RefreshToken: c2t.RefreshToken,
		ValidUntil:   time.Now().Add(time.Duration(c2t.ExpiresIn-30) * time.Second),
	}
	dp, err := ga.db.StoreToken(user, v, true)
	if err != nil {
		glog.Errorf("Failed to record server token: %s", err)
		http.Error(rw, "Failed to record server token: %s", http.StatusInternalServerError)
		return
	}

	fmt.Fprintf(rw, `Server logged in; now run "docker login YOUR_REGISTRY_FQDN", use %s as login and %s as password.`, user, dp)
}

func (ga *GoogleAuth) getIDTokenInfo(token string) (*GoogleTokenInfo, error) {
	// There is no Go auth library yet, using the tokeninfo endpoint.
	resp, err := http.Get(fmt.Sprintf("https://www.googleapis.com/oauth2/v2/tokeninfo?id_token=%s", token))
	if err != nil {
		return nil, fmt.Errorf("could not verify token %s: %s", token, err)
	}
	body, _ := ioutil.ReadAll(resp.Body)
	resp.Body.Close()

	var ti GoogleTokenInfo
	err = json.Unmarshal(body, &ti)
	if err != nil {
		return nil, fmt.Errorf("could not unmarshal token info %q: %s", string(body), err)
	}
	glog.V(2).Infof("Token info: %+v", strings.Replace(string(body), "\n", " ", -1))
	if ti.Error != "" || ti.ErrorDescription != "" {
		return nil, fmt.Errorf("bad token %q: %s %s", token, ti.Error, ti.ErrorDescription)
	}
	if ti.ExpiresIn <= 0 {
		return nil, errors.New("expired token")
	}
	me := ga.config.ClientId
	if ti.Audience != me {
		return nil, fmt.Errorf("token intended for %s, not %s", ti.Audience, me)
	}
	if ti.Email == "" || !ti.VerifiedEmail {
		return nil, errors.New("no verified email in token")
	}
	err = ga.checkDomain(ti.Email)
	if err != nil {
		return nil, err
	}
	glog.V(2).Infof("Token for %s, expires in %d", ti.Email, ti.ExpiresIn)
	return &ti, nil
}

func (ga *GoogleAuth) checkDomain(email string) error {
	if ga.config.Domain == "" {
		return nil
	}
	parts := strings.Split(email, "@")
	if parts[1] != ga.config.Domain {
		return fmt.Errorf("only users from %s may login", ga.config.Domain)
	}
	return nil
}

// https://developers.google.com/identity/protocols/OAuth2WebServer#refresh
func (ga *GoogleAuth) refreshAccessToken(refreshToken string) (rtr RefreshTokenResponse, err error) {
	resp, err := ga.client.PostForm(
		"https://www.googleapis.com/oauth2/v3/token",
		url.Values{
			"refresh_token": []string{refreshToken},
			"client_id":     []string{ga.config.ClientId},
			"client_secret": []string{ga.config.ClientSecret},
			"grant_type":    []string{"refresh_token"},
		})
	if err != nil {
		err = fmt.Errorf("Error talking to Google auth backend: %s", err)
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

func (ga *GoogleAuth) validateAccessToken(toktype, token string) (user string, err error) {
	req, _ := http.NewRequest("GET", "https://www.googleapis.com/userinfo/v2/me", nil)
	req.Header.Add("Authorization", fmt.Sprintf("%s %s", toktype, token))
	resp, err := ga.client.Do(req)
	if err != nil {
		return
	}
	respStr, _ := ioutil.ReadAll(resp.Body)
	glog.V(2).Infof("Access token validation rrsponse: %s", strings.Replace(string(respStr), "\n", " ", -1))
	var pr ProfileResponse
	err = json.Unmarshal(respStr, &pr)
	if err != nil {
		return
	}
	err = ga.checkDomain(pr.Email)
	if err != nil {
		return
	}
	return pr.Email, nil
}

func (ga *GoogleAuth) validateServerToken(user string) (*TokenDBValue, error) {
	v, err := ga.db.GetValue(user)
	if err != nil || v == nil {
		if err == nil {
			err = errors.New("no db value, please sign out and sign in again.")
		}
		return nil, err
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
	tokenUser, err := ga.validateAccessToken(v.TokenType, v.AccessToken)
	if err != nil {
		glog.Warningf("Token for %q failed validation: %s", user, err)
		return nil, fmt.Errorf("server token invalid: %s", err)
	}
	if tokenUser != user {
		glog.Errorf("token for wrong user: expected %s, found %s", user, tokenUser)
		return nil, fmt.Errorf("found token for wrong user")
	}
	texp := v.ValidUntil.Sub(time.Now())
	glog.V(1).Infof("Validated Google auth token for %s (exp %d)", user, int(texp.Seconds()))
	return v, nil
}

func (ga *GoogleAuth) doGoogleAuthCheck(rw http.ResponseWriter, token string) {
	// First, authenticate web user.
	ti, err := ga.getIDTokenInfo(token)
	if err != nil {
		http.Error(rw, fmt.Sprintf("Could not verify user token: %s", err), http.StatusBadRequest)
		return
	}
	// User authenticated, now verify our token.
	dbv, err := ga.validateServerToken(ti.Email)
	if err != nil {
		http.Error(rw, fmt.Sprintf("Could not verify server token: %s", err), http.StatusBadRequest)
		return
	}
	// Truncate to seconds for presentation.
	texp := time.Duration(int64(dbv.ValidUntil.Sub(time.Now()).Seconds())) * time.Second
	fmt.Fprintf(rw, "Server token for %s validated, expires in %s", ti.Email, texp)
}

func (ga *GoogleAuth) doGoogleAuthSignOut(rw http.ResponseWriter, token string) {
	// Authenticate web user.
	ti, err := ga.getIDTokenInfo(token)
	if err != nil {
		http.Error(rw, fmt.Sprintf("Could not verify user token: %s", err), http.StatusBadRequest)
		return
	}
	err = ga.db.DeleteToken(ti.Email)
	if err != nil {
		glog.Error(err)
	}
	fmt.Fprint(rw, "signed out")
}

func (ga *GoogleAuth) Authenticate(user string, password PasswordString) (bool, Labels, error) {
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

func (ga *GoogleAuth) Stop() {
	ga.db.Close()
	glog.Info("Token DB closed")
}

func (ga *GoogleAuth) Name() string {
	return "Google"
}
