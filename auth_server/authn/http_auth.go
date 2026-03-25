/*
   Copyright 2016 Cesanta Software Ltd.

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
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/cesanta/docker_auth/auth_server/api"
	"github.com/cesanta/glog"
)

const (
	httpAuthAllow             = "allow"
	httpAuthDeny              = "deny"
	httpAuthFailed            = "failed"
	httpAuthNoMatch           = "no_match"
	httpAuthMaxErrorBodyBytes = 1024
)

type HttpAuthConfig struct {
	Url                string              `yaml:"http_url"`
	InsecureSkipVerify bool                `yaml:"insecure_tls_skip_verify,omitempty"`
	HTTPTimeout        time.Duration       `yaml:"http_timeout,omitempty"`
	DisableKeepAlives  bool                `yaml:"http_disable_keepalives,omitempty"`
	Headers            map[string][]string `yaml:"http_headers,omitempty"`
}

type HttpAuthRequest struct {
	User     string `json:"user"`
	Password string `json:"password"`
}

type HttpAuthResponse struct {
	Result string     `json:"result,omitempty"`
	Labels api.Labels `json:"labels,omitempty"`
}

func (c *HttpAuthConfig) Validate() error {
	if c.Url == "" {
		return fmt.Errorf("http_url is not set")
	}
	return nil
}

type httpAuth struct {
	cfg        *HttpAuthConfig
	ctx        context.Context
	cancel     context.CancelFunc
	httpClient *http.Client
}

func NewHttpAuth(cfg *HttpAuthConfig) (*httpAuth, error) {
	glog.Infof("HTTP authenticator: %s", cfg.Url)
	for k, vals := range cfg.Headers {
		glog.V(2).Infof("HTTP authenticator header: %s=%v", k, vals)
	}

	// Create a context that can be cancelled when the authenticator is stopped
	ctx, cancel := context.WithCancel(context.Background())

	// Set default timeout if not set
	if cfg.HTTPTimeout <= 0 {
		cfg.HTTPTimeout = 15 * time.Second
	}
	transport := &http.Transport{
		DisableKeepAlives:   cfg.DisableKeepAlives,
		DisableCompression:  true,
		ForceAttemptHTTP2:   false,
		TLSHandshakeTimeout: cfg.HTTPTimeout,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: cfg.InsecureSkipVerify},
	}
	httpClient := &http.Client{
		Transport: transport,
		Timeout:   cfg.HTTPTimeout,
	}

	return &httpAuth{cfg: cfg, ctx: ctx, cancel: cancel, httpClient: httpClient}, nil
}

func (ha *httpAuth) Authenticate(user string, password api.PasswordString) (bool, api.Labels, error) {
	authReq := HttpAuthRequest{
		User:     user,
		Password: string(password),
	}

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(&authReq); err != nil {
		return false, nil, fmt.Errorf("failed to create JSON payload: %w", err)
	}
	req, err := http.NewRequestWithContext(ha.ctx, "POST", ha.cfg.Url, &buf)
	if err != nil {
		return false, nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	// Set custom headers
	for k, vals := range ha.cfg.Headers {
		for _, v := range vals {
			req.Header.Add(k, v)
		}
	}
	resp, err := ha.httpClient.Do(req)
	if err != nil {
		return false, nil, fmt.Errorf("http request failed: %w", err)
	}
	defer resp.Body.Close()
	// Process http errors
	if resp.StatusCode != http.StatusOK {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return false, nil, fmt.Errorf("error: HTTP server responded status code %d", resp.StatusCode)
		}
		// Limit error body size to avoid potential log flooding
		if len(body) > httpAuthMaxErrorBodyBytes {
			body = body[:httpAuthMaxErrorBodyBytes]
		}
		return false, nil, fmt.Errorf("error: HTTP server responded status code %d - %s", resp.StatusCode, body)
	}
	// Process response
	authResp := &HttpAuthResponse{}
	if err := json.NewDecoder(resp.Body).Decode(&authResp); err != nil {
		return false, nil, fmt.Errorf("invalid JSON in response body: %w", err)
	}
	switch authResp.Result {
	case httpAuthAllow:
		return true, authResp.Labels, nil
	case httpAuthDeny:
		return false, nil, nil
	case httpAuthFailed:
		return false, nil, api.WrongPass
	case httpAuthNoMatch:
		return false, nil, api.NoMatch
	default:
		return false, nil, fmt.Errorf("unexpected \"result\" value %q in JSON response; expected one of %q, %q, %q, %q", authResp.Result, httpAuthAllow, httpAuthDeny, httpAuthFailed, httpAuthNoMatch)
	}
}

func (ha *httpAuth) Stop() {
	ha.cancel()
}

func (ha *httpAuth) Name() string {
	return "http_auth"
}
