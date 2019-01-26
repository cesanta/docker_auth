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

package common

import (
	"crypto/tls"
	"crypto/x509"
	"net"

	"github.com/docker/libtrust"
)

type ServerConfig struct {
	ListenAddress string `yaml:"addr,omitempty"`
	PathPrefix    string `yaml:"path_prefix,omitempty"`
	RealIPHeader  string `yaml:"real_ip_header,omitempty"`
	RealIPPos     int    `yaml:"real_ip_pos,omitempty"`
	CertFile      string `yaml:"certificate,omitempty"`
	KeyFile       string `yaml:"key,omitempty"`

	PublicKey  libtrust.PublicKey
	PrivateKey libtrust.PrivateKey
}

type TokenConfig struct {
	Issuer     string `yaml:"issuer,omitempty"`
	CertFile   string `yaml:"certificate,omitempty"`
	KeyFile    string `yaml:"key,omitempty"`
	Expiration int64  `yaml:"expiration,omitempty"`

	PublicKey  libtrust.PublicKey
	PrivateKey libtrust.PrivateKey
}

type AuthRequest struct {
	RemoteConnAddr string
	RemoteAddr     string
	RemoteIP       net.IP
	User           string
	Password       PasswordString
	Account        string
	Service        string
	Scopes         []AuthScope
	Labels         Labels
}

type AuthScope struct {
	Type    string
	Name    string
	Actions []string
}

type AuthzResult struct {
	Scope            AuthScope
	AutorizedActions []string
}

func LoadCertAndKey(certFile, keyFile string) (pk libtrust.PublicKey, prk libtrust.PrivateKey, err error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return
	}
	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return
	}
	pk, err = libtrust.FromCryptoPublicKey(x509Cert.PublicKey)
	if err != nil {
		return
	}
	prk, err = libtrust.FromCryptoPrivateKey(cert.PrivateKey)
	return
}
