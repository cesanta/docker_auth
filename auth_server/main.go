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

//go:generate ./gen_version.py

package main // import "github.com/cesanta/docker_auth/auth_server"

import (
	"crypto/tls"
	"flag"
	"math/rand"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cesanta/docker_auth/auth_server/server"
	"github.com/cesanta/glog"
	"github.com/facebookgo/httpdown"
	"golang.org/x/crypto/acme/autocert"
	fsnotify "gopkg.in/fsnotify.v1"
)

type RestartableServer struct {
	configFile string
	hd         *httpdown.HTTP
	authServer *server.AuthServer
	hs         httpdown.Server
}

func ServeOnce(c *server.Config, cf string, hd *httpdown.HTTP) (*server.AuthServer, httpdown.Server) {
	glog.Infof("Config from %s (%d users, %d ACL static entries)", cf, len(c.Users), len(c.ACL))
	as, err := server.NewAuthServer(c)
	if err != nil {
		glog.Exitf("Failed to create auth server: %s", err)
	}

	tlsConfig := &tls.Config{
		MinVersion:               tls.VersionTLS10,
		PreferServerCipherSuites: true,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		},
		NextProtos: []string{"http/1.1"},
	}
	if c.Server.CertFile != "" || c.Server.KeyFile != "" {
		// Check for partial configuration.
		if c.Server.CertFile == "" || c.Server.KeyFile == "" {
			glog.Exitf("Failed to load certificate and key: both were not provided")
		}
		glog.Infof("Cert file: %s", c.Server.CertFile)
		glog.Infof("Key file : %s", c.Server.KeyFile)
		tlsConfig.Certificates = make([]tls.Certificate, 1)
		tlsConfig.Certificates[0], err = tls.LoadX509KeyPair(c.Server.CertFile, c.Server.KeyFile)
		if err != nil {
			glog.Exitf("Failed to load certificate and key: %s", err)
		}
	} else if c.Server.LetsEncrypt.Email != "" {
		m := &autocert.Manager{
			Email:  c.Server.LetsEncrypt.Email,
			Prompt: autocert.AcceptTOS,
		}
		if c.Server.LetsEncrypt.Host != "" {
			m.HostPolicy = autocert.HostWhitelist(c.Server.LetsEncrypt.Host)
		}
		glog.Infof("Using LetsEncrypt, host %q, email %q", c.Server.LetsEncrypt.Host, c.Server.LetsEncrypt.Email)
		tlsConfig.GetCertificate = m.GetCertificate
	} else {
		glog.Warning("Running without TLS")
		tlsConfig = nil
	}
	hs := &http.Server{
		Addr:      c.Server.ListenAddress,
		Handler:   as,
		TLSConfig: tlsConfig,
	}

	s, err := hd.ListenAndServe(hs)
	if err != nil {
		glog.Exitf("Failed to set up listener: %s", err)
	}
	glog.Infof("Serving on %s", c.Server.ListenAddress)
	return as, s
}

func (rs *RestartableServer) Serve(c *server.Config) {
	rs.authServer, rs.hs = ServeOnce(c, rs.configFile, rs.hd)
	rs.WatchConfig()
}

func (rs *RestartableServer) WatchConfig() {
	w, err := fsnotify.NewWatcher()
	if err != nil {
		glog.Fatalf("Failed to create watcher: %s", err)
	}
	defer w.Close()

	stopSignals := make(chan os.Signal, 1)
	signal.Notify(stopSignals, syscall.SIGTERM, syscall.SIGINT)

	err = w.Add(rs.configFile)
	watching, needRestart := (err == nil), false
	for {
		select {
		case <-time.After(1 * time.Second):
			if !watching {
				err = w.Add(rs.configFile)
				if err != nil {
					glog.Errorf("Failed to set up config watcher: %s", err)
				} else {
					watching, needRestart = true, true
				}
			} else if needRestart {
				rs.MaybeRestart()
				needRestart = false
			}
		case ev := <-w.Events:
			if ev.Op == fsnotify.Remove {
				glog.Warningf("Config file disappeared, serving continues")
				w.Remove(rs.configFile)
				watching, needRestart = false, false
			} else if ev.Op == fsnotify.Write {
				needRestart = true
			}
		case s := <-stopSignals:
			signal.Stop(stopSignals)
			glog.Infof("Signal: %s", s)
			rs.hs.Stop()
			rs.authServer.Stop()
			glog.Exitf("Exiting")
		}
	}
}

func (rs *RestartableServer) MaybeRestart() {
	glog.Infof("Validating new config")
	c, err := server.LoadConfig(rs.configFile)
	if err != nil {
		glog.Errorf("Failed to reload config (server not restarted): %s", err)
		return
	}
	glog.Infof("Config ok, restarting server")
	rs.hs.Stop()
	rs.authServer.Stop()
	rs.authServer, rs.hs = ServeOnce(c, rs.configFile, rs.hd)
}

func main() {
	flag.Parse()
	rand.Seed(time.Now().UnixNano())
	glog.CopyStandardLogTo("INFO")

	glog.Infof("docker_auth %s build %s", Version, BuildId)

	cf := flag.Arg(0)
	if cf == "" {
		glog.Exitf("Config file not specified")
	}
	c, err := server.LoadConfig(cf)
	if err != nil {
		glog.Exitf("Failed to load config: %s", err)
	}
	rs := RestartableServer{
		configFile: cf,
		hd:         &httpdown.HTTP{},
	}
	rs.Serve(c)
}
