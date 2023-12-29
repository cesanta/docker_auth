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

package main

import (
	"context"
	"crypto/tls"
	"flag"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/cesanta/glog"
	"golang.org/x/crypto/acme/autocert"
	fsnotify "gopkg.in/fsnotify.v1"

	"github.com/cesanta/docker_auth/auth_server/server"
)

var (
	// Version comment
	Version = ""
	// BuildID comment
	BuildID = ""
)

type RestartableServer struct {
	configFile string
	authServer *server.AuthServer
	hs         *http.Server
}

func stringToUint16(s string) uint16 {
	v, err := strconv.ParseUint(s, 0, 16)
	if err != nil {
		glog.Exitf("Failed to convert %s to uint16", s)
	}
	return uint16(v)
}

func ServeOnce(c *server.Config, cf string) (*server.AuthServer, *http.Server) {
	glog.Infof("Config from %s (%d users, %d ACL static entries)", cf, len(c.Users), len(c.ACL))
	as, err := server.NewAuthServer(c)
	if err != nil {
		glog.Exitf("Failed to create auth server: %s", err)
	}

	tlsConfig := &tls.Config{}
	if c.Server.HSTS {
		glog.Info("HTTP Strict Transport Security enabled")
	}
	if c.Server.TLSMinVersion != "" {
		value, found := server.TLSVersionValues[c.Server.TLSMinVersion]
		if !found {
			value = stringToUint16(c.Server.TLSMinVersion)
		}
		tlsConfig.MinVersion = value
		glog.Infof("TLS MinVersion: %s", c.Server.TLSMinVersion)
	}
	if c.Server.TLSCurvePreferences != nil {
		var values []tls.CurveID
		for _, s := range c.Server.TLSCurvePreferences {
			value, found := server.TLSCurveIDValues[s]
			if !found {
				value = tls.CurveID(stringToUint16(s))
			}
			values = append(values, value)
		}
		tlsConfig.CurvePreferences = values
		glog.Infof("TLS CurvePreferences: %s", c.Server.TLSCurvePreferences)
	}
	if c.Server.TLSCipherSuites != nil {
		var values []uint16
		for _, s := range c.Server.TLSCipherSuites {
			value, found := server.TLSCipherSuitesValues[s]
			if !found {
				value = stringToUint16(s)
			}
			values = append(values, value)
		}
		tlsConfig.CipherSuites = values
		glog.Infof("TLS CipherSuites: %s", c.Server.TLSCipherSuites)
	} else {
		for _, s := range tls.CipherSuites() {
			tlsConfig.CipherSuites = append(tlsConfig.CipherSuites, s.ID)
		}
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
			Cache:  autocert.DirCache(c.Server.LetsEncrypt.CacheDir),
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

	var listener net.Listener
	if c.Server.Net == "unix" {
		// Remove socket, if exists
		if _, err := os.Stat(c.Server.ListenAddress); err == nil {
			if err := os.Remove(c.Server.ListenAddress); err != nil {
				glog.Fatal(err.Error())
			}
		}
		listener, err = net.Listen("unix", c.Server.ListenAddress)
		if err != nil {
			glog.Fatal(err.Error())
		}
	} else {
		listener, err = net.Listen("tcp", c.Server.ListenAddress)
		if err != nil {
			glog.Fatal(err.Error())
		}
	}

	go func() {
		if c.Server.CertFile == "" && c.Server.KeyFile == "" {
			if err := hs.Serve(listener); err != nil {
				if err == http.ErrServerClosed {
					return
				}
			}
		} else {
			if err := hs.ServeTLS(listener, c.Server.CertFile, c.Server.KeyFile); err != nil {
				if err == http.ErrServerClosed {
					return
				}
			}
		}
	}()
	glog.Infof("Serving on %s", c.Server.ListenAddress)
	return as, hs
}

func (rs *RestartableServer) Serve(c *server.Config) {
	rs.authServer, rs.hs = ServeOnce(c, rs.configFile)
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
			if err := rs.hs.Shutdown(context.Background()); err != nil {
				glog.Errorf("HTTP server Shutdown: %v", err)
			}
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
	rs.hs.Close()
	rs.authServer.Stop()
	rs.authServer, rs.hs = ServeOnce(c, rs.configFile)
}

func main() {
	flag.Parse()
	rand.Seed(time.Now().UnixNano())
	glog.CopyStandardLogTo("INFO")

	glog.Infof("docker_auth %s build %s", Version, BuildID)

	cf := flag.Arg(0)
	if cf == "" {
		glog.Exitf("Config file not specified")
	}
	config, err := server.LoadConfig(cf)
	if err != nil {
		glog.Exitf("Failed to load config: %s", err)
	}
	rs := RestartableServer{
		configFile: cf,
	}
	rs.Serve(config)
}
