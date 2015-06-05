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
	"crypto/tls"
	"flag"
	"math/rand"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cesanta/docker_auth/auth_server/server"
	"github.com/facebookgo/httpdown"
	"github.com/golang/glog"
	"github.com/howeyc/fsnotify"
)

type RestartableServer struct {
	cf string
	c  *server.Config
	hd *httpdown.HTTP
	as *server.AuthServer
	s  httpdown.Server
}

func ServeOnce(c *server.Config, cf string, hd *httpdown.HTTP) (*server.AuthServer, httpdown.Server) {
	glog.Infof("Config from %s (%d users, %d ACL entries)", cf, len(c.Users), len(c.ACL))
	as, err := server.NewAuthServer(c)
	if err != nil {
		glog.Exitf("Failed to create auth server: %s", err)
	}

	hs := &http.Server{
		Addr:    c.Server.ListenAddress,
		Handler: as,
		TLSConfig: &tls.Config{
			NextProtos:   []string{"http/1.1"},
			Certificates: make([]tls.Certificate, 1),
		},
	}

	glog.Infof("Cert file: %s", c.Server.CertFile)
	glog.Infof("Key file : %s", c.Server.KeyFile)
	hs.TLSConfig.Certificates[0], err = tls.LoadX509KeyPair(c.Server.CertFile, c.Server.KeyFile)
	if err != nil {
		glog.Exitf("Failed to load certificate and key: %s", err)
	}

	s, err := hd.ListenAndServe(hs)
	if err != nil {
		glog.Exitf("Failed to set up listener: %s", err)
	}
	glog.Infof("Serving")
	return as, s
}

func (rs *RestartableServer) Serve() {
	rs.as, rs.s = ServeOnce(rs.c, rs.cf, rs.hd)
	go rs.s.Wait()
	rs.WatchConfig()
}

func (rs *RestartableServer) WatchConfig() {
	w, err := fsnotify.NewWatcher()
	if err != nil {
		glog.Fatalf("Failed to create watcher: %s", err)
	}

	stopSignals := make(chan os.Signal, 1)
	signal.Notify(stopSignals, syscall.SIGTERM, syscall.SIGINT)

	err = w.WatchFlags(rs.cf, fsnotify.FSN_MODIFY|fsnotify.FSN_DELETE)
	watching, needRestart := (err == nil), false
	for {
		select {
		case <-time.After(1 * time.Second):
			if !watching {
				err = w.WatchFlags(rs.cf, fsnotify.FSN_MODIFY|fsnotify.FSN_DELETE)
				if err != nil {
					glog.Errorf("Failed to set up config watcher: %s", err)
				} else {
					watching, needRestart = true, true
				}
			} else if needRestart {
				rs.MaybeRestart()
				needRestart = false
			}
		case ev := <-w.Event:
			if ev.IsDelete() {
				glog.Warningf("Config file disappeared, serving continues")
				w.RemoveWatch(rs.cf)
				watching, needRestart = false, false
			} else {
				needRestart = true
			}
		case s := <-stopSignals:
			signal.Stop(stopSignals)
			glog.Infof("Signal: %s", s)
			rs.s.Stop()
			rs.as.Stop()
			glog.Exitf("Exiting")
		}
	}
	w.Close()
}

func (rs *RestartableServer) MaybeRestart() {
	glog.Infof("Restarting server")
	c, err := server.LoadConfig(rs.cf)
	if err != nil {
		glog.Errorf("Failed to reload config (server not restarted): %s", err)
		return
	}
	rs.c = c
	glog.Infof("New config loaded")
	rs.s.Stop()
	rs.as.Stop()
	rs.as, rs.s = ServeOnce(rs.c, rs.cf, rs.hd)
	go rs.s.Wait()
}

func main() {
	flag.Parse()
	rand.Seed(time.Now().UnixNano())
	glog.CopyStandardLogTo("INFO")

	cf := flag.Arg(0)
	if cf == "" {
		glog.Exitf("Config file not specified")
	}
	c, err := server.LoadConfig(cf)
	if err != nil {
		glog.Exitf("Failed to load config: %s", err)
	}
	rs := RestartableServer{
		c:  c,
		cf: cf,
		hd: &httpdown.HTTP{},
	}
	rs.Serve()
}
