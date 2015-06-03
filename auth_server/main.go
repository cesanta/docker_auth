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
	"flag"
	"math/rand"
	"net/http"
	"time"

	"github.com/cesanta/docker_auth/auth_server/server"
	"github.com/golang/glog"
)

func main() {
	flag.Parse()
	rand.Seed(time.Now().UnixNano())

	configFile := flag.Arg(0)
	if configFile == "" {
		glog.Exitf("Config file not specified")
	}
	config, err := server.LoadConfig(configFile)
	if err != nil {
		glog.Exitf("Failed to load config: %s", err)
	}
	glog.Infof("Config from %s (%d users, %d ACL entries)", configFile, len(config.Users), len(config.ACL))

	s, err := server.NewAuthServer(config)
	if err != nil {
		glog.Exitf("Failed to create auth server: %s", err)
	}

	sc := &config.Server
	glog.Infof("Listening on %s", sc.ListenAddress)
	err = http.ListenAndServeTLS(sc.ListenAddress, sc.CertFile, sc.KeyFile, s)
	if err != nil {
		glog.Exitf("Failed to set up server: %s", err)
	}
}
