package server

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/moby/moby/pkg/fileutils"
	"gopkg.in/yaml.v2"
)

func TestLoadConfig(t *testing.T) {
	conf, err := LoadConfig("../../examples/reference.yml", "AUTH")
	if err != nil {
		t.Error(err)
		return
	}

	dir, err := ioutil.TempDir("", "docker_auth_test")
	fname := filepath.Join(dir, "conf.yml")
	if err := fileutils.CreateIfNotExists(fname, false); err != nil {
		t.Fatal(err)
		return
	}

	f, err := os.OpenFile(fname, os.O_RDWR, 0666)
	if err != nil {
		t.Fatal(err)
		return
	}

	out, err := yaml.Marshal(conf)
	_, err = f.Write(out)
	if err != nil {
		t.Fatal(err)
		return
	}

	reconf, err := LoadConfig(f.Name(), "AUTH")
	if err != nil {
		t.Fatal(err)
		return
	}

	if !reflect.DeepEqual(conf, reconf) {
		t.Error("reloaded config is not same")
		return
	}
}
