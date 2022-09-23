package server

import (
	"os"
	"testing"
)

func TestLoadConfig(t *testing.T) {

	conf, err := LoadConfig("../../examples/reference.yml", "AUTH")
	if err != nil {
		t.Error(err)
		return
	}
	if conf.Server.Net != "tcp" {
		t.Errorf("expected tcp, got %s", conf.Server.Net)
	}

}

func TestOverwritingConfig(t *testing.T) {
	os.Setenv("AUTH__SERVER__LETSENCRYPT__EMAIL", "test@email.com")

	conf, err := LoadConfig("../../examples/reference.yml", "AUTH")
	if err != nil {
		t.Error(err)
		return
	}
	if conf.Server.Net != "tcp" {
		t.Errorf("expected tcp, got %s", conf.Server.Net)
	}
	if conf.Server.LetsEncrypt.Email != "test@email.com" {
		t.Errorf("expected test@email.com, got %s", conf.Server.LetsEncrypt.Email)
	}
}

func TestOverwritingConfigWithUnderscore(t *testing.T) {
	os.Setenv("AUTH__SERVER__LETSENCRYPT__CACHE_DIR", "/cache/dir")

	conf, err := LoadConfig("../../examples/reference.yml", "AUTH")
	if err != nil {
		t.Error(err)
		return
	}
	if conf.Server.Net != "tcp" {
		t.Errorf("expected tcp, got %s", conf.Server.Net)
	}
	if conf.Server.LetsEncrypt.CacheDir != "/cache/dir" {
		t.Errorf("expected /cache/dir, got %s", conf.Server.LetsEncrypt.CacheDir)
	}
}
