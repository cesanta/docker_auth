package factory

import (
	"fmt"

	"github.com/golang/glog"

	"github.com/cesanta/docker_auth/auth_server/authn/tokenstore"
)

// tokenStoreFactories stores an internal mapping between token store names
// and their respective factories
var tokenStoreFactories = make(map[string]TokenStoreFactory)

type RawYAML struct {
	unmarshal func(interface{}) error
}

func (raw *RawYAML) UnmarshalYAML(unmarshal func(interface{}) error) error {
	raw.unmarshal = unmarshal
	return nil
}

func (raw *RawYAML) Unmarshal(v interface{}) error {
	if raw.unmarshal == nil {
		return fmt.Errorf("Token store has empty configuration")
	}
	return raw.unmarshal(v)
}

// TokenStoreFactory defines methods for implementing a Token Store factory.
type TokenStoreFactory interface {
	Create() (tokenstore.TokenStore, error)
}

// Register adds a factory to tokenStoreFactories
func Register(name string, factory TokenStoreFactory) {
	if factory == nil {
		glog.Fatalf("Nil factory provided for token store '%s'", name)
	}
	if _, exists := tokenStoreFactories[name]; exists {
		glog.Fatalf("Token store factory '%s' already exists", name)
	}
	tokenStoreFactories[name] = factory
}

// Create a new token store.
func Create(name string, params RawYAML) (tokenstore.TokenStore, error) {
	factory, exists := tokenStoreFactories[name]
	if !exists {
		return nil, fmt.Errorf("Token store factory '%s' not registered", name)
	}
	if err := params.Unmarshal(factory); err != nil {
		return nil, err
	}
	return factory.Create()
}
