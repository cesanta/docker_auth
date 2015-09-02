package leveldb

import (
	"fmt"

	"github.com/syndtr/goleveldb/leveldb"

	"github.com/cesanta/docker_auth/auth_server/authn/tokenstore"
	"github.com/cesanta/docker_auth/auth_server/authn/tokenstore/factory"
)

var StoreName = "leveldb"

func init() {
	factory.Register(StoreName, new(levelDbFactory))
}

// levelDbFactory implements factory.TokenStoreFactory for leveldb
type levelDbFactory string

func (factory *levelDbFactory) Create() (tokenstore.TokenStore, error) {
	path := fmt.Sprint(*factory)
	if path == "" {
		return nil, fmt.Errorf("%s: must provide a path string", StoreName)
	}
	db, err := leveldb.OpenFile(path, nil)
	if err != nil {
		return nil, err
	}

	return &store{
		Path: path,
		DB:   db,
	}, nil
}

type store struct {
	Path string
	DB   *leveldb.DB
}

func (s *store) String() string {
	return fmt.Sprintf("%s: %s", StoreName, s.Path)
}

func (s *store) Close() error {
	return s.DB.Close()
}

func (s *store) Get(key []byte) ([]byte, error) {
	value, err := s.DB.Get(key, nil)
	if err == leveldb.ErrNotFound {
		err = tokenstore.ErrNotFound
	}
	return value, err
}

func (s *store) Put(key, value []byte) error {
	return s.DB.Put(key, value, nil)
}

func (s *store) Delete(key []byte) error {
	return s.DB.Delete(key, nil)
}
