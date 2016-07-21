package tokenstore

import (
	"errors"
)

var (
	ErrNotFound = errors.New("tokenstore: not found")
)

// TokenStore defines methods that a Token Store must implement
// for token key/value storage.
type TokenStore interface {
	String() string
	Get(key []byte) ([]byte, error)
	Put(key, value []byte) error
	Delete(key []byte) error
	Close() error
}
