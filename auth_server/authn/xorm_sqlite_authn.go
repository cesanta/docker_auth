// +build sqlite
package authn

import (
	_ "github.com/mattn/go-sqlite3"
)

func init() {
	EnableSQLite3 = true
}
