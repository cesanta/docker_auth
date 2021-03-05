package authn

import (
	"os"
	"testing"

	"github.com/go-redis/redis"
)

func TestNewTokenDB(t *testing.T) {
	t.Run("LevelDB config", func(t *testing.T) {
		defer os.RemoveAll("testdata/example-db")
		cfg := TokenConfiguration{
			TokenDB: "testdata/example-db",
		}
		db, err := NewTokenDB(cfg)

		if err != nil {
			t.Fatalf("Expected no error from NewTokenDB(), got %s", err.Error())
		}
		defer db.Close()

		if _, ok := db.(*leveldbTokenDB); !ok {
			t.Fatalf("Unexpected underlying type for db, got %#v", db)
		}
		if db.String() != "testdata/example-db" {
			t.Fatalf("Expected db.String() to be %q, got %q", "testdata/example-db", db.String())
		}
	})

	t.Run("GCS config", func(t *testing.T) {
		cfg := TokenConfiguration{
			GCSTokenDB: &GCSTokenConfig{
				Bucket:           "bucket",
				ClientSecretFile: "testdata/gcs-credential-file.json",
			},
		}
		db, err := NewTokenDB(cfg)

		if err != nil {
			t.Fatalf("Expected no error from NewTokenDB(), got %s", err.Error())
		}
		defer db.Close()

		if _, ok := db.(*gcsTokenDB); !ok {
			t.Fatalf("Unexpected underlying type for db, got %#v", db)
		}
		if db.String() != "GCS: bucket" {
			t.Fatalf("Expected db.String() to be %q, got %q", "GCS: bucket", db.String())
		}
	})

	t.Run("Redis config", func(t *testing.T) {
		cfg := TokenConfiguration{
			RedisTokenDB: &RedisTokenConfig{
				ClientOptions: &redis.Options{
					Password: "rofl",
				},
			},
		}
		db, err := NewTokenDB(cfg)

		if err != nil {
			t.Fatalf("Expected no error from NewTokenDB(), got %s", err.Error())
		}
		defer db.Close()

		if _, ok := db.(*redisTokenDB); !ok {
			t.Fatalf("Unexpected underlying type for db, got %#v", db)
		}
		if db.String() != "Redis<localhost:6379 db:0>" {
			t.Fatalf("Expected db.String() to be %q, got %q", "Redis<localhost:6379 db:0>", db.String())
		}
	})
}
