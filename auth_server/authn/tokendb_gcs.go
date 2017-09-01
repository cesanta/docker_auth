/*
   Copyright 2017 Cesanta Software Ltd.

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
package authn

import (
	"encoding/json"
	"fmt"
	"time"

	"cloud.google.com/go/storage"
	"github.com/cesanta/glog"
	"github.com/dchest/uniuri"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/net/context"
	"google.golang.org/api/option"
)

// NewGCSTokenDB return a new TokenDB structure which uses Google Cloud Storage as backend. The
// created DB uses file-per-user strategy and stores credentials independently for each user.
//
// Note: it's not recomanded bucket to be shared with other apps or services
func NewGCSTokenDB(bucket, clientSecretFile string) (TokenDB, error) {
	gcs, err := storage.NewClient(context.Background(), option.WithServiceAccountFile(clientSecretFile))
	return &gcsTokenDB{gcs, bucket}, err
}

type gcsTokenDB struct {
	gcs    *storage.Client
	bucket string
}

// GetValue gets token value associated with the provided user. Each user
// in the bucket is having it's own file for tokens and it's recomanded bucket
// to not be shared with other apps
func (db *gcsTokenDB) GetValue(user string) (*TokenDBValue, error) {
	rd, err := db.gcs.Bucket(db.bucket).Object(user).NewReader(context.Background())
	if err == storage.ErrObjectNotExist {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("could not retrieved token for user '%s' due: %v", user, err)
	}
	defer rd.Close()

	var dbv TokenDBValue
	if err := json.NewDecoder(rd).Decode(&dbv); err != nil {
		glog.Errorf("bad DB value for %q: %v", user, err)
		return nil, fmt.Errorf("could not read token for user '%s' due: %v", user, err)
	}

	return &dbv, nil
}

// StoreToken stores token in the GCS file in a JSON format. Note that separate file is
// used for each user
func (db *gcsTokenDB) StoreToken(user string, v *TokenDBValue, updatePassword bool) (dp string, err error) {
	if updatePassword {
		dp = uniuri.New()
		dph, _ := bcrypt.GenerateFromPassword([]byte(dp), bcrypt.DefaultCost)
		v.DockerPassword = string(dph)
	}

	wr := db.gcs.Bucket(db.bucket).Object(user).NewWriter(context.Background())

	if err := json.NewEncoder(wr).Encode(v); err != nil {
		glog.Errorf("failed to set token data for %s: %s", user, err)
		return "", fmt.Errorf("failed to set token data for %s due: %v", user, err)
	}

	err = wr.Close()
	return
}

// ValidateToken verifies whether the provided token passed as password field
// is still valid, e.g available and not expired
func (db *gcsTokenDB) ValidateToken(user string, password PasswordString) error {
	dbv, err := db.GetValue(user)
	if err != nil {
		return err
	}
	if dbv == nil {
		return NoMatch
	}

	if bcrypt.CompareHashAndPassword([]byte(dbv.DockerPassword), []byte(password)) != nil {
		return WrongPass
	}
	if time.Now().After(dbv.ValidUntil) {
		return ExpiredToken
	}

	return nil
}

// DeleteToken deletes the GCS file that is associated with the provided user.
func (db *gcsTokenDB) DeleteToken(user string) error {
	ctx := context.Background()
	err := db.gcs.Bucket(db.bucket).Object(user).Delete(ctx)
	if err == storage.ErrObjectNotExist {
		return nil
	}
	return err
}

// Close is a nop operation for this db
func (db *gcsTokenDB) Close() error {
	return nil
}
