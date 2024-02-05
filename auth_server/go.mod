module github.com/cesanta/docker_auth/auth_server

go 1.16

require (
	cloud.google.com/go/storage v1.29.0
	github.com/casbin/casbin/v2 v2.55.1
	github.com/cesanta/glog v0.0.0-20150527111657-22eb27a0ae19
	github.com/coreos/go-oidc/v3 v3.9.0
	github.com/dchest/uniuri v0.0.0-20220929095258-3027df40b6ce
	github.com/deckarep/golang-set v1.8.0
	github.com/docker/distribution v2.8.1+incompatible
	github.com/docker/libtrust v0.0.0-20160708172513-aabc10ec26b7
	github.com/go-ldap/ldap v3.0.3+incompatible
	github.com/go-redis/redis v6.15.9+incompatible
	github.com/go-sql-driver/mysql v1.6.0
	github.com/gorilla/mux v1.8.0 // indirect
	github.com/klauspost/compress v1.15.11 // indirect
	github.com/lib/pq v1.10.7
	github.com/mattn/go-sqlite3 v2.0.3+incompatible
	github.com/montanaflynn/stats v0.6.6 // indirect
	github.com/schwarmco/go-cartesian-product v0.0.0-20180515110546-d5ee747a6dc9
	github.com/sirupsen/logrus v1.9.0 // indirect
	github.com/syndtr/goleveldb v1.0.0
	github.com/youmark/pkcs8 v0.0.0-20201027041543-1326539a0a0a // indirect
	go.mongodb.org/mongo-driver v1.10.2
	golang.org/x/crypto v0.14.0
	golang.org/x/net v0.17.0
	golang.org/x/oauth2 v0.13.0
	google.golang.org/api v0.126.0
	gopkg.in/asn1-ber.v1 v1.0.0-20181015200546-f715ec2f112d // indirect
	gopkg.in/fsnotify.v1 v1.4.7
	gopkg.in/mgo.v2 v2.0.0-20190816093944-a6b53ec6cb22
	gopkg.in/yaml.v2 v2.4.0
	xorm.io/builder v0.3.12 // indirect
	xorm.io/xorm v1.3.2
)
