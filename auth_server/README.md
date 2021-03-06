### Building local image

```
# copy ca certificate to /etc/ssl/certs/ca-certificates.crt
mkdir -p /var/tmp/go/src/github.com/cesanta
cd /var/tmp/go/src/github.com/cesanta
git clone https://github.com/cesanta/docker_auth.git
cd docker_auth/auth_server
export GOPATH=/var/tmp/go
export PATH=$PATH:$GOPATH/bin
# download dependencies
make deps
# build source
make generate
make
```
