### Building local image

```
git clone https://github.com/cesanta/docker_auth.git
cd docker_auth/auth_server
# copy ca certificate to /etc/ssl/certs/ca-certificates.crt
pip install gitpython
mkdir /var/tmp/go
export GOPATH=/var/tmp/go
export PATH=$PATH:$GOPATH/bin
make
```
