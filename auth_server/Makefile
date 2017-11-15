MAKEFLAGS += --warn-undefined-variables
IMAGE ?= cesanta/docker_auth
COMPRESS_BINARY ?= false
CA_BUNDLE = /etc/ssl/certs/ca-certificates.crt
VERSION = $(shell cat version.txt)

BUILDER_IMAGE ?= golang:1.8.0-alpine

.PHONY: %

all: build

deps:
	go get -v -u github.com/kardianos/govendor
	govendor sync
	go install -v github.com/cesanta/docker_auth/auth_server/vendor/github.com/jteeuwen/go-bindata/go-bindata

generate:
	go generate \
	  github.com/cesanta/docker_auth/auth_server \
	  github.com/cesanta/docker_auth/auth_server/authn/... \
	  github.com/cesanta/docker_auth/auth_server/authz/... \
	  github.com/cesanta/docker_auth/auth_server/mgo_session/... \
	  github.com/cesanta/docker_auth/auth_server/server/...

build:
	CGO_ENABLED=0 go build -v -i --ldflags=--s

ca-certificates.crt:
	cp $(CA_BUNDLE) .

build-release: ca-certificates.crt
	docker run --rm -v $(PWD)/..:/go/src/github.com/cesanta/docker_auth \
	  $(BUILDER_IMAGE) sh -x -c "\
	    apk update && apk add git make py2-pip && pip install GitPython && \
	    cd /go/src/github.com/cesanta/docker_auth/auth_server && \
	    go get -v -u github.com/kardianos/govendor && \
	    umask 0 && govendor sync -v && \
	    go install -v github.com/cesanta/docker_auth/auth_server/vendor/github.com/jteeuwen/go-bindata/go-bindata && \
	    make generate && \
	    CGO_ENABLED=0 go build -v -i --ldflags=--s"
	@echo === Built version $(VERSION) ===

auth_server:
	@echo
	@echo Use build or build-release to produce the auth_server binary
	@echo
	@exit 1

docker-build:
	docker build -t $(IMAGE):latest .
	docker tag $(IMAGE):latest $(IMAGE):$(VERSION)

docker-tag-%:
	docker tag $(IMAGE):latest $(IMAGE):$*

docker-push:
	docker push $(IMAGE):latest
	docker push $(IMAGE):$(VERSION)

docker-push-%: docker-tag-%
	docker push $(IMAGE):$*

clean:
	rm -rf auth_server vendor/*/*
