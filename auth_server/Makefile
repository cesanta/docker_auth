MAKEFLAGS += --warn-undefined-variables
IMAGE ?= cesanta/docker_auth
COMPRESS_BINARY ?= false
CA_BUNDLE = /etc/ssl/certs/ca-certificates.crt
VERSION = $(shell cat version.txt)

BUILDER_IMAGE ?= golang:1.15-alpine3.12

.PHONY: %

all: build

deps:
	go get -v github.com/go-bindata/go-bindata/...

generate:
	go generate \
	  github.com/cesanta/docker_auth/auth_server \
	  github.com/cesanta/docker_auth/auth_server/authn/... \
	  github.com/cesanta/docker_auth/auth_server/authz/... \
	  github.com/cesanta/docker_auth/auth_server/mgo_session/... \
	  github.com/cesanta/docker_auth/auth_server/server/...

build:
	CGO_ENABLED=0 go build -v --ldflags=--s

ca-certificates.crt:
	cp $(CA_BUNDLE) .

build-release: ca-certificates.crt
	docker run --rm -v $(PWD)/..:/src \
	  $(BUILDER_IMAGE) sh -x -c "\
	    apk update && apk add git make py3-pip && pip install GitPython && \
	    cd /src/auth_server && \
	    umask 0 && \
	    go install -v github.com/go-bindata/go-bindata && \
	    make generate && \
	    CGO_ENABLED=0 go build -v --ldflags=--s"
	@echo === Built version $$(cat version.txt) ===

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
