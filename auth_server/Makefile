MAKEFLAGS += --warn-undefined-variables
IMAGE ?= us.gcr.io/ai-blt/docker-auth
COMPRESS_BINARY ?= false
CA_BUNDLE = /etc/ssl/certs/ca-certificates.crt
VERSION = $(shell cat version.txt)

BUILDER_IMAGE ?= centurylink/golang-builder
BUILDER_IMAGE_EXTRA-build-cross = -cross
BUILDER_OPTS-docker-build = -v /var/run/docker.sock:/var/run/docker.sock
BUILDER_IMAGE_EXTRA-docker-build =

.PHONY: %

all: build
local: build-local

update-deps:
	go get -v -u -f github.com/tools/godep github.com/jteeuwen/go-bindata/...
	go generate ./...

godep:
	godep save

build-local: update-deps
	go build

ca-certificates.crt:
	cp $(CA_BUNDLE) .

docker-build:
	go generate ./...
	docker run --rm -v $(PWD):/src -e COMPRESS_BINARY=$(COMPRESS_BINARY) $(BUILDER_OPTS-$@) $(BUILDER_IMAGE)$(BUILDER_IMAGE_EXTRA-$@) $(IMAGE)
	@echo === Built version $(VERSION) ===

build build-cross: update-deps godep ca-certificates.crt docker-build

docker-tag:
	docker tag $(IMAGE):latest $(IMAGE):$(VERSION)

docker-tag-%:
	docker tag $(IMAGE):latest $(IMAGE):$*

docker-push:
	docker push $(IMAGE):$(VERSION)

docker-push-%: docker-tag-%
	docker push $(IMAGE):$*

# Shortcut for latest
docker-push: docker-push-latest
