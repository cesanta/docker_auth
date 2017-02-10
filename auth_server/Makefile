#MAKEFLAGS += --warn-undefined-variables
#IMAGE ?= cesanta/docker_auth
#COMPRESS_BINARY ?= false
#CA_BUNDLE = /etc/ssl/certs/ca-certificates.crt
#VERSION = $(shell cat version.txt)
#
#BUILDER_IMAGE ?= centurylink/golang-builder
#BUILDER_IMAGE_EXTRA-build-cross = -cross
#BUILDER_OPTS-docker-build = -v /var/run/docker.sock:/var/run/docker.sock
#BUILDER_IMAGE_EXTRA-docker-build =
#
#.PHONY: %
#
#all: build
#local: build-local
#
#update-deps:
#	go get -v -u -f github.com/tools/godep github.com/jteeuwen/go-bindata/...
#	go generate ./...
#
#godep:
#	godep save
#
#build-local: update-deps
#	go build
#
#ca-certificates.crt:
#	cp $(CA_BUNDLE) .
#
#docker-build:
#	go generate ./...
#	docker run --rm -v $(PWD):/src -e COMPRESS_BINARY=$(COMPRESS_BINARY) $(BUILDER_OPTS-$@) $(BUILDER_IMAGE)$(BUILDER_IMAGE_EXTRA-$@) $(IMAGE)
#	@echo === Built version $(VERSION) ===
#
#build build-cross: update-deps godep ca-certificates.crt docker-build
#
#docker-tag:
#	docker tag $(IMAGE):latest $(IMAGE):$(VERSION)
#
#docker-tag-%:
#	docker tag $(IMAGE):latest $(IMAGE):$*
#
#docker-push:
#	docker push $(IMAGE):$(VERSION)
#
#docker-push-%: docker-tag-%
#	docker push $(IMAGE):$*
#
## Shortcut for latest
#docker-push: docker-push-latest

# BINARY_NAME defaults to the name of the repository
BINARY_NAME := docker_auth
LIST_NO_VENDOR := $(go list ./... | grep -v /vendor/)
GOBIN := $(GOPATH)/bin

default: check fmt deps test build

.PHONY: build
build:
	# Build project
	go build -a -o $(BINARY_NAME) .

.PHONY: check
check:
	# Only continue if go is installed
	go version || ( echo "Go not installed, exiting"; exit 1 )

.PHONY: clean
clean:
	go clean -i
	rm -rf ./vendor/*/
	rm -f $(BINARY_NAME)

deps:
	# Install or update govend
	go get -u github.com/govend/govend
	# Fetch vendored dependencies
	$(GOBIN)/govend -v

.PHONY: fmt
fmt:
	# Format all Go source files (excluding vendored packages)
	go fmt $(LIST_NO_VENDOR)

generate-deps:
	# Generate vendor.yml
	govend -v -l
	git checkout vendor/.gitignore

.PHONY: test
test:
	# Run all tests (excluding vendored packages)
	go test -a -v $(LIST_NO_VENDOR)
