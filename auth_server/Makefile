MAKEFLAGS += --warn-undefined-variables
IMAGE ?= cesanta/docker_auth
VERSION ?= $(shell go run ./gen_version.go | awk '{print $$1}')
BUILD_ID ?= $(shell go run ./gen_version.go | awk '{print $$2}')

.PHONY: %

all: build

build:
	go build -v -ldflags="-extldflags '-static' -X 'main.Version=${VERSION}' -X 'main.BuildID=${BUILD_ID}'"

auth_server:
	@echo
	@echo Use build or build-release to produce the auth_server binary
	@echo
	@exit 1

docker-build:
	docker build --build-arg VERSION="${VERSION}" --build-arg BUILD_ID="${BUILD_ID}" -t $(IMAGE):latest .
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
