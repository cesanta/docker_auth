.PHONY: update-deps build docker-build

all: docker-build

update-deps:
	go get -v -u -f github.com/jteeuwen/go-bindata/... .

build:
	go generate ./...
	go build

docker-build: update-deps build
	docker build -t cesanta/docker_auth -f Dockerfile .
