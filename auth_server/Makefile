.PHONY: update-deps build docker-build

all: docker-build

update-deps:
	go get -u -f

build:
	go build

docker-build: build
	docker build -t cesanta/docker_auth -f Dockerfile .
