.PHONY: update-deps build docker-build

all: build

update-deps:
	go get -v -u -f github.com/jteeuwen/go-bindata/... .

build:
	go generate ./...
	go build

docker-build: update-deps build
	docker build -t cesanta/docker_auth -f Dockerfile .

docker-push-latest:
	docker push cesanta/docker_auth:latest

docker-push-stable:
	docker tag -f cesanta/docker_auth:latest cesanta/docker_auth:stable
	docker push cesanta/docker_auth:stable
