IMAGE=cesanta/docker_auth

.PHONY: update-deps build docker-build

all: build

update-deps:
	go get -v -u -f github.com/jteeuwen/go-bindata/... .

build:
	go generate ./...
	go build

docker-build: update-deps build
	docker build -t $(IMAGE) -f Dockerfile .

docker-push-latest:
	docker push $(IMAGE)

docker-push-stable:
	docker tag -f $(IMAGE):latest $(IMAGE):stable
	docker push $(IMAGE):stable
