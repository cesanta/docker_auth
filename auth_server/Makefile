image=cesanta/docker_auth
compress_binary=true
builder_image=centurylink/golang-builder
builder_image_extra-build-cross=-cross
builder_opts-docker-build=-v /var/run/docker.sock:/var/run/docker.sock

.PHONY: update-deps build-local build build-cross docker-build docker-push-% docker-tag-% docker-push

all: build
local: build-local

update-deps:
	go get -v -u -f github.com/jteeuwen/go-bindata/... .
	godep save

build-local: update-deps
	go generate ./...
	go build

build build-cross docker-build: update-deps
	docker run --rm -v $(PWD):/src -e COMPRESS_BINARY=$(compress_binary) $(builder_opts-$@) $(builder_image)$(builder_image_extra-$@) $(image)

docker-tag-%:
	docker tag -f $(image):latest $(image):$*

docker-push-%: docker-tag-%
	docker push $(image):$*

# Shortcut for latest
docker-push: docker-push-latest
