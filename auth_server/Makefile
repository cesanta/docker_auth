BINARY_NAME := docker_auth
BUILD_INFO_FLAGS := -X main.BuildTime=$(shell date -u '+%Y-%m-%d_%H:%M:%S') -X main.BuildCommitHash=$(shell git rev-parse HEAD)
GOBIN := $(GOPATH)/bin
LIST_NO_VENDOR := $(go list ./... | grep -v /vendor/)
OSX_BUILD_FLAGS := -s
STATIC_BUILD_FLAGS := -linkmode external -extldflags -static -w

# `make` -- run in wercker (golang image uses Debian)
default: check fmt deps test build.static

# `make dev` / `make osx` -- run when doing local development (on OSX)
dev: osx
osx: check fmt deps test.osx build

# `make alpine` / `make docker` -- run when building an Alpine-based Docker image
docker: alpine
alpine: check fmt deps test.nocover build.static

.PHONY: build
build:
	# Build project
	go build -ldflags "$(BUILD_INFO_FLAGS) $(OSX_BUILD_FLAGS)" -a -o $(BINARY_NAME) .

.PHONY: build.static
build.static:
	# Build statically linked binary
	go build -ldflags "$(BUILD_INFO_FLAGS) $(STATIC_BUILD_FLAGS)" -a -o $(BINARY_NAME) .

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
	# Run all tests, with coverage (excluding vendored packages)
	go test -a -v -cover $(LIST_NO_VENDOR)

.PHONY: test.osx
test.osx:
	# Run all tests, with coverage (excluding vendored packages)
	go test -a -v -cover $(LIST_NO_VENDOR) -ldflags "$(OSX_BUILD_FLAGS)"

.PHONY: test.nocover
test.nocover:
	# Run all tests (excluding vendored packages)
	go test -a -v $(LIST_NO_VENDOR)
