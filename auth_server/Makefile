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
