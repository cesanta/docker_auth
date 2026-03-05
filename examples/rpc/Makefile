GO ?= go

PKI_EXPIRATION ?= 90
PKI_COUNTRY ?= XX
PKI_STATE ?= StateName
PKI_LOCATION ?= CityName
PKI_ORGANIZATION ?= CompanyName
PKI_SECTION ?= CompanySectionName
PKI_SUBJECT ?= CommonNameOrHostname

.PHONY: default
default: all

.PHONY: all
all: build

.PHONY: serve
serve: ../../auth_server/auth_server auth_server.yml pki build
	$< auth_server.yml

../../auth_server/auth_server:
	$(MAKE) -C $(dir $@) build

target/issuer.crt.pem: target/issuer.key.pem
	mkdir -p $(dir $@)
	openssl req -new -x509 -key $< -out $@ -days $(PKI_EXPIRATION) \
	  -nodes -subj "/C=$(PKI_COUNTRY)/ST=$(PKI_STATE)/L=$(PKI_LOCATION)/O=$(PKI_ORGANIZATION)/OU=$(PKI_SECTION)/CN=$(PKI_SUBJECT)"

target/issuer.key.pem:
	mkdir -p $(dir $@)
	openssl genrsa -out $@ 3072

target/%:
	cd $*; $(GO) build -v \
	  -ldflags="-extldflags '-static' $(GOLDFLAGS)" \
	  -o $(abspath $@)

.PHONY: server
server: ../../auth_server/auth_server

.PHONY: pki
pki: target/issuer.crt.pem target/issuer.key.pem

.PHONY: build
build: target/authn target/authz

.PHONY: clean
clean:
	$(RM) target
