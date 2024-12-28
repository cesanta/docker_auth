FROM golang:1.23-alpine3.21 as build

ARG VERSION
ENV VERSION "${VERSION}"
ARG BUILD_ID
ENV BUILD_ID "${BUILD_ID}"
ARG CGO_EXTRA_CFLAGS

RUN apk add -U --no-cache ca-certificates make git gcc musl-dev binutils-gold

COPY . /build
WORKDIR /build
RUN make build

FROM alpine:3.21
COPY --from=build /build/auth_server /docker_auth/
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
ENTRYPOINT ["/docker_auth/auth_server"]
CMD ["/config/auth_config.yml"]
EXPOSE 5001
