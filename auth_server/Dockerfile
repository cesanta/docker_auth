FROM alpine:3.5

ARG GITHUB_TOKEN

ADD . /go/src/github.com/veritone/docker_auth/auth_server

RUN echo http://nl.alpinelinux.org/alpine/edge/community >> /etc/apk/repositories && \
    apk update && \
    apk add -U build-base file go git bash curl libstdc++ && \
    cd /go/src/github.com/veritone/docker_auth/auth_server && \
    git config --global url."https://${GITHUB_TOKEN}:x-oauth-basic@github.com/".insteadOf "https://github.com/" && \
    GOPATH=/go make && \
    apk del build-base go file git

EXPOSE 5001

ENTRYPOINT /go/src/github.com/veritone/docker_auth/auth_server/docker_auth
