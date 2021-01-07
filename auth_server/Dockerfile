ARG BASE_IMAGE=scratch

#################################################################
####                         Stage 1                         ####
#################################################################

FROM golang:1.15-alpine AS build-env
RUN apk --no-cache add git make py3-pip && \
    pip3 install gitpython
RUN apk add --no-cache gcc musl-dev
COPY . /go/src/app/auth_server
WORKDIR /go/src/app/auth_server/


RUN make deps

RUN make generate

RUN make


#################################################################
####                         Stage 2                         ####
#################################################################

FROM ${BASE_IMAGE}

WORKDIR /app/
COPY --from=build-env /go/src/app/auth_server /app/
EXPOSE 5001
ENTRYPOINT ["/app/auth_server"]
CMD ["/config/auth_config.yml"]
