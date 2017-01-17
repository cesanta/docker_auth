FROM alpine:3.5
RUN apk update && apk add curl
ADD auth_server /docker_auth/
COPY ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
ENTRYPOINT ["/docker_auth/auth_server"]
CMD ["/config/auth_config.yml"]
EXPOSE 5001
