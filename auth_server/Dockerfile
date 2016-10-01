FROM golang
EXPOSE 5001
ENTRYPOINT ["/auth_server"]
CMD ["/config/auth_config.yml"]
COPY ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY auth_server .
