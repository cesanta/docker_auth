Helm Chart for docker_auth
=======================

**This is a fork of <https://github.com/cesanta/docker_auth> with support for token based authentication using a token server (specified by Docker's [Token Authentication Specification](https://docs.docker.com/registry/spec/auth/token/)).**

Open issues:
- Add this chart to helm hub (cf. [Guidelines for Repository Inclusion](https://github.com/helm/hub/blob/master/Repositories.md))

## Introduction

This [Helm](https://github.com/kubernetes/helm) chart installs a private Docker registry with token based authentication and support for authorization in a Kubernetes cluster. 

Is uses
- [docker-registry](https://github.com/helm/charts/tree/master/stable/docker-registry) for running a Docker registry
- [docker_auth](https://github.com/cesanta/docker_auth) for providing token based authentication

## Installation

Install the docker-auth helm chart:

Add repository to helm

```bash
helm repo add pfisterer-docker-auth https://pfisterer.github.io/docker_auth/
helm repo update
```

Installation: 

```bash
helm dependency update
helm install --name=docker-auth pfisterer-docker-auth/docker_auth
```

To delete the `my-release` deployment, run:

```bash
helm delete --purge docker-auth
```

## Configuration

The following table lists the configurable parameters of the docker-auth chart and the default values.

| Parameter                         | Description                                                                                                                                                                                                                                            | Default                |
| --------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ---------------------- |
| **Docker Registry**               |                                                                                                                                                                                                                                                        |                        |
| `registry.enabled`                | Deploy an instance of the docker registry                                                                                                                                                                                                              | `false`                |
| **Secret**                        |
| `secret.data.server.certificate`  | Content of server.pem  (mutually exclusive with secretName, keyName, certificateName)                                                                                                                                                                  |                        |
| `secret.data.server.key`          | Content of server.key  (mutually exclusive with secretName, keyName, certificateName)                                                                                                                                                                  |                        |
| `secret.secretName`               | The name of the secret containing server key and certificate (mutually exclusive with secret.data.server.key/certificate)                                                                                                                              |                        |
| `secret.certificateFileName`      | The name of the server certificate file (mutually exclusive with secret.data.server.key/certificate)                                                                                                                                                   | tls.crt                |
| `secret.keyFileName`              | The name of the server key file (mutually exclusive with secret.data.server.key/certificate)                                                                                                                                                           | tls.key                |
| **Configmap**                     |
| `configmap.data.token.issuer`     | Must match issuer in the Registry config                                                                                                                                                                                                               | `Acme auth server`     |
| `configmap.data.token.expiration` | Token Expiration                                                                                                                                                                                                                                       | `900`                  |
| `configmap.data.users`            | Static user map                                                                                                                                                                                                                                        |                        |
| `configmap.data.acl`              | ACL specifies who can do what. If the match section of an entry matches the request, the set of allowed actions will be applied to the token request and a ticket will be issued only for those of the requested actions that are allowed by the rule. |                        |
| **ingress**                       |
| `ingress.hosts.host`              | Domain to your `docker_auth` installation                                                                                                                                                                                                              | `docker-auth.test.com` |
| **High Available**                |
| `replicaCount`                    | Replica count for High Available                                                                                                                                                                                                                       | `1`                    |

## Generate certificates

Replace the parameter to `-subj` with sensible values for your deployment. The value of `CN=` must be supplied to `docker-registry.configData.auth.token.issuer` (see below).

```bash
openssl req -new -newkey rsa:4096 -days 5000 -nodes -x509 \
    -subj "/C=DE/ST=BW/L=Mannheim/O=ACME/CN=docker-auth" \
    -keyout generated-docker-auth-server.key \
    -out generated-docker-auth-server.pem

CERT_PEM_BASE64=`cat generated-docker-auth-server.pem | base64`
CERT_KEY_BASE64=`cat generated-docker-auth-server.key | base64`
```

## Users

Generate a password for your user using `htpasswd`
```bash
PWGEN_USER="admin"
PWGEN=`pwgen -N 1 -B 10 | tr -d '\n'`
PWGEN_HTPASSWD_LINE=`htpasswd -Bbn $PWGEN_USER $PWGEN | tr -d '\n'`
PWGEN_HTPASSWD_PASSWD_ONLY=`echo $PWGEN_HTPASSWD_LINE | awk '{ sub(/^$PWGEN_USER\:/, ""); print }'`
```

Replace `$PWGEN_HTPASSWD_PASSWD_ONLY` in the following YAML snippet with actual value:

```yaml
configmap:
  data:
    users:
      "admin":
         password: "$PWGEN_HTPASSWD_PASSWD_ONLY"
      "": {}  # Allow anonymous (no "docker login") access.
```

## ACLs

If the match section of an entry matches the request, the set of allowed actions will be applied to the token request and a ticket will be issued only for those of the requested actions that are allowed by the rule.

Example:

```yaml
configmap:
  data:
    acl: 
      - match: { account: "admin" }
        actions: ["*"]
        comment: "Admin has full access to everything."
      - match: { account: "" }
        actions: ["pull"]
        comment: "Anonymous users can pull"
```

# Working Example

## Generate password hashes for user `admin`

```bash
PWGEN=`pwgen -N 1 -B 10 | tr -d '\n'`
htpasswd -Bbn admin $PWGEN > generated-registry-htpasswd
PWGEN_HTPASSWD_LINE=`cat generated-registry-htpasswd | tr -d '\n'`
PWGEN_HTPASSWD_PASSWD_ONLY=`echo $PWGEN_HTPASSWD_LINE | awk '{ sub(/^admin\:/, ""); print }'`
echo "Docker registry admin password is: $PWGEN"
```

## Generate a self-signed certificate

```bash
openssl req -new -newkey rsa:4096 -days 5000 -nodes -x509 \
        -subj "/C=DE/ST=BW/L=Mannheim/O=DHBW/CN=docker-auth" \
        -keyout generated-docker-auth-server.key  \
        -out generated-docker-auth-server.pem

CERT_PEM_BASE64=`cat generated-docker-auth-server.pem | base64`
CERT_KEY_BASE64=`cat generated-docker-auth-server.key | base64`
```

## Create a k8s secret with the certificate

Save this to `my-secret.yaml` (and replace `$CERT_PEM_BASE64` with the actual value):

```bash
apiVersion: v1
kind: Secret
type: Opaque
metadata:
  namespace: "your-namespace"
  name: "your-docker-registry-cert"
data:
  tokenAuthRootCertBundle: "$CERT_PEM_BASE64"
```

Run `kubectl apply -f my-secret.yaml`

## Generate the configuration file for Helm

```bash
DOCKER_REG_HOSTNAME="docker-registry.example.com"
DOCKER_AUTH_HOSTNAME="docker-registry-auth.example.com"

cat <<EOF > generated-docker-auth-values.yaml
configmap:
  data:
    token:
      issuer: "docker-auth"
      expiration: 900
    users:
      "admin":
         password: "$PWGEN_HTPASSWD_PASSWD_ONLY"
      "": {}  # Allow anonymous (no "docker login") access.
    acl: 
      - match: { account: "admin" }
        actions: ["*"]
        comment: "Admin has full access to everything."
      - match: { account: "" }
        actions: ["pull"]
        comment: "Anonymous users can pull"
secret:
  data:
    server:
      certificate: "$CERT_PEM_BASE64"
      key: "$CERT_KEY_BASE64"

registry:
  enabled: true

logging:
  level: 5

docker-registry:
  configData:
    log:
      level: debug
      accesslog:
        disabled: false
    auth:
      token:
        autoredirect: false
        issuer: "docker-auth"
        realm: "https://$DOCKER_AUTH_HOSTNAME/auth"
        service: "token-service"

  ingress:
    enabled: true
    hosts:
      - $DOCKER_REG_HOSTNAME
    annotations:
      external-dns.alpha.kubernetes.io/hostname: $DOCKER_REG_HOSTNAME
      kubernetes.io/ingress.class: "nginx"
      nginx.ingress.kubernetes.io/force-ssl-redirect: "true"
      nginx.ingress.kubernetes.io/proxy-body-size: "0"
    tls:
      - hosts:
          - $DOCKER_REG_HOSTNAME

  extraVolumeMounts:
    - name: token-auth-root-cert-bundle
      mountPath: /tokenAuthRootCertBundle
      readOnly: true

  extraVolumes:
    - name: token-auth-root-cert-bundle
      secret:
        secretName: "your-docker-registry-cert"
        items:
          - key: tokenAuthRootCertBundle
            path: cert.pem

ingress:
  enabled: true
  hosts:
    - $DOCKER_AUTH_HOSTNAME
  annotations:
    external-dns.alpha.kubernetes.io/hostname: $DOCKER_AUTH_HOSTNAME
    kubernetes.io/ingress.class: "nginx"
    nginx.ingress.kubernetes.io/force-ssl-redirect: "true"
  tls:
    - hosts:
        - $DOCKER_AUTH_HOSTNAME

EOF
```

## Install the chart

```bash
helm install ./docker_auth \
            --name=docker-auth \
            --namespace=$HUB_NAMESPACE \
            -f generated-docker-auth-values.yaml
```

# Development: Upload a new version of the chart

```bash
helm lint
helm package .
mv docker-auth-*.tgz ../../docs/
helm repo index ../../docs/ --url https://github.com/pfisterer/docker_auth/
git add ../../docs/
git commit -a -m "Updated helm repository"
git push origin master
```
