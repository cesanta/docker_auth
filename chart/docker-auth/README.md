# Helm Chart for docker_auth

A Helm chart for deploying a [private Docker Registry](https://github.com/cesanta/docker_auth).

## Overview

This chart deploys docker_auth, which provides token-based authentication and authorization for Docker Registry v2. It implements the Docker Registry authentication protocol and supports various authentication backends.

## Prerequisites

- Kubernetes 1.25+
- Helm 3.0+

## Installation

### Add Helm Repository

```bash
helm repo add cesanta https://cesanta.github.io/docker_auth/
helm repo update
```

### Basic Installation

```bash
helm install my-docker-auth cesanta/docker-auth
```

### Installation with Custom Values

```bash
helm install docker-auth cesanta/docker-auth -f values.yaml
```

### Uninstall

```bash
helm uninstall docker-auth
```

## Configuration

### Values

| Parameter | Description | Default |
|-----------|-------------|---------|
| **Image** | | |
| `image.repository` | Docker image repository | `cesanta/docker_auth` |
| `image.tag` | Docker image tag | `1.14.0` |
| `image.pullPolicy` | Image pull policy | `IfNotPresent` |
| **Deployment** | | |
| `replicaCount` | Number of replicas | `1` |
| `nameOverride` | Override name of the chart | `""` |
| `fullnameOverride` | Override full name of the chart | `""` |
| **Logging** | | |
| `logging.level` | Log verbosity level (0-10). Passed as `--v=X` flag to docker_auth binary. Higher numbers = more verbose logging. | `2` |
| **Authentication** | | |
| `configmap.data.token.issuer` | Token issuer name (must match registry config) | `"Acme auth server"` |
| `configmap.data.token.expiration` | Token expiration time in seconds | `900` |
| `configmap.data.token.disableLegacyKeyId` | Disables legacy key IDs for registry v3 | `false` |
| `configmap.data.users` | Static user definitions | See values.yaml |
| `configmap.data.acl` | Access control list rules | See values.yaml |
| **TLS/Certificates** | | |
| `secret.data.server.certificate` | Server certificate content (PEM format, base64 encoded) | `""` |
| `secret.data.server.key` | Server private key content (PEM format, base64 encoded) | `""` |
| `secret.secretName` | External secret name for certificates (alternative to inline cert/key) | `""` |
| **Service** | | |
| `service.type` | Kubernetes service type | `ClusterIP` |
| `service.port` | Service port | `5001` |
| `service.targetPort` | Container port | `5001` |
| **Ingress** | | |
| `ingress.enabled` | Enable ingress | `true` |
| `ingress.className` | Ingress class name | `""` |
| `ingress.annotations` | Ingress annotations | `{}` |
| `ingress.labels` | Ingress labels | `{}` |
| `ingress.hosts` | Ingress hosts configuration | See values.yaml |
| `ingress.tls` | Ingress TLS configuration | `[]` |
| **Resources** | | |
| `resources` | CPU/Memory resource requests/limits | `{}` |
| `nodeSelector` | Node selector | `{}` |
| `tolerations` | Tolerations | `[]` |
| `affinity` | Affinity rules | `{}` |
| **Security** | | |
| `podSecurityContext` | Pod security context | `{}` |
| `containerSecurityContext` | Container security context | `{}` |
| `podAnnotations` | Pod annotations | `{}` |
| **Registry Integration** | | |
| `registry.enabled` | Enable integrated docker-registry | `false` |

### Quick Start Example

```yaml
# values.yaml
ingress:
  enabled: true
  className: "nginx"
  annotations:
    cert-manager.io/cluster-issuer: "letsencrypt-prod"
    nginx.ingress.kubernetes.io/force-ssl-redirect: "true"
  hosts:
    - host: docker-auth.example.com
      paths:
        - path: /
          pathType: Prefix
  tls:
    - secretName: docker-auth-tls
      hosts:
        - docker-auth.example.com

configmap:
  data:
    token:
      issuer: "docker-auth-prod"
      expiration: 900
    users:
      "admin":
        password: "$2y$05$..." # Generate with htpasswd -Bbn admin password
    acl:
      - match: {account: "admin"}
        actions: ["*"]
        comment: "Admin has full access"
      - match: {account: ""}
        actions: ["pull"]
        comment: "Anonymous users can pull"
```

## Certificate Management

### Generate Self-Signed Certificates

```bash
openssl req -new -newkey rsa:4096 -days 5000 -nodes -x509 \
    -subj "/C=DE/ST=BW/L=Mannheim/O=ACME/CN=docker-auth" \
    -keyout generated-docker-auth-server.key \
    -out generated-docker-auth-server.pem

CERT_PEM_BASE64=`cat generated-docker-auth-server.pem | base64`
CERT_KEY_BASE64=`cat generated-docker-auth-server.key | base64`
```

## Access Control Lists (ACL)

### ACL Configuration

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

## Monitoring and Logging

### Increase Log Verbosity

```yaml
logging:
  level: 5  # Higher values = more verbose (0-10)
```

## Troubleshooting

### Debug Commands

```bash
# Check pod logs
kubectl logs -l app.kubernetes.io/name=docker-auth

# Check configuration
kubectl get configmap docker-auth -o yaml

# Test authentication endpoint
curl -k https://docker-auth.example.com/auth

# Verify certificate
openssl x509 -in certificate.pem -text -noout
```

## Integration with Docker Registry

To use with Docker Registry, configure the registry with:

```yaml
# Registry configuration
auth:
  token:
    realm: https://docker-auth.example.com/auth
    service: token-service
    issuer: docker-auth-prod  # Must match configmap.data.token.issuer
    rootcertbundle: /path/to/docker-auth.crt
```

## Development

### Chart Development

```bash
# Lint the chart
helm lint chart/docker-auth

# Test template rendering
helm template test-release chart/docker-auth

# Package the chart
helm package chart/docker-auth
```

### Update Repository

```bash
cd chart/docker-auth
helm lint
helm package .
mv docker-auth-*.tgz ../../docs/
helm repo index ../../docs/ --url https://cesanta.github.io/docker_auth/
git add ../../docs/
git commit -m "Updated helm repository"
git push origin main
```
