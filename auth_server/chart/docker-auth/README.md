Helm Chart for docker_auth
=======================

## Introduction

This [Helm](https://github.com/kubernetes/helm) chart installs [docker_auth](https://github.com/cesanta/docker_auth) in a Kubernetes cluster.

## Prerequisites

- Kubernetes cluster 1.10+
- Helm 2.8.0+

## Installation

### Install the chart

Install the docker-auth helm chart with a release name `my-release`:

```bash
helm install --name my-release docker-auth
```

### Uninstallation

To uninstall/delete the `my-release` deployment:

```bash
helm delete --purge my-release
```

## Configuration

The following table lists the configurable parameters of the docker-auth chart and the default values.

| Parameter                                                                   | Description                                                                                                                                                                                                                                                                                                                                     | Default                         |
| --------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------- |
| **Configmap**                                                                  |
| `configmap.data.server.certificate`                                                               | path to server.pem.                                                                                                                                                                                                                                                                         |                        |
| `configmap.data.server.key`                                                        | path to server.key                                                                                                                                                                                                                                                                                                                           |                           |
| `configmap.data.token.issuer` | Must match issuer in the Registry config | `Acme auth server` |
| `configmap.data.token.expiration`                                                     | token expiration                                                   | `900`                                |
| **ingress**                                                             |
| `ingress.hosts.host`                                                       | docker-auth.domain                                                                                                                                                                                                                                                                                                              | `docker-auth.domain`                          |
| **High Available**                                                             |
| `replicaCount`                                                       | Replica count for High Available                                                                                                                                                                                                                                                                                                              | `3`                          |
