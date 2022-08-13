Docker Registry 2 authentication server
=========================================

The original Docker Registry server (v1) did not provide any support for authentication or authorization.
Access control had to be performed externally, typically by deploying Nginx in the reverse proxy mode with Basic or other type of authentication.
While performing simple user authentication is pretty straightforward, performing more fine-grained access control was cumbersome.

Docker Registry 2.0 introduced a new, token-based authentication and authorization protocol, but the server to generate them was not released.
Thus, most guides found on the internet still describe a set up with a reverse proxy performing access control.

This server fills the gap and implements the protocol described [here](https://github.com/docker/distribution/blob/main/docs/spec/auth/token.md).

Supported authentication methods:
 * Static list of users
 * Google Sign-In (incl. Google for Work / GApps for domain) (documented [here](https://github.com/cesanta/docker_auth/blob/main/examples/reference.yml))
 * [Github Sign-In](docs/auth-methods.md#github)
 * Gitlab Sign-In
 * LDAP bind ([demo](https://github.com/kwk/docker-registry-setup))
 * MongoDB user collection
 * MySQL/MariaDB, PostgreSQL, SQLite database table
 * [External program](https://github.com/cesanta/docker_auth/blob/main/examples/ext_auth.sh)

Supported authorization methods:
 * Static ACL
 * MongoDB-backed ACL
 * MySQL/MariaDB, PostgreSQL, SQLite backed ACL
 * External program

## Installation and Examples

### Using Helm/Kubernetes

A helm chart is available in the folder [chart/docker-auth](chart/docker-auth).

### Docker

A public Docker image is available on Docker Hub: [cesanta/docker_auth](https://hub.docker.com/r/cesanta/docker_auth/).

Tags available:
 - `:edge` - bleeding edge, usually works but breaking config changes are possible. You probably do not want to use this in production.
 - `:latest` - latest tagged release, will line up with `:1` tag
 - `:1` - the `1.x` version, will have fixes, no breaking config changes. Previously known as `:stable`.
 - `:1.x` - specific release, see [here](https://github.com/cesanta/docker_auth/releases) for the list of current releases.

The binary takes a single argument - path to the config file.
If no arguments are given, the Dockerfile defaults to `/config/auth_config.yml`.

Example command line:

```{r, engine='bash', count_lines}
$ docker run \
    --rm -it --name docker_auth -p 5001:5001 \
    -v /path/to/config_dir:/config:ro \
    -v /var/log/docker_auth:/logs \
    cesanta/docker_auth:1 /config/auth_config.yml
```

See the [example config files](https://github.com/cesanta/docker_auth/tree/main/examples/) to get an idea of what is possible.

## Troubleshooting

Run with increased verbosity:
```{r, engine='bash', count_lines}
docker run ... cesanta/docker_auth:1 --v=2 --alsologtostderr /config/auth_config.yml
```

## Contributing

Bug reports, feature requests and pull requests (for small fixes) are welcome.
If you require larger changes, please file an issue.
We cannot guarantee response but will do our best to address them.

## Licensing

   Copyright 2015 [Cesanta Software Ltd](http://www.cesanta.com).

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this software except in compliance with the License.
   You may obtain a copy of the License at

       https://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
