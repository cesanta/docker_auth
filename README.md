Docker Registry 2.0 authentication server
=========================================

The original Docker Registry server (v1) did not provide any support for authentication or authorization.
Access control had to be performed externally, typically by deploying Nginx in the reverse proxy mode with Basic or other type of authentication.
While performing simple user authentication is pretty straightforward, performing more fine-grained access control was cumbersome.

Docker Registry 2.0 introduced a new, token-based authentication and authorization protocol, but the server to generate them was not released.
Thus, most guides found on the internet still describe a set up with a reverse proxy performing access control.

This server fills the gap and implements the protocol described [here](https://github.com/docker/distribution/blob/master/docs/spec/auth/token.md).

Supported authentication methods:
 * Static list of users
 * Google Sign-In (incl. Google for Work / GApps for domain) (documented [here](https://github.com/brandnetworks/docker_auth/blob/master/examples/reference.yml))
 * LDAP (documented [here](https://github.com/brandnetworks/docker_auth/blob/master/examples/reference.yml))

## Installation and Examples

A public Docker image is available on Docker Hub: [brandnetworks/docker_auth](https://registry.hub.docker.com/u/brandnetworks/docker_auth/).

The binary takes a single argument - path to the config file.

Example command line:

```{r, engine='bash', count_lines}
$ docker run \
    --rm -it --name docker_auth -p 5001:5001 \
    -v /path/to/config_dir:/config:ro \
    -v /var/log/docker_auth:/logs \
    cesanta/docker_auth /config/auth_config.yml
```

See the [example config files](https://github.com/brandnetworks/docker_auth/tree/master/examples/) to get an idea of what is possible.

## Troubleshooting

Run with increased verbosity:
```{r, engine='bash', count_lines}
docker run ... brandnetworks/docker_auth --v=2 /config/auth_config.yml
```

## Contributing

Bug reports, feature requests and pull requests (for small fixes) are welcome.
If you require larger changes, please file an issue.
We cannot guarantee response but will do our best to address them.

## Licensing

   Copyright 2015 [Cesanta Software Ltd](http://www.cesanta.com) and [Brand Networks](http://bn.co).

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this software except in compliance with the License.
   You may obtain a copy of the License at

       https://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
