## Github

First you need to setup a [Github OAuth Application](https://github.com/settings/applications).

- The callback url needs to be `$fqdn:5001/github_auth`
   - `$fqdn` is the domain where docker_auth is accessed
   - `5001` or what port is specified in the `server` block

Once you have setup a Github OAuth application you need to add a `github` block to the docker_auth config file:

```yaml
github_auth:
  organization: "my-org-name"
  client_id: "..."
  client_secret: "..." # or client_secret_file
  level_token_db:
    path: /data/tokens.db
    # Optional token hash cost for bcrypt hashing
    # token_hash_cost: 5
```

Then specify what teams can do via acls

```yaml
acl:
  - match: {team: "infrastructure"}
    actions: ["pull", "push"]
    comment: "Infrastructure team members can push and all images"
```
