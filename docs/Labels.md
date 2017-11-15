# Labels

Labels can be used to reduce the number ACLS needed in large, complex installations.

Labels are only supported for certain auth backends. As of right now labels are only supported when using Static Authentication or Mongo Authentication.

## Label Placeholders

Label placeholders are available for any label that is assigned to a user.

For example, given a user:

```json
{
    "username" : "busy-guy",
    "password" : "$2y$05$B.x046DV3bvuwFgn0I42F.W/SbRU5fUoCbCGtjFl7S33aCUHNBxbq",
    "labels" : {
        "group" : [
            "web",
            "webdev"
        ],
        "project" : [
            "website",
            "api"
        ],
        "tier" : [
            "frontend",
            "backend"
        ]
    }
}
```

The following placeholders could be used in any match field:

  * `${labels:group}`
  * `${labels:project}`
  * `${labels:tier}`

Example acl with label matching:

```json
{
  "match": { "name": "${labels:project}/*" },
  "actions": [ "push", "pull" ],
  "comment": "Users can push to any project they are assigned to"
}
```

Single label matching is efficient and will be tested in the order
they are listed in the user record.


## Using Multiple Labels when matching

It's possible to use multiple labels in a single match. When multiple labels are
used in a single match all possible combinations of the labels are tested
in [no particular order](https://blog.golang.org/go-maps-in-action#TOC_7.).

Example acl with multiple label matching:

```json
{
  "match": { "name": "${labels:project}/${labels:group}-${labels:tier}" },
  "actions": [ "push", "pull" ],
  "comment": "Contrived multiple label match rule"
}
```

When paired with the user given above would result in 8 possible combinations
that would need to be tested.

  * `${labels:project} : website`, `${labels:group} : dev`, `${labels:tier} : frontend`
  * `${labels:project} : website`, `${labels:group} : dev`, `${labels:tier} : backend`
  * `${labels:project} : website`, `${labels:group} : webdev`, `${labels:tier} : frontend`
  * `${labels:project} : website`, `${labels:group} : webdev`, `${labels:tier} : backend`
  * `${labels:project} : api`, `${labels:group} : dev`, `${labels:tier} : frontend`
  * `${labels:project} : api`, `${labels:group} : dev`, `${labels:tier} : backend`
  * `${labels:project} : api`, `${labels:group} : webdev`, `${labels:tier} : frontend`
  * `${labels:project} : api`, `${labels:group} : webdev`, `${labels:tier} : backend`

This grows rapidly as more placeholders and labels are added. So it's best
to limit multiple label matching when possible.

## Using Labels for User Based Access

If you want to use minimal ACLs then you can create some very basic acls and rely on user-side labels for access control.

Example acls:

```yaml
  - match: {name: "${labels:full-access}"}
    actions: ["*"]
  - match: {name: "${labels:read-only-access}"}
    actions: ["pull"]
```

Given the acl above you could use labels to grant access by simply updating a user's record

Example User with full-access to `test/*` and read-only access to `prod/*`

```json
{
    "username" : "test-user",
    "labels" : {
        "full-access" : [
            "test/*"
        ],
        "read-only-access" : [
            "prod/*"
        ]
    }
}

```

If you wanted to grant more access to test-user in the future you would simply add to the `full-access` or `read-only-access` labels list. This works best when paired with a dynamic authentication method that returns labels. As of v1.3 that includes mongo and ext_auth
