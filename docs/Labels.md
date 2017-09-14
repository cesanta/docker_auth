# Labels

Labels can be used to reduce the number ACLS needed in large, complex installations.

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
