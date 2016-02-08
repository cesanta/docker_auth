# MongoDB Backends

You may want to manage your ACLs and Users from an external application and therefore
need them to be stored outside of your auth_server's configuration file.

For this purpose, there's a [MongoDB](https://www.mongodb.org/) backend
which can query ACL and Auth from a MongoDB database.


## Auth backend in MongoDB

Auth entries in mongo are single dictionary containing a username and password entry.
The password entry must contain a BCrypt hash.

```json
{
    "username" : "admin",
    "password" : "$2y$05$B.x046DV3bvuwFgn0I42F.W/SbRU5fUoCbCGtjFl7S33aCUHNBxbq"
}
```

## ACL backend in MongoDB

A typical ACL entry from the static YAML configuration file looks something like
this:

```yaml
- match: {account: "/.+/", name: "${account}/*"}
  actions: ["push", "pull"]
  comment: "All logged in users can push all images that are in a namespace beginning with their name"
```

Notice the use of a regular expression (`/.+/`), a placeholder (`${account}`),
and in particular the `actions` array.

The ACL entry as is it is stored inside the static YAML file can be mapped to
MongoDB quite easily. Below you can find a list of ACL entries that are ready to
be imported into MongoDB. Those ACL entries reflect what's specified in the
`example/reference.yml` file under the `acl` section (aka static ACL).

The added field of seq is used to provide a reliable order which MongoDB does not
guarantee by default, i.e. [Natural Sorting](https://docs.mongodb.org/manual/reference/method/cursor.sort/#return-natural-order).

``seq`` is a required field in all MongoDB ACL documents. Any documents without this key will be excluded. seq uniqeness is also enforced.

**reference_acl.json**

```json
{"seq": 10, "match" : {"account" : "admin"}, "actions" : ["*"], "comment" : "Admin has full access to everything."}
{"seq": 20, "match" : {"account" : "test", "name" : "test-*"}, "actions" : ["*"], "comment" : "User \"test\" has full access to test-* images but nothing else. (1)"}
{"seq": 30, "match" : {"account" : "test"}, "actions" : [], "comment" : "User \"test\" has full access to test-* images but nothing else. (2)"}
{"seq": 40, "match" : {"account" : "/.+/"}, "actions" : ["pull"], "comment" : "All logged in users can pull all images."}
{"seq": 50, "match" : {"account" : "/.+/", "name" : "${account}/*"}, "actions" : ["*"], "comment" : "All logged in users can push all images that are in a namespace beginning with their name"}
{"seq": 60, "match" : {"account" : "", "name" : "hello-world"}, "actions" : ["pull"], "comment" : "Anonymous users can pull \"hello-world\"."}
```

**Note** that each document entry must span exactly one line or otherwise the
`mongoimport` tool (see below) will not accept it.

### Import reference ACLs into MongoDB

To import the above specified ACL entries from the reference file, simply
execute the following commands.

#### Ensure MongoDB is running

If you don't have a MongoDB server running, consider to start it within it's own
docker container:

`docker run --name mongo-acl -d mongo`

Then wait until the MongoDB server is ready to accept connections. You can find
this out by running `docker logs -f mongo-acl`. Once you see the message
`waiting for connections on port 27017`, you can proceed with the instructions
below.

#### Get mongoimport tool

On Ubuntu this is a matter of `sudo apt-get install mongodb-clients`.

#### Import ACLs

```bash
MONGO_IP=$(docker inspect --format '{{ .NetworkSettings.IPAddress }}' mongo-acl)
mongoimport --host $MONGO_IP --db docker_auth --collection acl < reference_acl.json
```

This should print a message like this if everything was successful:

```
connected to: 172.17.0.4
Wed Nov  4 13:34:15.816 imported 6 objects
```
