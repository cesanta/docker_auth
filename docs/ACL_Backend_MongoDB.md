# ACL backend in MongoDB

Maybe you want to manage your ACLs from an external application and therefore
need them to be stored outside of your auth_server's configuration file.

For this purpose, there's a [MongoDB](https://www.mongodb.org/) ACL backend
which can query ACLs from a MongoDB database.

A typical ACL from the static YAML configuration file looks something like this:

```
- match: {account: "/.+/", name: "${account}/*"}
  actions: ["push", "pull"]
  comment: "All logged in users can push all images that are in a namespace beginning with their name"
```

Notice the use of a regular expression (`/.+/`), a placeholder (`${account}`),
and in particular the `actions` array.

The ACL as is it is stored inside the static YAML file can be mapped to MongoDB
quite easily. Below you can find a list of ACLs that are ready to be imported
into MongoDB. Those ACLs reflect what's specified in the `example/reference.yml`
file.

**reference_acls.json**

```json
{"match" : {"account" : "admin"}, "actions" : ["*"], "comment" : "Admin has full access to everything."}
{"match" : {"account" : "test", "name" : "test-*"}, "actions" : ["*"], "comment" : "User \"test\" has full access to test-* images but nothing else. (1)"}
{"match" : {"account" : "test"}, "actions" : [], "comment" : "User \"test\" has full access to test-* images but nothing else. (2)"}
{"match" : {"account" : "/.+/"}, "actions" : ["pull"], "comment" : "All logged in users can pull all images."}
{"match" : {"account" : "/.+/", "name" : "${account}/*"}, "actions" : ["*"], "comment" : "All logged in users can push all images that are in a namespace beginning with their name"}
{"match" : {"account" : "", "name" : "hello-world"}, "actions" : ["pull"], "comment" : "Anonymous users can pull \"hello-world\"."}
```

**Note** that each document entry must span exactly one line or otherwise the
`mongoimport` tool (see below) will not accept it.

## Import reference ACLs into MongoDB

To import the above specified ACLs from the reference file, simply execute these
commands:

### Ensure MongoDB is running

If you don't have a MongoDB server running, consider to start it within it's own
docker container:

`docker run --name mongo-acl -d mongo`

### Get mongoimport tool

On Ubuntu this is a matter of `sudo apt-get install mongodb-clients`.

### Import ACLs

```bash
MONGO_IP=$(docker inspect --format '{{ .NetworkSettings.IPAddress }}' mongo-acl)
mongoimport --host $MONGO_IP --db docker_auth --collection acl < reference_acls.json
```

This should print a message like this if everything was successful:

```
connected to: 172.17.0.4
Wed Nov  4 13:34:15.816 imported 6 objects
```
