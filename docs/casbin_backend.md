# Casbin Backend

[Casbin](https://github.com/casbin/casbin) is a powerful and efficient open-source access control library written by Golang. It provides support for enforcing authorization based on various access control models.

## Usage

add casbin section in yml configuration file

```yaml
casbin_authz:
  model_path: "path/to/model"
  policy_path: "path/to/policy"
```

more info see: https://github.com/casbin/casbin