### logout

#### Command

```sh
p0 logout [--debug]
```

#### Description

Logs out the current user by deleting all authentication data, including identity files, configuration files, and authentication caches.

#### Options

| Option    | Description                                             |
|-----------|--------------------------------------------------------|
| `--debug` | (Optional) Prints debug information about deleted files |

#### Example Usage

```sh
$ p0 logout
Logging out...
Successfully logged out. All authentication data has been cleared.

$ p0 logout --debug
Logging out...
Deleted identity file: /path/to/identity
Deleted config file: /path/to/config
Deleted cache: /path/to/cache
Successfully logged out. All authentication data has been cleared.
```