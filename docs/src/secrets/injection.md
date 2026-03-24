# Secret Injection

The `sesame` CLI provides two commands for injecting vault secrets into running processes:
`sesame env` for spawning a child process with secrets as environment variables, and
`sesame export` for emitting secrets in shell, dotenv, or JSON format. Both commands enforce a
runtime denylist that blocks security-sensitive environment variable names.

## sesame env

`sesame env` spawns a child process with all secrets from the specified profile(s) injected as
environment variables.

```bash
sesame env -p work -- my-application --flag
```

The command resolves profile specs from the `-p` flag or, if omitted, from the
`SESAME_PROFILES` environment variable. If neither is set, the default profile name is used.

The child process also receives a `SESAME_PROFILES` environment variable containing a CSV of
the resolved profile specs (e.g., `work,braincraft:operations`), allowing it to know its
security context.

After the child process exits, all secret byte vectors are zeroized via `zeroize::Zeroize`
before the parent process exits with the child's exit code.

### Multi-Profile Support

Multiple profiles can be specified as a comma-separated list:

```bash
sesame env -p "default,work" -- my-application
```

Secrets are fetched from each profile in order and merged with left-wins collision resolution:
if the same secret key name exists in multiple profiles, the value from the first profile in
the list is used. This is implemented in `fetch_multi_profile_secrets()` in
`open-sesame/src/ipc.rs`, which uses a `HashSet` to track seen key names.

### Prefix

The `--prefix` flag prepends a string to all generated environment variable names:

```bash
sesame env -p work --prefix MYAPP -- my-application
# Secret "api-key" becomes MYAPP_API_KEY
```

## sesame export

`sesame export` emits secrets in one of three formats, suitable for shell evaluation or file
generation.

### Shell Format

```bash
sesame export -p work --format shell
```

Output:

```bash
export API_KEY="the-secret-value"
export DB_PASSWORD="another-value"
```

### Dotenv Format

```bash
sesame export -p work --format dotenv
```

Output:

```text
API_KEY="the-secret-value"
DB_PASSWORD="another-value"
```

### JSON Format

```bash
sesame export -p work --format json
```

Output:

```json
{"API_KEY":"the-secret-value","DB_PASSWORD":"another-value"}
```

After output, all intermediate string copies are zeroized via unsafe
`as_bytes_mut().zeroize()`.

## Secret Name to Environment Variable Conversion

The `secret_key_to_env_var()` function in `open-sesame/src/env.rs` converts secret key names
to environment variable names using the following rules:

| Input character | Output |
|---|---|
| Hyphen (`-`) | Underscore (`_`) |
| Dot (`.`) | Underscore (`_`) |
| ASCII alphanumeric | Uppercased |
| Underscore (`_`) | Preserved |
| All other characters | Underscore (`_`) |

The entire result is uppercased. If a prefix is provided, it is prepended with an underscore
separator.

**Examples** (from tests in `open-sesame/src/env.rs`):

| Secret key | Prefix | Environment variable |
|---|---|---|
| `api-key` | None | `API_KEY` |
| `api-key` | `MYAPP` | `MYAPP_API_KEY` |
| `db.host-name` | None | `DB_HOST_NAME` |

## Environment Variable Denylist

The `DENIED_ENV_VARS` constant in `open-sesame/src/env.rs` defines environment variable names
that must never be overwritten by secret injection. The `is_denied_env_var()` function checks
against this list using case-insensitive comparison. The `BASH_FUNC_` prefix is matched as a
prefix (any variable starting with `BASH_FUNC_` is denied).

If a secret's converted name matches a denied variable, the secret is skipped with a warning
printed to stderr. It is not injected into the child process or emitted in export output.

### Full Denylist

**Dynamic linker -- arbitrary code execution:**

- `LD_PRELOAD`
- `LD_LIBRARY_PATH`
- `LD_AUDIT`
- `LD_DEBUG`
- `LD_DEBUG_OUTPUT`
- `LD_DYNAMIC_WEAK`
- `LD_PROFILE`
- `LD_SHOW_AUXV`
- `LD_BIND_NOW`
- `LD_BIND_NOT`
- `DYLD_INSERT_LIBRARIES`
- `DYLD_LIBRARY_PATH`
- `DYLD_FRAMEWORK_PATH`

**Core execution environment:**

- `PATH`
- `HOME`
- `USER`
- `SHELL`
- `LOGNAME`
- `LANG`
- `TERM`
- `DISPLAY`
- `WAYLAND_DISPLAY`
- `XDG_RUNTIME_DIR`

**Shell injection vectors:**

- `BASH_ENV`
- `ENV`
- `BASH_FUNC_` (prefix match)
- `CDPATH`
- `GLOBIGNORE`
- `SHELLOPTS`
- `BASHOPTS`
- `PROMPT_COMMAND`
- `PS1`, `PS2`, `PS4`
- `MAIL`, `MAILPATH`, `MAILCHECK`
- `IFS`

**Language runtime code execution:**

- `PYTHONPATH`, `PYTHONSTARTUP`, `PYTHONHOME`
- `NODE_OPTIONS`, `NODE_PATH`, `NODE_EXTRA_CA_CERTS`
- `PERL5LIB`, `PERL5OPT`
- `RUBYLIB`, `RUBYOPT`
- `GOPATH`, `GOROOT`, `GOFLAGS`
- `JAVA_HOME`, `CLASSPATH`, `JAVA_TOOL_OPTIONS`

**Security and authentication:**

- `SSH_AUTH_SOCK`
- `GPG_AGENT_INFO`
- `KRB5_CONFIG`, `KRB5CCNAME`
- `SSL_CERT_FILE`, `SSL_CERT_DIR`
- `CURL_CA_BUNDLE`, `REQUESTS_CA_BUNDLE`
- `GIT_SSL_CAINFO`
- `NIX_SSL_CERT_FILE`

**Nix:**

- `NIX_PATH`
- `NIX_CONF_DIR`

**Sudo and privilege escalation:**

- `SUDO_ASKPASS`
- `SUDO_EDITOR`
- `VISUAL`
- `EDITOR`

**Systemd and D-Bus:**

- `SYSTEMD_UNIT_PATH`
- `DBUS_SESSION_BUS_ADDRESS`

**Open Sesame namespace:**

- `SESAME_PROFILE`

## Shell Escaping

The `shell_escape()` function in `open-sesame/src/env.rs` produces output safe for embedding
in double-quoted `export` statements. The following transformations are applied:

| Character | Output | Reason |
|---|---|---|
| `\0` (null) | Stripped | C string truncation risk |
| `"` | `\"` | Shell metacharacter |
| `\` | `\\` | Shell metacharacter |
| `$` | `\$` | Variable expansion |
| `` ` `` | `` \` `` | Command substitution |
| `!` | `\!` | History expansion |
| `\n` | `\n` (literal backslash-n) | Newline |
| `\r` | `\r` (literal backslash-r) | Carriage return |

## JSON Escaping

The `json_escape()` function produces output safe for embedding in JSON string values:

| Character | Output |
|---|---|
| `\0` (null) | Stripped |
| `"` | `\"` |
| `\` | `\\` |
| `\n` | `\n` |
| `\r` | `\r` |
| `\t` | `\t` |
| Other control characters | `\uXXXX` (Unicode escape) |
