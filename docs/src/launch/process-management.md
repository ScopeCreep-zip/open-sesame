# Process Management

Daemon-launcher spawns child processes in isolated systemd scopes with zombie reaping and
post-spawn secret zeroization.

## systemd-run Scope Isolation

Every launched process is wrapped in a transient systemd user scope via:

```bash
systemd-run --user --scope --unit=app-open-sesame-{entry_id}-{pid}.scope -- {program} {args}
```

This provides:

- **cgroup isolation**: the child runs in its own cgroup, enabling per-application resource
  accounting via `systemd-cgtop`.
- **No inherited limits**: the child does not inherit `MemoryMax` or mount namespace
  restrictions from the launcher's service unit.
- **Launcher restart survival**: because `KillMode=process` semantics apply to scopes (the
  scope itself has no main process), children survive launcher daemon restarts.
- **Clean unit naming**: the scope name is sanitized from the entry ID by replacing
  non-alphanumeric characters with dashes and collapsing runs.

### Fallback to Direct Spawn

If `systemd-run` is unavailable (not installed, or the spawn fails), daemon-launcher falls back
to a direct `Command::spawn()`. The `via_scope` flag in the log output indicates which path was
taken.

## No Sandbox Inheritance

Daemon-launcher intentionally does not apply seccomp or Landlock sandboxing to itself. Seccomp
and Landlock rules inherit across `fork+exec` and would be applied to every child process,
breaking arbitrary desktop applications. The security boundary for daemon-launcher is the Noise
IK authenticated IPC bus, not process-level sandboxing.

## Child Reaping

After spawning, daemon-launcher reaps the wrapper process (or direct child) in a
`tokio::task::spawn_blocking` closure that calls `child.wait()`. This prevents zombie
accumulation.

When using systemd-run scopes, the reaped process is the `systemd-run` wrapper, not the
application itself. The application continues running under the transient scope until it exits
naturally.

## Secret Zeroization

Secret values pass through two zeroization points:

1. **Error paths**: if a secret value fails UTF-8 validation, the raw bytes are zeroized before
   returning the error.
2. **Post-spawn cleanup**: after `Command::spawn()` copies the environment to the OS process,
   all values in the composed environment `BTreeMap` are zeroized via `zeroize::Zeroize`, and
   the map is dropped.

This ensures secret material does not persist in the daemon-launcher process memory after it has
been handed off to the child.

## I/O Configuration

Spawned processes have their I/O handles configured as:

| Stream | Configuration |
|---|---|
| stdin | `/dev/null` (`Stdio::null()`) |
| stdout | `/dev/null` (`Stdio::null()`) |
| stderr | Inherited from daemon-launcher (`Stdio::inherit()`) |

Stderr inheritance allows application error output to reach the journal when daemon-launcher runs
under systemd.

## Environment Propagation

The composed environment (launch profile env vars + secrets + implicit `SESAME_*` vars) is
propagated to both the `systemd-run` wrapper and the direct spawn fallback. The `systemd-run`
process passes its environment through to the child in the scope.

The working directory (`cwd`) from the launch profile is validated as an absolute, existing
directory path before being set on the command. Relative paths are rejected with an error.
