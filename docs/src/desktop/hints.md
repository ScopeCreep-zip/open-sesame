# Hint Assignment

The `hints` module (`daemon-wm/src/hints.rs`) assigns mnemonic letter hints to windows for
keyboard-driven selection. Each window's hint repeats its application's key: windows of one
application take consecutive repetitions (`f`, `ff`, `fff`), which numeric shorthand abbreviates
(`f2`, `f3`). The same key launches the application when no window of it is open
(focus-or-launch).

## Hint Assignment

`assign_app_hints(app_ids, key_bindings, hint_keys)` returns one hint per window, in window
order:

1. Each window's key is resolved with `key_for_app()` (see [Key Selection](#key-selection)).
2. A window takes its key repeated once per earlier window with the same key.

For a window list of Firefox, Ghostty, Firefox the hints are `f`, `g`, `ff`.

An application without a key (no binding and no letter in its name) takes the first
`hint_keys` key that no other application on screen uses. When every pool key is taken, it
takes the first pool key, shared by repetition. With `hint_keys = "asd"`, windows of
`alacritty`, `org.x.123`, and `org.y.456` receive `a`, `s`, `ss`: `a` belongs to alacritty,
so both letterless applications share `s`.

`hint_keys` (default `"asdfghjkl"`) must be a non-empty set: configuration validation reports
an error for an empty pool or a repeated key.

## Key Selection

`key_for_app(app_id, key_bindings)` resolves the base key for each application.

### 1. Key Bindings

The `key_bindings` map in `WmConfig` maps a key to the application ID patterns it covers:

```toml
[profiles.default.wm.key_bindings.f]
apps = ["firefox", "org.mozilla.firefox"]
launch = "firefox"
```

A pattern matches an application, ignoring case, when it equals the application ID or the
application's name (the last reverse-DNS segment: `org.mozilla.firefox` is named `firefox`).
The first binding with a matching pattern supplies the key.

### 2. Mnemonic Key

Without a matching binding, `auto_key_for_app(app_id)` takes the first ASCII letter of the
application's name, lowercased:

- `com.mitchellh.ghostty` -- named `ghostty`, key `g`.
- `firefox` -- key `f`.
- `org.x.123` -- no letter, no key: the window takes a `hint_keys` key.

### Default Key Bindings

`WmConfig::default()` ships with bindings for common applications:

| Key | Applications | Launch Command |
| --- | --- | --- |
| `g` | ghostty, com.mitchellh.ghostty | `ghostty` |
| `f` | firefox, org.mozilla.firefox | `firefox` |
| `e` | microsoft-edge | `microsoft-edge` |
| `c` | chromium, google-chrome | -- |
| `v` | code, Code, cursor, Cursor | `code` |
| `n` | nautilus, org.gnome.Nautilus | `nautilus` |
| `s` | slack, Slack | `slack` |
| `d` | discord, Discord | `discord` |
| `m` | spotify | `spotify` |
| `t` | thunderbird | `thunderbird` |

## Numeric Shorthand

`normalize_input()` lowercases the input and expands numeric shorthand before matching: one
repeated letter followed by a count from 1 to 26 expands to that many repetitions.

- `a2` normalizes to `aa`
- `aa3` normalizes to `aaa`
- `f1` normalizes to `f`

Any other input is only lowercased: `ab2` (mixed letters), `a27` (count beyond 26), `a0`, and
`42` (no letter) stay as typed. Typing `S` therefore matches the hint `s`.

## Match Results

`match_input(input, hints)` normalizes the input and returns one of three `MatchResult`
variants:

- **`Exact(index)`** -- Exactly one hint starts with the normalized input, and equals it. The
  controller selects this window.
- **`Partial(indices)`** -- Several hints start with the normalized input, one of which may
  equal it (typing `a` with hints `a`, `aa`, `aaa` yields `Partial([0, 1, 2])`). The display
  narrows to those rows; Enter or the modifier release commits the selection.
- **`NoMatch`** -- No hint starts with the normalized input, or the input is empty. The
  controller checks for a launch binding.

## Focus-or-Launch

When the input matches no hint and is a single character, the controller looks the character
up with `hints::binding_for_key(key, key_bindings)` (case-insensitive). If the binding has a
`launch` command:

1. A pending launch is staged with the binding's command, `tags`, and `launch_args`.
2. The overlay shows the staged intent (`Launch <command>`).
3. The launch executes on modifier release or Enter (see
   [Staged Launch](window-manager.md#staged-launch)).

Without a launch command the input filters to no rows and the overlay shows that nothing
matches.

## Tags and Launch Args

Each `WmKeyBinding` can carry `tags` and `launch_args`:

```toml
[profiles.default.wm.key_bindings.g]
apps = ["ghostty"]
launch = "ghostty"
tags = ["dev-rust", "ai-tools"]
launch_args = ["--working-directory=/workspace"]
```

- `tags` are forwarded to `daemon-launcher` in the `LaunchExecute` IPC message for launch
  profile composition (environment variable injection, secret fetching, Nix devshell
  activation). Tags support qualified cross-profile references using colon syntax (e.g.,
  `"work:corp"`).
- `launch_args` are appended to the launched command's argument list.
