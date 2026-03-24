# Hint Assignment

The `hints` module (`daemon-wm/src/hints.rs`) assigns letter-based hints to windows for
keyboard-driven selection. Hints follow a Vimium-style model where each window receives a unique
string of repeated characters that the user types to select it.

## Hint Assignment Algorithm

The `assign_hints(count, hint_keys)` function generates hints from a configurable key set string
(default: `"asdfghjkl"` via `WmConfig`). For `N` windows and `K` available keys in the key set:

1. The first `K` windows each receive a single character: `a`, `s`, `d`, `f`, ...
2. The next `K` windows receive doubled characters: `aa`, `ss`, `dd`, `ff`, ...
3. The pattern continues with tripled characters, and so on.

Each key is used once at each repetition level before any key repeats at the next level. For
example, with `hint_keys = "asd"` and 5 windows, the assigned hints are: `a`, `s`, `d`, `aa`,
`ss`.

This function is used internally. The primary entry point for daemon-wm is `assign_app_hints()`,
which groups windows by application before assigning.

## App Grouping

The `assign_app_hints(app_ids, key_bindings)` function groups windows by their resolved base key
character before assigning hints. Windows sharing the same base key receive consecutive
repetitions of that character.

For a window list containing two Firefox instances and one Ghostty:

- Firefox window 1: `f`
- Firefox window 2: `ff`
- Ghostty window 1: `g`

The function returns `(hint_string, original_index)` pairs sorted by original window index,
preserving display order.

## Key Selection

The base key for each application is determined by `key_for_app(app_id, key_bindings)` with the
following priority:

### 1. Explicit Config Override

The `key_bindings` map in `WmConfig` allows explicit key-to-app mapping. Each `WmKeyBinding`
entry contains an `apps` list of app ID patterns:

```toml
[profiles.default.wm.key_bindings.f]
apps = ["firefox", "org.mozilla.firefox"]
launch = "firefox"
```

`key_for_app()` iterates all key bindings and checks each pattern against the app ID using three
comparisons:

- Exact match: `pattern == app_id`
- Case-insensitive match: `pattern.to_lowercase() == app_id.to_lowercase()`
- Last-segment match: the reverse-DNS last segment of `app_id` (lowercased) equals the pattern
  (lowercased). For `org.mozilla.firefox`, the last segment is `firefox`.

The first matching binding's key character is returned.

### 2. Auto-Key Detection

If no explicit binding matches, `auto_key_for_app(app_id)` extracts the first alphabetic
character from the last segment of the app ID (split on `.`):

- `com.mitchellh.ghostty` -- last segment is `ghostty`, auto-key is `g`.
- `firefox` -- no dots, the full string is the segment, auto-key is `f`.
- `microsoft-edge` -- auto-key is `m`.

The character is lowercased. If no alphabetic character is found, `None` is returned and
`assign_app_hints()` falls back to `'a'`.

### Default Key Bindings

`WmConfig::default()` ships with bindings for common applications:

| Key | Applications | Launch Command |
|-----|-------------|----------------|
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

The `normalize_input()` function expands numeric suffixes before matching. This allows users to
type `a2` instead of `aa`, or `f3` instead of `fff`:

- `a2` normalizes to `aa`
- `a3` normalizes to `aaa`
- `f1` normalizes to `f`

Expansion rules:

- The input must be at least 2 characters long.
- The trailing characters must all be ASCII digits.
- The leading characters must all be the same letter (e.g., `a` or `aa`, but not `ab`).
- The numeric value must be between 1 and 26 inclusive.

If any rule is violated, the input is returned as-is (lowercased). Mixed-character inputs like
`ab2` are not expanded because the letter prefix contains non-identical characters.

## Case-Insensitive Matching

All input is lowercased by `normalize_input()` before matching. Typing `S` matches the hint `s`.
This applies to both direct character matching and numeric shorthand expansion.

## Match Results

The `match_input(input, hints)` function normalizes the input and returns one of three
`MatchResult` variants:

- **`Exact(index)`** -- Exactly one hint equals the normalized input, and no other hints share
  it as a prefix. The controller selects this window.
- **`Partial(indices)`** -- Multiple hints start with the normalized input. This includes cases
  where one hint is an exact match but others share the same prefix (e.g., typing `a` with hints
  `a`, `aa`, `aaa` yields `Partial([0, 1, 2])`). The controller updates the display but does not
  commit a selection.
- **`NoMatch`** -- No hint starts with the normalized input. The controller checks for a launch
  command binding.

## Focus-or-Launch

When `check_hint_or_launch()` in the controller receives `MatchResult::NoMatch` and the input
buffer contains exactly one character, it calls `hints::launch_for_key(key, key_bindings)`. If a
launch command exists for that key:

1. A `PendingLaunch` is staged via `set_pending_launch()`, containing the command string, tags,
   and launch args from the binding.
2. The overlay displays the staged intent via `Command::ShowLaunchStaged`.
3. The launch executes on modifier release or Enter (see
   [Staged Launch](window-manager.md#staged-launch)).

If no launch command is configured for the key, the input is treated as a filter with no matches.

## Tags and Launch Args

Each `WmKeyBinding` can carry `tags` and `launch_args` fields:

```toml
[profiles.default.wm.key_bindings.g]
apps = ["ghostty"]
launch = "ghostty"
tags = ["dev-rust", "ai-tools"]
launch_args = ["--working-directory=/workspace"]
```

- `tags_for_key(key, key_bindings)` returns the `tags` vector for the matching key. Tags are
  forwarded to `daemon-launcher` in the `LaunchExecute` IPC message for launch profile
  composition (environment variable injection, secret fetching, Nix devshell activation). Tags
  support qualified cross-profile references using colon syntax (e.g., `"work:corp"`).
- `launch_args_for_key(key, key_bindings)` returns the `launch_args` vector. These are appended
  to the launched command's argument list.

Both functions perform case-insensitive key lookup by lowercasing the input character before
looking up the `BTreeMap`.
