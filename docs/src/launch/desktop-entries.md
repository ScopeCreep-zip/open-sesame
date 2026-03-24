# Desktop Entry Discovery

Daemon-launcher discovers launchable applications by scanning XDG desktop entry files, builds a
fuzzy search index, and ranks results using frecency (frequency + recency).

## XDG Desktop Entry Scanning

The scanner in `daemon-launcher/src/scanner.rs` uses the `freedesktop-desktop-entry` crate to
enumerate `.desktop` files from `$XDG_DATA_DIRS/applications/`. Scanning is synchronous and runs
in a `tokio::task::spawn_blocking` context at daemon startup.

### Filtering Rules

Entries are filtered before indexing:

| Condition | Action |
|---|---|
| `NoDisplay=true` | Skipped. Non-launchable entries (e.g., D-Bus activatable services). |
| `Hidden=true` | Skipped. Explicitly hidden by the packager. |
| No `Exec=` field | Skipped. Not a launchable application. |
| Duplicate ID | Only the first occurrence is kept. |

### Indexed Fields

For each surviving entry, the scanner produces a `MatchItem` with:

- **id**: the desktop entry ID (e.g., `org.mozilla.firefox`).
- **name**: the localized `Name=` field, falling back to the entry ID.
- **extra**: a space-joined string of `Keywords=` and `Categories=` values, used to broaden
  fuzzy match surface.

The `Exec` line is cached separately in a `CachedEntry` for post-scan use during launch
execution. The Exec cache is stored as a `HashMap<String, CachedEntry>` keyed by entry ID.

## Fuzzy Search

Daemon-launcher uses the `nucleo` fuzzy matching library (via the `core-fuzzy` crate). Items are
injected into the matcher at startup via an `Injector`. Queries arrive as `LaunchQuery` IPC
messages and are dispatched to `SearchEngine::query()`, which combines fuzzy match scores with
frecency boosts.

Query results are returned as `LaunchResult` values containing the entry ID, display name, icon,
and composite score.

## Frecency Ranking

Launch frequency and recency are tracked in a per-profile SQLite database managed by
`core-fuzzy::FrecencyDb`. The database file is stored at:

```text
~/.config/pds/launcher/{profile_name}.frecency.db
```

Each trust profile has its own frecency database, providing isolation between profiles. When a
`LaunchQuery` specifies a different profile than the current one, the search engine switches its
frecency context via `engine.switch_profile()`.

When a `LaunchExecute` succeeds, `engine.record_launch(entry_id)` updates the frecency database.
The frecency boost is refreshed periodically via `engine.refresh_frecency()`.

## Desktop Entry Field Code Stripping

Before executing an `Exec` line, the scanner strips freedesktop `%`-prefixed field codes. These
are placeholder tokens defined by the Desktop Entry Specification that would normally be replaced
by a file manager:

Stripped codes: `%f`, `%F`, `%u`, `%U`, `%d`, `%D`, `%n`, `%N`, `%i`, `%c`, `%k`, `%v`, `%m`.

The literal `%%` sequence is collapsed to a single `%`.

After stripping, multiple consecutive spaces from removed codes are collapsed. The result is
then tokenized using freedesktop quoting rules (double-quote escaping for `\"`, `` \` ``, `\\`,
`\$`). The tokenizer does not invoke a shell.

## 3-Strategy Resolution Fallback

When a `LaunchExecute` request arrives, the entry ID is resolved against the cached entries
using three strategies in order:

1. **Exact match**: the entry ID matches a cache key exactly (e.g., `org.mozilla.firefox`).
2. **Last segment match**: the entry ID matches the last dot-separated segment of a cached ID,
   case-insensitively (e.g., `firefox` matches `org.mozilla.firefox`).
3. **Case-insensitive full ID match**: the entry ID matches a cached ID when both are lowercased
   (e.g., `alacritty` matches `Alacritty`).

If none of the three strategies produces a match, `LaunchDenial::EntryNotFound` is returned.
