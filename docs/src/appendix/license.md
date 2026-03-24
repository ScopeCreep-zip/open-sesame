# License

Open Sesame is licensed under **GPL-3.0-only** (GNU General Public License,
version 3, with no "or later" clause).

## Why GPL-3.0

The `cosmic-protocols` crate, which provides Wayland protocol definitions for
the COSMIC desktop compositor, is licensed under GPL-3.0-only. Because
Open Sesame links against `cosmic-protocols` in the `platform-linux` and
`daemon-wm` crates, the entire combined work must be distributed under
GPL-3.0-only to satisfy the license terms.

## License Text

The full license text is in the
[`LICENSE`](https://github.com/ScopeCreep-zip/open-sesame/blob/main/LICENSE)
file at the repository root. It is the standard GNU General Public License
version 3 as published by the Free Software Foundation on 29 June 2007.

## SPDX Identifier

All crate manifests declare `license = "GPL-3.0-only"` in their
`Cargo.toml` workspace configuration, using the
[SPDX license identifier](https://spdx.org/licenses/GPL-3.0-only.html).
