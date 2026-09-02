# AUR Packages

PKGBUILD templates for the Arch User Repository. `.SRCINFO` is generated
in CI by `makepkg --printsrcinfo` and pushed alongside the PKGBUILD by
`KSXGitHub/github-actions-deploy-aur`. Do not commit `.SRCINFO` here.

## Packages

- `open-sesame-bin` — split binary package (headless + desktop) from
  release tarballs. Published to AUR automatically on every release via
  `KSXGitHub/github-actions-deploy-aur`.

Source-build pkgbase (`open-sesame`) is not automated. The full workspace
compile requires Rust 1.97+, raised RLIMIT_MEMLOCK for ProtectedAlloc
tests, and wayland/xkbcommon/seccomp dev headers. Publish manually if
maintaining: `cd aur/open-sesame && makepkg --printsrcinfo > .SRCINFO`
then push to `ssh://aur@aur.archlinux.org/open-sesame.git`.
