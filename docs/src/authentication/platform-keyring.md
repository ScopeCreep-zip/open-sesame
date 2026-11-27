# Platform Keyring Backend

The platform keyring factor (`AuthFactorId::PlatformKeyring`, config string
`platform-keyring`) unlocks a vault without interaction while the user's operating-system
keyring is unlocked: on Linux, the freedesktop Secret Service (gnome-keyring, `KWallet`,
oo7-daemon, `KeePassXC`) that the desktop login usually unlocks.

## Design

Enrollment draws a random 256-bit key-encrypting key (KEK) from the OS random source,
stores it in the credential store as service `open-sesame`, account `vault-kek:<profile>`,
and writes the vault's master key wrapped under it (`WrappedKey`, AES-256-GCM) to
`<config dir>/vaults/<profile>.keyring-enrollment`. Unlock reads the KEK back and unwraps.

- Neither half alone yields the master key: the enrollment file decrypts nothing without the
  keyring item, and the keyring item is a random key that decrypts nothing but that file.
- The KEK is never derived from a password, so a stolen enrollment file offers nothing to
  brute-force offline.
- Each enrollment draws a fresh KEK; re-enrolling replaces both halves.

## The Credential Store Seam

`core_types::CredentialStore` is the operating system's store of per-user secrets behind one
interface; each platform crate implements it and consumers hold an
`Arc<dyn CredentialStore>`:

| Method | Answer |
| --- | --- |
| `get(id)` | The secret in protected memory (`SensitiveBytes`), or `None` when no credential carries `id` |
| `set(id, label, secret)` | Stores the secret, replacing the credential carrying `id` |
| `delete(id)` | Whether a credential carried `id` |
| `vendor()`, `persistence()` | The implementation, and how long credentials last |

A missing credential is an answer, not an error. The errors are distinct
(`CredentialError`): `Unavailable` (no store reachable), `Locked` (not unlocked),
`Dismissed` (the user dismissed the store's prompt), `Ambiguous` (more than one credential
carries the id; the store holds items the caller did not write, and choosing one would be a
guess), and `Platform`.

| Platform | Implementation |
| --- | --- |
| Linux | `platform_linux::keyring::SecretServiceStore` |
| macOS | Keychain: not implemented (`platform-macos/src/keychain.rs`) |
| Windows | Credential Manager: not implemented (`platform-windows/src/credential.rs`) |

`core_daemon::credential_store()` connects the platform's store, or returns `None` (logged)
when the platform has none or it cannot be reached. Its callers are the CLI and
daemon-launcher ([Who Reads the KEK](#who-reads-the-kek)).

## Linux: SecretServiceStore

`SecretServiceStore` is built on oo7. `connect()` uses the Secret Service default collection
on the host, and the Secret portal's file keyring inside a Flatpak sandbox
(`oo7::Keyring::new`). `with_connection(connection)` uses the Secret Service on a given D-Bus
connection.

- Credentials are items with the attributes `service` and `username`, the convention
  libsecret's `secret-tool` and keyring-rs share
  (`secret-tool lookup service open-sesame username vault-kek:work` finds a vault's KEK).
- A locked collection is unlocked before every operation, which may raise the keyring's own
  prompt. A locked keyring is never read as an empty one.
- More than one item carrying the id is `Ambiguous` for `get` and `set`.

`platform-linux/tests/secret_service.rs` runs the store against oo7-daemon's Secret Service,
served in-process over a peer-to-peer D-Bus connection: round trip, replacement, deletion,
ambiguous items, and a collection locked through the Secret Service `Lock` method.

## Who Reads the KEK

The credential store is a service on the session D-Bus bus, and a process on that bus can also
ask the user's service manager (`org.freedesktop.systemd1`, `StartTransientUnit`) to run any
command. No sandboxed daemon is granted the bus ([Sandbox Model](../architecture/sandbox-model.md)),
so the factor is read only by processes outside a sandbox:

- `sesame unlock` (the CLI) reads it itself.
- The overlay's inline unlock (daemon-wm) asks daemon-launcher, the one daemon outside a
  sandbox, with `KeyringUnlockRequest { profile }`. daemon-launcher reads the KEK, unwraps the
  master key, and submits the factor to daemon-secrets; daemon-wm receives daemon-secrets' own
  answer (`FactorResponse`, `UnlockRejected`), relayed, or `KeyringUnlockFailed { reason }` when
  the factor could not be read. Neither the KEK nor the master key enters daemon-wm.
  daemon-launcher serves the request only from the bus-verified sender `daemon-wm`, since it
  unlocks a vault without the user.

This is the shape of the freedesktop Secret portal: the sandboxed client makes a narrow request
over an authenticated channel, and a trusted process outside the sandbox does the credential
access.

## Commands

| Command | Effect |
| --- | --- |
| `sesame keyring enroll -p <profiles>` | Enrolls the factor ([the enrollment transaction](./factor-architecture.md#enrollment-and-revocation)); requires the vault password |
| `sesame keyring status -p <profiles> [--json]` | Reports, per vault, the enrollment file, the metadata record, and the KEK's state in the store; the vault is ready only with all three |
| `sesame keyring revoke -p <profiles>` | Removes the enrollment file, the KEK, and the metadata record |

`status` reports each KEK state separately: `present`, `missing`, `malformed`,
`locked`, `dismissed`, `ambiguous`, `store-unavailable`, `failed`. A vault whose metadata
cannot be read is reported in its row with the reason; the store and the other vaults are
still reported. Reading the KEK may raise the keyring's unlock prompt.

## Failure Modes

| Condition | Result |
| --- | --- |
| No credential store reachable | The CLI's factor has no backend, and a vault requiring it names the factor; the overlay receives `KeyringUnlockFailed` and tries the next factor |
| daemon-launcher not running | The overlay's request fails and the next factor is tried |
| Keyring locked, prompt dismissed | `AuthError::Keyring(CredentialError::Dismissed)`; the next factor is tried |
| KEK deleted from the keyring | `AuthError::KeyringEntryMissing`, naming the credential and `sesame keyring enroll` |
| Keyring item not 32 bytes | `AuthError::MalformedKek`, naming the credential |
| Enrollment file damaged | `AuthError::InvalidBlob`, naming the file |
| A different KEK in the keyring | `AuthError::UnwrapFailed` |
