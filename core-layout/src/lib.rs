//! The PDS installation layout: the single owner of every location PDS
//! reads or writes.
//!
//! Two inputs determine every location:
//! - the process [`Environment`], read once by [`Environment::from_process`],
//!   the only code in the workspace that reads location-bearing or
//!   session-identity environment variables or platform directories;
//! - the platform, selected at compile time inside this crate.
//!
//! Every location is a pure derivation from a [`Layout`]. Binaries build one
//! [`Layout`] in `main` and pass it down; tests build one under a temporary
//! root with [`Layout::under`]. Sandbox rules are derived from the same
//! [`Layout`] as the code that opens the files, so the granted set and the
//! accessed set cannot diverge.
//!
//! A location whose input is absent is an [`Error::Missing`] naming the
//! input.
#![forbid(unsafe_code)]

pub mod file;

use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};

use core_types::TrustProfileName;

/// A location could not be derived.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// An input the location derives from is not set.
    #[error("cannot determine the {location}: {input} is not set")]
    Missing {
        /// The location that was requested.
        location: &'static str,
        /// The environment input it derives from.
        input: &'static str,
    },
    /// The platform has no such location.
    #[error("the {location} is not supported on this platform")]
    Unsupported {
        /// The location that was requested.
        location: &'static str,
    },
    /// An input the location derives from is set, but not in the one form
    /// it is derived from.
    #[error("cannot determine the {location}: {input} is {value:?}; {expected}")]
    Malformed {
        /// The location that was requested.
        location: &'static str,
        /// The environment input it derives from.
        input: &'static str,
        /// The input's value.
        value: String,
        /// The form the input must take.
        expected: &'static str,
    },
}

impl From<Error> for core_types::Error {
    fn from(e: Error) -> Self {
        Self::Config(e.to_string())
    }
}

/// Result alias for layout derivations.
pub type Result<T> = std::result::Result<T, Error>;

/// The location-bearing process inputs. Plain data: production reads it
/// with [`Environment::from_process`]; tests construct it directly.
///
/// An empty environment value is treated as unset: it names no directory
/// or socket.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Environment {
    /// User configuration base (`$XDG_CONFIG_HOME`, `~/.config` on Linux).
    pub config_home: Option<PathBuf>,
    /// User cache base (`$XDG_CACHE_HOME`, `~/.cache` on Linux).
    pub cache_home: Option<PathBuf>,
    /// User data base (`$XDG_DATA_HOME`, `~/.local/share` on Linux).
    pub data_home: Option<PathBuf>,
    /// The user's home directory.
    pub home: Option<PathBuf>,
    /// Session runtime directory (`$XDG_RUNTIME_DIR`).
    pub runtime_dir: Option<PathBuf>,
    /// Wayland display name or socket path (`$WAYLAND_DISPLAY`).
    pub wayland_display: Option<OsString>,
    /// SSH agent socket (`$SSH_AUTH_SOCK`).
    pub ssh_auth_sock: Option<PathBuf>,
    /// systemd notification socket (`$NOTIFY_SOCKET`); `@`-prefixed values
    /// name abstract sockets.
    pub notify_socket: Option<OsString>,
    /// The system D-Bus bus address (`$DBUS_SYSTEM_BUS_ADDRESS`).
    pub system_bus_address: Option<OsString>,
    /// Workspace root override (`$SESAME_WORKSPACE_ROOT`), taking
    /// precedence over the configured `[settings] root`.
    pub workspace_root: Option<PathBuf>,
    /// The login user name (`$USER`).
    pub login_user: Option<OsString>,
    /// The user's login shell (`$SHELL`).
    pub login_shell: Option<PathBuf>,
    /// The graphical session type (`$XDG_SESSION_TYPE`: `wayland`, `x11`, ...).
    pub session_type: Option<OsString>,
    /// The system data directories, colon-separated (`$XDG_DATA_DIRS`).
    pub data_dirs: Option<OsString>,
    /// Explicit extra configuration read roots (`$SESAME_CONFIG_READ_ROOTS`,
    /// platform path-list syntax). These grant entire directory trees.
    pub config_read_roots: Option<OsString>,
}

impl Environment {
    /// Read the location-bearing inputs of this process.
    ///
    /// The only reader of these environment variables and platform
    /// directories in the workspace.
    #[must_use]
    #[expect(
        clippy::disallowed_methods,
        reason = "the single owner of location-bearing process inputs"
    )]
    pub fn from_process() -> Self {
        let var = |name: &str| std::env::var_os(name).filter(|value| !value.is_empty());
        Self {
            config_home: dirs::config_dir(),
            cache_home: dirs::cache_dir(),
            data_home: dirs::data_dir(),
            home: dirs::home_dir(),
            runtime_dir: var("XDG_RUNTIME_DIR").map(PathBuf::from),
            wayland_display: var("WAYLAND_DISPLAY"),
            ssh_auth_sock: var("SSH_AUTH_SOCK").map(PathBuf::from),
            notify_socket: var("NOTIFY_SOCKET"),
            system_bus_address: var("DBUS_SYSTEM_BUS_ADDRESS"),
            workspace_root: var("SESAME_WORKSPACE_ROOT").map(PathBuf::from),
            login_user: var("USER"),
            login_shell: var("SHELL").map(PathBuf::from),
            session_type: var("XDG_SESSION_TYPE"),
            data_dirs: var("XDG_DATA_DIRS"),
            config_read_roots: var("SESAME_CONFIG_READ_ROOTS"),
        }
    }
}

/// A file belonging to one profile's vault, under [`Layout::vaults_dir`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultFile {
    /// The `SQLCipher` database (`<profile>.db`).
    Database,
    /// The key-derivation salt (`<profile>.salt`).
    Salt,
    /// Enrolled factors and auth policy (`<profile>.vault-meta`).
    Metadata,
    /// The password-wrapped master key (`<profile>.password-wrap`).
    PasswordWrap,
    /// The SSH-agent-wrapped master key (`<profile>.ssh-enrollment`).
    SshEnrollment,
    /// The master key wrapped under the platform keyring's KEK
    /// (`<profile>.keyring-enrollment`).
    KeyringEnrollment,
}

impl VaultFile {
    /// Every vault file kind.
    pub const ALL: [Self; 6] = [
        Self::Database,
        Self::Salt,
        Self::Metadata,
        Self::PasswordWrap,
        Self::SshEnrollment,
        Self::KeyringEnrollment,
    ];

    /// The file extension, which is also the suffix after `<profile>.`.
    #[must_use]
    pub const fn extension(self) -> &'static str {
        match self {
            Self::Database => "db",
            Self::Salt => "salt",
            Self::Metadata => "vault-meta",
            Self::PasswordWrap => "password-wrap",
            Self::SshEnrollment => "ssh-enrollment",
            Self::KeyringEnrollment => "keyring-enrollment",
        }
    }
}

/// One file of a daemon's Noise IK keypair under
/// [`Layout::keys_dir`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyFile {
    /// The public key (`.pub`, mode 0644).
    Public,
    /// The private key (`.key`, mode 0600).
    Private,
    /// The tamper-detection checksum (`.checksum`, mode 0600), written
    /// last.
    Checksum,
}

impl KeyFile {
    /// The file extension.
    #[must_use]
    pub const fn extension(self) -> &'static str {
        match self {
            Self::Public => "pub",
            Self::Private => "key",
            Self::Checksum => "checksum",
        }
    }
}

/// Application directory name under the user configuration base and the
/// session runtime directory.
const PDS: &str = "pds";
/// Application directory name under the user cache base.
const CACHE_APP: &str = "open-sesame";

/// Every location PDS reads or writes, derived from one [`Environment`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Layout {
    env: Environment,
    /// The system policy file: the platform location, or beneath the root
    /// of a [`Layout::under`] layout.
    system_policy: Option<PathBuf>,
    /// The machine identity file: the platform location, or beneath the
    /// root of a [`Layout::under`] layout.
    machine_id: Option<PathBuf>,
    /// The process information filesystem.
    proc_root: Option<PathBuf>,
    /// The group database.
    group_database: Option<PathBuf>,
    /// The directory holding kernel build configurations.
    boot_dir: Option<PathBuf>,
    /// The system D-Bus socket when `$DBUS_SYSTEM_BUS_ADDRESS` is unset.
    system_bus: Option<PathBuf>,
    deployment_root: PathBuf,
}

/// The platform's system files, or `None` where the platform has none.
struct PlatformFiles {
    system_policy: Option<&'static str>,
    machine_id: Option<&'static str>,
    proc_root: Option<&'static str>,
    group_database: Option<&'static str>,
    boot_dir: Option<&'static str>,
    system_bus: Option<&'static str>,
}

#[cfg(target_os = "linux")]
const PLATFORM_FILES: PlatformFiles = PlatformFiles {
    system_policy: Some("/etc/pds/policy.toml"),
    machine_id: Some("/etc/machine-id"),
    proc_root: Some("/proc"),
    group_database: Some("/etc/group"),
    boot_dir: Some("/boot"),
    // The D-Bus specification's default system bus address.
    system_bus: Some("/var/run/dbus/system_bus_socket"),
};

#[cfg(not(target_os = "linux"))]
const PLATFORM_FILES: PlatformFiles = PlatformFiles {
    system_policy: None,
    machine_id: None,
    proc_root: None,
    group_database: None,
    boot_dir: None,
    system_bus: None,
};

/// The location name of the system D-Bus socket.
const SYSTEM_BUS: &str = "system D-Bus socket";

/// The socket of a D-Bus address that is exactly one `unix:path=` address
/// (a `guid=` key is allowed), its value unescaped per the D-Bus
/// specification (`%XX` hex escapes). The path is absolute.
fn unix_path_address(address: &OsStr) -> Option<PathBuf> {
    let params = address.to_str()?.strip_prefix("unix:")?;
    if params.contains(';') {
        return None;
    }
    let mut path = None;
    for pair in params.split(',') {
        match pair.split_once('=')? {
            ("path", value) if path.is_none() => path = Some(unescape_address_value(value)?),
            ("guid", _) => {}
            _ => return None,
        }
    }
    path.filter(|path| path.starts_with('/')).map(PathBuf::from)
}

/// A D-Bus address value with its `%XX` escapes decoded; `None` for a
/// truncated or non-hex escape, or bytes that are not UTF-8.
fn unescape_address_value(value: &str) -> Option<String> {
    let mut bytes = Vec::with_capacity(value.len());
    let mut rest = value.as_bytes();
    while let Some((&byte, tail)) = rest.split_first() {
        if byte == b'%' {
            let (hex, after) = tail.split_at_checked(2)?;
            if !hex.iter().all(u8::is_ascii_hexdigit) {
                return None;
            }
            bytes.push(u8::from_str_radix(std::str::from_utf8(hex).ok()?, 16).ok()?);
            rest = after;
        } else {
            bytes.push(byte);
            rest = tail;
        }
    }
    String::from_utf8(bytes).ok()
}

impl Layout {
    /// The layout of this process: [`Environment::from_process`].
    #[must_use]
    pub fn from_process() -> Self {
        Self::new(Environment::from_process())
    }

    /// The layout derived from `env`, with the platform's system policy.
    #[must_use]
    pub fn new(env: Environment) -> Self {
        Self {
            env,
            system_policy: PLATFORM_FILES.system_policy.map(PathBuf::from),
            machine_id: PLATFORM_FILES.machine_id.map(PathBuf::from),
            proc_root: PLATFORM_FILES.proc_root.map(PathBuf::from),
            group_database: PLATFORM_FILES.group_database.map(PathBuf::from),
            boot_dir: PLATFORM_FILES.boot_dir.map(PathBuf::from),
            system_bus: PLATFORM_FILES.system_bus.map(PathBuf::from),
            deployment_root: PathBuf::from("/nix/store"),
        }
    }

    /// A layout with every input set beneath `root`: `root/config`,
    /// `root/cache`, `root/data`, `root/home`, `root/runtime`, system policy
    /// `root/etc/pds/policy.toml`, machine identity `root/etc/machine-id`,
    /// process filesystem `root/proc`, group database `root/etc/group`,
    /// kernel configurations in `root/boot`, system D-Bus socket
    /// `root/run/dbus/system_bus_socket`, Wayland display
    /// `wayland-test`, SSH agent
    /// `root/runtime/ssh-agent.sock`, no systemd notification socket, no
    /// workspace root override (the configured root applies), and no
    /// session identity (login user, shell, session type, desktop).
    /// For tests and isolated runs: every location is beneath `root`.
    #[must_use]
    pub fn under(root: &Path) -> Self {
        Self {
            env: Environment {
                config_home: Some(root.join("config")),
                cache_home: Some(root.join("cache")),
                data_home: Some(root.join("data")),
                home: Some(root.join("home")),
                runtime_dir: Some(root.join("runtime")),
                wayland_display: Some("wayland-test".into()),
                ssh_auth_sock: Some(root.join("runtime").join("ssh-agent.sock")),
                notify_socket: None,
                system_bus_address: None,
                workspace_root: None,
                login_user: None,
                login_shell: None,
                session_type: None,
                data_dirs: Some(root.join("share").into_os_string()),
                config_read_roots: None,
            },
            system_policy: Some(root.join("etc").join(PDS).join("policy.toml")),
            machine_id: Some(root.join("etc").join("machine-id")),
            proc_root: Some(root.join("proc")),
            group_database: Some(root.join("etc").join("group")),
            boot_dir: Some(root.join("boot")),
            system_bus: Some(root.join("run").join("dbus").join("system_bus_socket")),
            deployment_root: root.join("nix/store"),
        }
    }

    /// The inputs this layout derives from.
    #[must_use]
    pub fn environment(&self) -> &Environment {
        &self.env
    }

    fn required<'a>(
        value: Option<&'a PathBuf>,
        location: &'static str,
        input: &'static str,
    ) -> Result<&'a Path> {
        value
            .map(PathBuf::as_path)
            .ok_or(Error::Missing { location, input })
    }

    // -- User bases ---------------------------------------------------------

    /// The user configuration base (`$XDG_CONFIG_HOME`), parent of
    /// [`config_dir`](Self::config_dir); other applications' configuration
    /// (COSMIC) lives beneath it.
    ///
    /// # Errors
    ///
    /// [`Error::Missing`] when neither `$XDG_CONFIG_HOME` nor `$HOME` is set.
    pub fn user_config_base(&self) -> Result<&Path> {
        Self::required(
            self.env.config_home.as_ref(),
            "user configuration directory",
            "$XDG_CONFIG_HOME or $HOME",
        )
    }

    /// The user data base (`$XDG_DATA_HOME`).
    ///
    /// # Errors
    ///
    /// [`Error::Missing`] when neither `$XDG_DATA_HOME` nor `$HOME` is set.
    pub fn user_data_base(&self) -> Result<&Path> {
        Self::required(
            self.env.data_home.as_ref(),
            "user data directory",
            "$XDG_DATA_HOME or $HOME",
        )
    }

    /// The user's home directory.
    ///
    /// # Errors
    ///
    /// [`Error::Missing`] when `$HOME` is not set.
    pub fn home(&self) -> Result<&Path> {
        Self::required(self.env.home.as_ref(), "home directory", "$HOME")
    }

    // -- Configuration ------------------------------------------------------

    /// The PDS configuration directory (`<user config base>/pds`).
    ///
    /// # Errors
    ///
    /// The [`user_config_base`](Self::user_config_base) errors.
    pub fn config_dir(&self) -> Result<PathBuf> {
        Ok(self.user_config_base()?.join(PDS))
    }

    /// Declared read-only deployment roots, independent of current symlink targets.
    ///
    /// The immutable Nix store is an intentional whole-tree grant. Additional
    /// deployments declare stable roots in the service environment before startup.
    /// Roots must exist when Landlock is installed; adding a root requires restart.
    ///
    /// # Errors
    ///
    /// An explicitly declared root is relative or contains a parent traversal.
    pub fn config_read_roots(&self) -> Result<Vec<PathBuf>> {
        let mut roots = vec![self.deployment_root.clone()];
        if let Some(parent) = self.system_policy_file().and_then(Path::parent) {
            roots.push(parent.to_path_buf());
        }
        if let Some(value) = &self.env.config_read_roots {
            for root in std::env::split_paths(value) {
                if !root.is_absolute()
                    || root
                        .components()
                        .any(|part| part == std::path::Component::ParentDir)
                {
                    return Err(Error::Malformed {
                        location: "configuration read roots",
                        input: "$SESAME_CONFIG_READ_ROOTS",
                        value: value.to_string_lossy().into_owned(),
                        expected: "absolute paths without parent traversal",
                    });
                }
                roots.push(root);
            }
        }
        roots.sort();
        roots.dedup();
        Ok(roots)
    }

    /// The user configuration file (`<config dir>/config.toml`).
    ///
    /// # Errors
    ///
    /// The [`config_dir`](Self::config_dir) errors.
    pub fn config_file(&self) -> Result<PathBuf> {
        Ok(self.config_dir()?.join("config.toml"))
    }

    /// The drop-in fragment directory (`<config dir>/config.d`).
    ///
    /// # Errors
    ///
    /// The [`config_dir`](Self::config_dir) errors.
    pub fn config_drop_in_dir(&self) -> Result<PathBuf> {
        Ok(self.config_dir()?.join("config.d"))
    }

    /// The per-profile override directory (`<config dir>/profiles`).
    ///
    /// # Errors
    ///
    /// The [`config_dir`](Self::config_dir) errors.
    pub fn profiles_dir(&self) -> Result<PathBuf> {
        Ok(self.config_dir()?.join("profiles"))
    }

    /// One profile's override file (`<profiles dir>/<profile>/config.toml`).
    ///
    /// # Errors
    ///
    /// The [`config_dir`](Self::config_dir) errors.
    pub fn profile_config_file(&self, profile: &TrustProfileName) -> Result<PathBuf> {
        Ok(self
            .profiles_dir()?
            .join(profile.as_ref())
            .join("config.toml"))
    }

    /// The workspace configuration base file (`<config dir>/workspaces.toml`).
    ///
    /// # Errors
    ///
    /// The [`config_dir`](Self::config_dir) errors.
    pub fn workspaces_file(&self) -> Result<PathBuf> {
        Ok(self.config_dir()?.join("workspaces.toml"))
    }

    /// The workspace configuration fragment directory
    /// (`<config dir>/workspaces.d`).
    ///
    /// # Errors
    ///
    /// The [`config_dir`](Self::config_dir) errors.
    pub fn workspaces_drop_in_dir(&self) -> Result<PathBuf> {
        Ok(self.config_dir()?.join("workspaces.d"))
    }

    /// The system policy file, the lowest and read-only configuration layer
    /// (`/etc/pds/policy.toml` on Linux). `None` on platforms without one.
    /// Whether it exists is the reader's concern.
    #[must_use]
    pub fn system_policy_file(&self) -> Option<&Path> {
        self.system_policy.as_deref()
    }

    /// The machine identity file (`/etc/machine-id` on Linux,
    /// machine-id(5)), source of the installation's machine binding. `None`
    /// on platforms without one. Whether it exists is the reader's concern.
    #[must_use]
    pub fn machine_id_file(&self) -> Option<&Path> {
        self.machine_id.as_deref()
    }

    /// The process information filesystem (`/proc` on Linux), read by
    /// `sesame status --doctor`. `None` on platforms without one.
    #[must_use]
    pub fn proc_root(&self) -> Option<&Path> {
        self.proc_root.as_deref()
    }

    /// The group database (`/etc/group`, group(5)). `None` on platforms
    /// without one.
    #[must_use]
    pub fn group_database(&self) -> Option<&Path> {
        self.group_database.as_deref()
    }

    /// The kernel build configuration of `release` installed by the
    /// distribution (`/boot/config-<release>` on Linux). `None` on
    /// platforms without one.
    #[must_use]
    pub fn kernel_config_file(&self, release: &str) -> Option<PathBuf> {
        self.boot_dir
            .as_ref()
            .map(|boot| boot.join(format!("config-{release}")))
    }

    /// The installation identity (`<config dir>/installation.toml`).
    ///
    /// # Errors
    ///
    /// The [`config_dir`](Self::config_dir) errors.
    pub fn installation_file(&self) -> Result<PathBuf> {
        Ok(self.config_dir()?.join("installation.toml"))
    }

    /// The lock cooperating configuration writers hold during commit and
    /// interrupted-publication recovery (`<config dir>/.lock`).
    ///
    /// # Errors
    ///
    /// The [`config_dir`](Self::config_dir) errors.
    pub fn config_lock_file(&self) -> Result<PathBuf> {
        Ok(self.config_dir()?.join(".lock"))
    }

    /// The configuration journal (`<config dir>/.revision`), containing a
    /// stable revision or pending publication's undo records. Readers accept
    /// only observations bounded by the same stable revision.
    ///
    /// # Errors
    ///
    /// The [`config_dir`](Self::config_dir) errors.
    pub fn config_revision_file(&self) -> Result<PathBuf> {
        Ok(self.config_dir()?.join(".revision"))
    }

    /// The hash-chained audit log (`<config dir>/audit.jsonl`).
    ///
    /// # Errors
    ///
    /// The [`config_dir`](Self::config_dir) errors.
    pub fn audit_log(&self) -> Result<PathBuf> {
        Ok(self.config_dir()?.join("audit.jsonl"))
    }

    /// The vault directory (`<config dir>/vaults`).
    ///
    /// # Errors
    ///
    /// The [`config_dir`](Self::config_dir) errors.
    pub fn vaults_dir(&self) -> Result<PathBuf> {
        Ok(self.config_dir()?.join("vaults"))
    }

    /// One file of `profile`'s vault (`<vaults dir>/<profile>.<extension>`).
    ///
    /// # Errors
    ///
    /// The [`config_dir`](Self::config_dir) errors.
    pub fn vault_file(&self, profile: &TrustProfileName, file: VaultFile) -> Result<PathBuf> {
        Ok(self
            .vaults_dir()?
            .join(format!("{profile}.{}", file.extension())))
    }

    /// The launcher's per-profile frecency database
    /// (`<config dir>/launcher/<profile>.frecency.db`).
    ///
    /// # Errors
    ///
    /// The [`config_dir`](Self::config_dir) errors.
    pub fn frecency_db(&self, profile: &TrustProfileName) -> Result<PathBuf> {
        Ok(self
            .config_dir()?
            .join("launcher")
            .join(format!("{profile}.frecency.db")))
    }

    /// The COSMIC desktop configuration directory
    /// (`<user config base>/cosmic`).
    ///
    /// # Errors
    ///
    /// The [`user_config_base`](Self::user_config_base) errors.
    pub fn cosmic_config_dir(&self) -> Result<PathBuf> {
        Ok(self.user_config_base()?.join("cosmic"))
    }

    // -- Cache --------------------------------------------------------------

    /// The PDS cache directory (`<user cache base>/open-sesame`).
    ///
    /// # Errors
    ///
    /// [`Error::Missing`] when neither `$XDG_CACHE_HOME` nor `$HOME` is set.
    pub fn cache_dir(&self) -> Result<PathBuf> {
        Ok(Self::required(
            self.env.cache_home.as_ref(),
            "user cache directory",
            "$XDG_CACHE_HOME or $HOME",
        )?
        .join(CACHE_APP))
    }

    /// The clipboard history database (`<cache dir>/clipboard.db`).
    ///
    /// # Errors
    ///
    /// The [`cache_dir`](Self::cache_dir) errors.
    pub fn clipboard_db(&self) -> Result<PathBuf> {
        Ok(self.cache_dir()?.join("clipboard.db"))
    }

    /// The window switcher's most-recently-used stack (`<cache dir>/mru`).
    ///
    /// # Errors
    ///
    /// The [`cache_dir`](Self::cache_dir) errors.
    pub fn mru_file(&self) -> Result<PathBuf> {
        Ok(self.cache_dir()?.join("mru"))
    }

    // -- Session runtime ----------------------------------------------------

    /// The session runtime directory (`$XDG_RUNTIME_DIR`), parent of
    /// [`runtime_dir`](Self::runtime_dir); session sockets (D-Bus, Wayland)
    /// live in it.
    ///
    /// # Errors
    ///
    /// [`Error::Missing`] when `$XDG_RUNTIME_DIR` is not set.
    pub fn session_runtime_dir(&self) -> Result<&Path> {
        Self::required(
            self.env.runtime_dir.as_ref(),
            "session runtime directory",
            "$XDG_RUNTIME_DIR",
        )
    }

    /// The PDS runtime directory (`$XDG_RUNTIME_DIR/pds`): the per-daemon
    /// keys, the bus endpoint, the bus socket on Linux, and per-daemon
    /// runtime files.
    ///
    /// # Errors
    ///
    /// [`Error::Missing`] when `$XDG_RUNTIME_DIR` is not set.
    pub fn runtime_dir(&self) -> Result<PathBuf> {
        Ok(self.session_runtime_dir()?.join(PDS))
    }

    /// The per-daemon keypair directory (`<runtime dir>/keys`).
    ///
    /// # Errors
    ///
    /// The [`runtime_dir`](Self::runtime_dir) errors.
    pub fn keys_dir(&self) -> Result<PathBuf> {
        Ok(self.runtime_dir()?.join("keys"))
    }

    /// The bus server's published endpoint (`<runtime dir>/bus.endpoint`,
    /// mode 0644): the Noise protocol name it bound with and its static
    /// public key. Clients handshake with exactly what it holds. The
    /// server's private key is never written to disk.
    ///
    /// # Errors
    ///
    /// The [`runtime_dir`](Self::runtime_dir) errors.
    pub fn bus_endpoint_file(&self) -> Result<PathBuf> {
        Ok(self.runtime_dir()?.join("bus.endpoint"))
    }

    /// One file of `daemon`'s keypair (`<keys dir>/<daemon>.<ext>`).
    ///
    /// # Errors
    ///
    /// The [`runtime_dir`](Self::runtime_dir) errors.
    pub fn daemon_key_file(&self, daemon: &str, file: KeyFile) -> Result<PathBuf> {
        Ok(self
            .keys_dir()?
            .join(format!("{daemon}.{}", file.extension())))
    }

    /// The IPC bus Unix domain socket the bus server binds.
    ///
    /// - Linux: `<runtime dir>/bus.sock`.
    /// - macOS: `~/Library/Application Support/pds/bus.sock`.
    ///
    /// # Errors
    ///
    /// [`Error::Missing`] when its input is unset, and
    /// [`Error::Unsupported`] on platforms without Unix domain sockets.
    pub fn bus_socket(&self) -> Result<PathBuf> {
        #[cfg(target_os = "linux")]
        {
            Ok(self.runtime_dir()?.join("bus.sock"))
        }
        #[cfg(target_os = "macos")]
        {
            Ok(self
                .home()?
                .join("Library/Application Support")
                .join(PDS)
                .join("bus.sock"))
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            Err(Error::Unsupported {
                location: "IPC bus socket",
            })
        }
    }

    /// The window-switcher fast-path resident's pid file and datagram
    /// socket (`<runtime dir>/wm-fast.pid`, `<runtime dir>/wm-fast.sock`).
    ///
    /// # Errors
    ///
    /// The [`runtime_dir`](Self::runtime_dir) errors.
    pub fn wm_fast_path_files(&self) -> Result<(PathBuf, PathBuf)> {
        let dir = self.runtime_dir()?;
        Ok((dir.join("wm-fast.pid"), dir.join("wm-fast.sock")))
    }

    /// The system D-Bus socket: the `unix:path=` address of
    /// `$DBUS_SYSTEM_BUS_ADDRESS`, or, when it is unset, the D-Bus
    /// specification's default (`/var/run/dbus/system_bus_socket` on
    /// Linux). Clients connect to this path and sandboxes grant it, so the
    /// two cannot diverge.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] when `$DBUS_SYSTEM_BUS_ADDRESS` is not exactly
    /// one `unix:path=` address with an absolute path, and
    /// [`Error::Unsupported`] on platforms without a system bus.
    pub fn system_bus_socket(&self) -> Result<PathBuf> {
        let Some(address) = &self.env.system_bus_address else {
            return self.system_bus.clone().ok_or(Error::Unsupported {
                location: SYSTEM_BUS,
            });
        };
        unix_path_address(address).ok_or_else(|| Error::Malformed {
            location: SYSTEM_BUS,
            input: "$DBUS_SYSTEM_BUS_ADDRESS",
            value: address.to_string_lossy().into_owned(),
            expected: "the supported form is one unix:path=<absolute socket path> address",
        })
    }

    /// The Wayland compositor socket: `$WAYLAND_DISPLAY` resolved against
    /// `$XDG_RUNTIME_DIR` (an absolute `$WAYLAND_DISPLAY` is used as is, per
    /// the Wayland client connection rules).
    ///
    /// # Errors
    ///
    /// [`Error::Missing`] when `$WAYLAND_DISPLAY` or `$XDG_RUNTIME_DIR` is
    /// not set.
    pub fn wayland_socket(&self) -> Result<PathBuf> {
        let display = self.env.wayland_display.as_ref().ok_or(Error::Missing {
            location: "Wayland compositor socket",
            input: "$WAYLAND_DISPLAY",
        })?;
        Ok(self.session_runtime_dir()?.join(display))
    }

    // -- Workspaces ---------------------------------------------------------

    /// The workspace root set by the environment
    /// (`$SESAME_WORKSPACE_ROOT`), which takes precedence over the
    /// configured `[settings] root`. `None` when it is not set.
    #[must_use]
    pub fn workspace_root_override(&self) -> Option<&Path> {
        self.env.workspace_root.as_deref()
    }

    // -- Session identity ---------------------------------------------------

    /// The login user name (`$USER`), `None` when unset.
    #[must_use]
    pub fn login_user(&self) -> Option<&OsStr> {
        self.env.login_user.as_deref()
    }

    /// The login shell (`$SHELL`), `None` when unset.
    #[must_use]
    pub fn login_shell(&self) -> Option<&Path> {
        self.env.login_shell.as_deref()
    }

    /// The graphical session type (`$XDG_SESSION_TYPE`), `None` when unset.
    #[must_use]
    pub fn session_type(&self) -> Option<&OsStr> {
        self.env.session_type.as_deref()
    }

    /// The system data directories in precedence order: `$XDG_DATA_DIRS`,
    /// or `/usr/local/share:/usr/share` when unset (XDG Base Directory
    /// Specification). Relative entries are ignored, as the specification
    /// requires.
    #[must_use]
    pub fn system_data_dirs(&self) -> Vec<PathBuf> {
        let list = self
            .env
            .data_dirs
            .clone()
            .unwrap_or_else(|| "/usr/local/share:/usr/share".into());
        std::env::split_paths(&list)
            .filter(|dir| dir.is_absolute())
            .collect()
    }

    /// The directories COSMIC's default shortcut configuration is read from
    /// (`<system data dir>/cosmic/com.system76.CosmicSettings.Shortcuts`),
    /// in precedence order.
    #[must_use]
    pub fn cosmic_shortcut_defaults(&self) -> Vec<PathBuf> {
        self.system_data_dirs()
            .into_iter()
            .map(|dir| {
                dir.join("cosmic")
                    .join("com.system76.CosmicSettings.Shortcuts")
            })
            .collect()
    }

    // -- External agents ----------------------------------------------------

    /// The SSH agent socket candidates in discovery order: `$SSH_AUTH_SOCK`
    /// (set by ssh-agent, sshd forwarding, or the systemd environment), then
    /// `~/.ssh/agent.sock` (a stable symlink to a forwarded agent that login
    /// hooks maintain for systemd user services, whose environment lacks
    /// the forwarded `$SSH_AUTH_SOCK`). Each candidate is present only when
    /// its input is set. Agent clients try them in order; sandboxes grant
    /// all of them.
    #[must_use]
    pub fn ssh_agent_sockets(&self) -> Vec<PathBuf> {
        self.env
            .ssh_auth_sock
            .iter()
            .cloned()
            .chain(
                self.env
                    .home
                    .iter()
                    .map(|home| home.join(".ssh").join("agent.sock")),
            )
            .collect()
    }

    /// The systemd notification socket, when it is a filesystem socket.
    /// Abstract sockets (`@`-prefixed) have no path and need no filesystem
    /// access.
    #[must_use]
    pub fn notify_socket_path(&self) -> Option<PathBuf> {
        self.env
            .notify_socket
            .as_ref()
            .filter(|value| !value.as_encoded_bytes().starts_with(b"@"))
            .map(PathBuf::from)
    }

    // -- Creation -----------------------------------------------------------

    /// Create the configuration, cache, and (when `$XDG_RUNTIME_DIR` is set)
    /// runtime directories. Directory creation is application-owned, not
    /// left to systemd tmpfiles.d or another init-system mechanism.
    ///
    /// On Unix every directory this creates is mode 0700, and the three PDS
    /// directories are set to 0700 when they already exist: they hold
    /// vaults, the audit log, clipboard history, and IPC keys.
    ///
    /// # Errors
    ///
    /// The [`config_dir`](Self::config_dir) and
    /// [`cache_dir`](Self::cache_dir) errors, and `core_types::Error::Io`
    /// naming the directory that cannot be created or restricted.
    pub fn bootstrap(&self) -> core_types::Result<()> {
        let mut dirs = vec![self.config_dir()?, self.cache_dir()?];
        if self.env.runtime_dir.is_some() {
            dirs.push(self.runtime_dir()?);
        }
        for dir in &dirs {
            file::create_private_dir(dir)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile(name: &str) -> TrustProfileName {
        TrustProfileName::try_from(name).unwrap()
    }

    #[test]
    fn locations_derive_from_their_bases() {
        let root = Path::new("/r");
        let layout = Layout::under(root);
        assert_eq!(layout.config_dir().unwrap(), root.join("config/pds"));
        assert_eq!(
            layout.config_file().unwrap(),
            root.join("config/pds/config.toml")
        );
        assert_eq!(
            layout.config_drop_in_dir().unwrap(),
            root.join("config/pds/config.d")
        );
        assert_eq!(
            layout.profile_config_file(&profile("work")).unwrap(),
            root.join("config/pds/profiles/work/config.toml")
        );
        assert_eq!(
            layout.installation_file().unwrap(),
            root.join("config/pds/installation.toml")
        );
        assert_eq!(
            layout.audit_log().unwrap(),
            root.join("config/pds/audit.jsonl")
        );
        assert_eq!(
            layout.config_lock_file().unwrap(),
            root.join("config/pds/.lock")
        );
        assert_eq!(
            layout.config_revision_file().unwrap(),
            root.join("config/pds/.revision")
        );
        assert_eq!(
            layout.workspaces_file().unwrap(),
            root.join("config/pds/workspaces.toml")
        );
        assert_eq!(
            layout.workspaces_drop_in_dir().unwrap(),
            root.join("config/pds/workspaces.d")
        );
        assert_eq!(
            layout.system_policy_file(),
            Some(root.join("etc/pds/policy.toml").as_path())
        );
        assert_eq!(
            layout.machine_id_file(),
            Some(root.join("etc/machine-id").as_path())
        );
        assert_eq!(layout.proc_root(), Some(root.join("proc").as_path()));
        assert_eq!(
            layout.group_database(),
            Some(root.join("etc/group").as_path())
        );
        assert_eq!(
            layout.kernel_config_file("6.9.0"),
            Some(root.join("boot/config-6.9.0"))
        );
        assert_eq!(layout.cache_dir().unwrap(), root.join("cache/open-sesame"));
        assert_eq!(
            layout.clipboard_db().unwrap(),
            root.join("cache/open-sesame/clipboard.db")
        );
        assert_eq!(
            layout.mru_file().unwrap(),
            root.join("cache/open-sesame/mru")
        );
        assert_eq!(
            layout.frecency_db(&profile("work")).unwrap(),
            root.join("config/pds/launcher/work.frecency.db")
        );
        assert_eq!(
            layout.cosmic_config_dir().unwrap(),
            root.join("config/cosmic")
        );
        assert_eq!(layout.runtime_dir().unwrap(), root.join("runtime/pds"));
        assert_eq!(layout.keys_dir().unwrap(), root.join("runtime/pds/keys"));
        assert_eq!(
            layout.system_bus_socket().unwrap(),
            root.join("run/dbus/system_bus_socket")
        );
        assert_eq!(
            layout.wayland_socket().unwrap(),
            root.join("runtime/wayland-test")
        );
        assert_eq!(
            layout.wm_fast_path_files().unwrap(),
            (
                root.join("runtime/pds/wm-fast.pid"),
                root.join("runtime/pds/wm-fast.sock")
            )
        );
        assert_eq!(layout.workspace_root_override(), None);
        let overridden = Layout::new(Environment {
            workspace_root: Some("/srv/workspace".into()),
            ..Environment::default()
        });
        assert_eq!(
            overridden.workspace_root_override(),
            Some(Path::new("/srv/workspace"))
        );
    }

    #[test]
    fn vault_files_are_profile_scoped() {
        let layout = Layout::under(Path::new("/r"));
        let work = profile("work");
        let names: Vec<PathBuf> = VaultFile::ALL
            .iter()
            .map(|&file| layout.vault_file(&work, file).unwrap())
            .collect();
        let vaults = Path::new("/r/config/pds/vaults");
        assert_eq!(
            names,
            [
                vaults.join("work.db"),
                vaults.join("work.salt"),
                vaults.join("work.vault-meta"),
                vaults.join("work.password-wrap"),
                vaults.join("work.ssh-enrollment"),
                vaults.join("work.keyring-enrollment"),
            ]
        );
    }

    #[test]
    fn key_files_name_their_owner() {
        let layout = Layout::under(Path::new("/r"));
        assert_eq!(
            layout.bus_endpoint_file().unwrap(),
            Path::new("/r/runtime/pds/bus.endpoint")
        );
        assert_eq!(
            layout
                .daemon_key_file("daemon-wm", KeyFile::Checksum)
                .unwrap(),
            Path::new("/r/runtime/pds/keys/daemon-wm.checksum")
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn bus_socket_is_in_the_runtime_dir() {
        let layout = Layout::under(Path::new("/r"));
        assert_eq!(
            layout.bus_socket().unwrap(),
            Path::new("/r/runtime/pds/bus.sock")
        );
    }

    #[test]
    fn missing_inputs_are_named() {
        let layout = Layout::new(Environment::default());
        for (result, input) in [
            (layout.config_dir(), "$XDG_CONFIG_HOME or $HOME"),
            (layout.cache_dir(), "$XDG_CACHE_HOME or $HOME"),
            (layout.runtime_dir(), "$XDG_RUNTIME_DIR"),
        ] {
            match result {
                Err(Error::Missing { input: named, .. }) => assert_eq!(named, input),
                other => panic!("expected Missing({input}), got {other:?}"),
            }
        }
        let wayland = Layout::new(Environment {
            runtime_dir: Some("/run/user/0".into()),
            ..Environment::default()
        });
        assert!(matches!(
            wayland.wayland_socket(),
            Err(Error::Missing {
                input: "$WAYLAND_DISPLAY",
                ..
            })
        ));
    }

    #[test]
    fn absolute_wayland_display_is_used_as_is() {
        let layout = Layout::new(Environment {
            runtime_dir: Some("/run/user/0".into()),
            wayland_display: Some("/tmp/compositor.sock".into()),
            ..Environment::default()
        });
        assert_eq!(
            layout.wayland_socket().unwrap(),
            Path::new("/tmp/compositor.sock")
        );
    }

    #[test]
    fn ssh_agent_socket_discovery_order() {
        let both = Layout::new(Environment {
            ssh_auth_sock: Some("/run/agent".into()),
            home: Some("/home/alice".into()),
            ..Environment::default()
        });
        assert_eq!(
            both.ssh_agent_sockets(),
            [
                PathBuf::from("/run/agent"),
                PathBuf::from("/home/alice/.ssh/agent.sock")
            ]
        );
        let conventional = Layout::new(Environment {
            home: Some("/home/alice".into()),
            ..Environment::default()
        });
        assert_eq!(
            conventional.ssh_agent_sockets(),
            [PathBuf::from("/home/alice/.ssh/agent.sock")]
        );
        assert!(
            Layout::new(Environment::default())
                .ssh_agent_sockets()
                .is_empty()
        );
    }

    #[test]
    fn system_data_dirs_follow_the_xdg_default_and_skip_relative_entries() {
        assert_eq!(
            Layout::new(Environment::default()).system_data_dirs(),
            [Path::new("/usr/local/share"), Path::new("/usr/share")]
        );
        let set = Layout::new(Environment {
            data_dirs: Some("/nix/profile/share:relative/share::/usr/share".into()),
            ..Environment::default()
        });
        assert_eq!(
            set.system_data_dirs(),
            [Path::new("/nix/profile/share"), Path::new("/usr/share")]
        );
        assert_eq!(
            set.cosmic_shortcut_defaults()[1],
            Path::new("/usr/share/cosmic/com.system76.CosmicSettings.Shortcuts")
        );
    }

    #[test]
    fn abstract_notify_socket_has_no_path() {
        let with = |value: &str| {
            Layout::new(Environment {
                notify_socket: Some(value.into()),
                ..Environment::default()
            })
            .notify_socket_path()
        };
        assert_eq!(with("@/org/freedesktop/systemd1/notify"), None);
        assert_eq!(
            with("/run/systemd/notify"),
            Some("/run/systemd/notify".into())
        );
    }

    fn system_bus_with(address: Option<&str>) -> Result<PathBuf> {
        Layout::new(Environment {
            system_bus_address: address.map(OsString::from),
            ..Environment::default()
        })
        .system_bus_socket()
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn system_bus_defaults_to_the_specification_address() {
        assert_eq!(
            system_bus_with(None).unwrap(),
            Path::new("/var/run/dbus/system_bus_socket")
        );
    }

    #[test]
    fn system_bus_is_the_unix_path_of_the_address() {
        assert_eq!(
            system_bus_with(Some("unix:path=/run/dbus/system_bus_socket")).unwrap(),
            Path::new("/run/dbus/system_bus_socket")
        );
        assert_eq!(
            system_bus_with(Some("unix:path=/run/a%20b%2c,guid=0123456789abcdef")).unwrap(),
            Path::new("/run/a b,"),
            "escapes decode and a guid is allowed"
        );
    }

    #[test]
    fn a_system_bus_address_of_another_form_is_named() {
        for address in [
            "unix:abstract=/tmp/dbus-x",
            "tcp:host=localhost,port=1",
            "unix:path=/a;unix:path=/b",
            "unix:path=relative",
            "unix:path=",
            "unix:path=/a,path=/b",
            "unix:path=/a%2",
            "unix:path=/a%+1",
            "unix:path=/a,tmpdir=/tmp",
        ] {
            match system_bus_with(Some(address)) {
                Err(Error::Malformed { input, value, .. }) => {
                    assert_eq!(input, "$DBUS_SYSTEM_BUS_ADDRESS");
                    assert_eq!(value, address);
                }
                other => panic!("{address}: expected Malformed, got {other:?}"),
            }
        }
    }

    #[test]
    fn bootstrap_creates_config_cache_and_runtime() {
        let root = tempfile::tempdir().unwrap();
        let layout = Layout::under(root.path());
        layout.bootstrap().unwrap();
        for dir in [
            layout.config_dir().unwrap(),
            layout.cache_dir().unwrap(),
            layout.runtime_dir().unwrap(),
        ] {
            assert!(dir.is_dir(), "{}", dir.display());
        }
    }

    #[cfg(unix)]
    #[test]
    fn bootstrap_creates_owner_only_directories() {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        let layout = Layout::under(root.path());
        layout.bootstrap().unwrap();
        for dir in [
            layout.config_dir().unwrap(),
            layout.cache_dir().unwrap(),
            layout.runtime_dir().unwrap(),
        ] {
            let mode = std::fs::metadata(&dir).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o700, "{}", dir.display());
        }
    }

    #[test]
    fn bootstrap_without_runtime_skips_it() {
        let root = tempfile::tempdir().unwrap();
        let layout = Layout::new(Environment {
            config_home: Some(root.path().join("config")),
            cache_home: Some(root.path().join("cache")),
            ..Environment::default()
        });
        layout.bootstrap().unwrap();
        assert!(!root.path().join("runtime").exists());
    }
}
