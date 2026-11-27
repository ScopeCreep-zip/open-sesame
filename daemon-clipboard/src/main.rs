//! daemon-clipboard: clipboard history daemon.
//!
//! Captures each text selection of the Wayland clipboard
//! (`platform_linux::clipboard`, the data-control protocols) into the
//! history of the default profile as daemon-profile reports it
//! (`StatusResponse` at startup, then `DefaultProfileChanged`), and serves
//! the per-profile history over the bus: listings, single-entry content,
//! and clearing. Entries are filed under the installation-scoped profile
//! identity (`ProfileId::of_profile`), so nothing is recorded before
//! `sesame init` writes the installation identity.
//!
//! A selection its source marks secret (the password manager hint) is
//! held in memory only, for the profile's `clipboard.sensitive_ttl_s`, and
//! then expires (`ClipboardEntryExpired`); it is never written to disk.
//! Every other selection is written to the `SQLite` history, skipped when
//! it repeats the newest entry, and pruned to `clipboard.max_history`.
//!
//! Landlock: bus client, configuration (read), the systemd notification
//! socket, the Wayland socket, and the cache directory (history database).
//! No network access beyond local IPC.

use anyhow::Context;
use clap::Parser;
use core_config::{ClipboardConfig, Config};
use core_daemon::{DaemonIdentity, EventLoop, LogFormat, Shutdown, Wake};
use core_ipc::{BusClient, Message};
use core_types::{
    ClipboardEntry, ClipboardEntryId, Daemon, EventKind, ProfileId, SecurityLevel, SensitiveBytes,
    SensitivityClass, TrustProfileName,
};
use rusqlite::Connection;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const IDENTITY: DaemonIdentity = DaemonIdentity {
    daemon: Daemon::Clipboard,
    version: env!("CARGO_PKG_VERSION"),
    capabilities: &["clipboard", "history"],
};

/// How many characters of an entry its preview shows.
const PREVIEW_CHARS: usize = 80;
/// The preview of an entry held as a secret: none of its content.
const SECRET_PREVIEW: &str = "[secret]";
/// How long the startup query for the default profile waits.
const STATUS_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Parser, Debug)]
#[command(name = IDENTITY.daemon.name(), about = "Clipboard history daemon")]
struct Cli {
    #[arg(long, value_enum, default_value = "json", env = "PDS_LOG_FORMAT")]
    log_format: LogFormat,
}

/// Open the history database at `db_path` (in the cache directory
/// `core_daemon::startup` creates) and create its schema.
fn init_db(db_path: &std::path::Path) -> anyhow::Result<Connection> {
    let conn = Connection::open(db_path)
        .with_context(|| format!("failed to open clipboard database {}", db_path.display()))?;
    init_schema(&conn)?;
    Ok(conn)
}

/// The history schema. `profile_id` is the installation-scoped
/// `ProfileId` of the entry's profile.
fn init_schema(conn: &Connection) -> anyhow::Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS clipboard_entries (
            entry_id TEXT PRIMARY KEY,
            profile_id TEXT NOT NULL,
            content TEXT NOT NULL,
            content_type TEXT NOT NULL DEFAULT 'text/plain',
            sensitivity TEXT NOT NULL DEFAULT 'public',
            preview TEXT NOT NULL,
            timestamp_ms INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_clipboard_profile
            ON clipboard_entries(profile_id, timestamp_ms DESC);",
    )
    .context("failed to initialize clipboard schema")
}

/// Every sensitivity class and its stored label.
const SENSITIVITY_LABELS: [(SensitivityClass, &str); 4] = [
    (SensitivityClass::Public, "public"),
    (SensitivityClass::Confidential, "confidential"),
    (SensitivityClass::Secret, "secret"),
    (SensitivityClass::TopSecret, "topsecret"),
];

/// Parse a stored sensitivity label. An unknown label is `None`: it must
/// not be downgraded to `Public`.
fn parse_sensitivity(label: &str) -> Option<SensitivityClass> {
    SENSITIVITY_LABELS
        .iter()
        .find(|(_, stored)| *stored == label)
        .map(|(class, _)| *class)
}

/// The stored label of `class`.
fn sensitivity_label(class: SensitivityClass) -> Option<&'static str> {
    SENSITIVITY_LABELS
        .iter()
        .find(|(known, _)| *known == class)
        .map(|(_, label)| *label)
}

/// Decode a column holding a UUID string. A malformed value is a
/// conversion error, not a freshly minted id.
fn uuid_column(row: &rusqlite::Row<'_>, idx: usize) -> rusqlite::Result<uuid::Uuid> {
    let text: String = row.get(idx)?;
    uuid::Uuid::parse_str(&text).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(idx, rusqlite::types::Type::Text, Box::new(e))
    })
}

/// Decode one row of `SELECT entry_id, profile_id, content_type,
/// sensitivity, preview, timestamp_ms`.
fn entry_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ClipboardEntry> {
    let label: String = row.get(3)?;
    let sensitivity = parse_sensitivity(&label).ok_or_else(|| {
        rusqlite::Error::FromSqlConversionFailure(
            3,
            rusqlite::types::Type::Text,
            format!("unknown sensitivity label {label:?}").into(),
        )
    })?;
    let timestamp: i64 = row.get(5)?;
    let timestamp_ms = u64::try_from(timestamp)
        .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(5, timestamp))?;
    Ok(ClipboardEntry {
        entry_id: ClipboardEntryId::from_uuid(uuid_column(row, 0)?),
        profile_id: ProfileId::from_uuid(uuid_column(row, 1)?),
        content_type: row.get(2)?,
        sensitivity,
        preview: row.get(4)?,
        timestamp_ms,
    })
}

/// The preview of `text`: its first [`PREVIEW_CHARS`] characters, with
/// line breaks and other control characters shown as spaces.
fn preview(text: &str) -> String {
    text.chars()
        .take(PREVIEW_CHARS)
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect()
}

/// Milliseconds since the Unix epoch.
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// An entry held in memory as a secret until `expires`.
struct Held {
    entry: ClipboardEntry,
    content: SensitiveBytes,
    expires: Instant,
}

/// One selection to record.
struct Selection<'a> {
    content_type: &'a str,
    text: &'a str,
    /// Whether the source marked it a secret.
    secret_hint: bool,
}

/// The clipboard history: the database of persisted entries and the
/// secrets held in memory.
struct History {
    db: Connection,
    held: Vec<Held>,
}

impl History {
    fn new(db: Connection) -> Self {
        Self {
            db,
            held: Vec::new(),
        }
    }

    /// Record `selection` in `profile`'s history under its `config`, at
    /// `timestamp_ms` (`now` for expiry): the new entry, or `None` when
    /// nothing is kept (it repeats the newest entry, `max_history` is 0,
    /// or a secret's `sensitive_ttl_s` is 0).
    fn record(
        &mut self,
        profile: ProfileId,
        config: &ClipboardConfig,
        selection: &Selection<'_>,
        timestamp_ms: u64,
        now: Instant,
    ) -> rusqlite::Result<Option<ClipboardEntry>> {
        let secret = config.detect_sensitive && selection.secret_hint;
        let entry = ClipboardEntry {
            entry_id: ClipboardEntryId::new(),
            content_type: selection.content_type.to_owned(),
            sensitivity: if secret {
                SensitivityClass::Secret
            } else {
                SensitivityClass::Public
            },
            profile_id: profile,
            preview: if secret {
                SECRET_PREVIEW.to_owned()
            } else {
                preview(selection.text)
            },
            timestamp_ms,
        };
        if secret {
            if config.sensitive_ttl_s == 0 {
                return Ok(None);
            }
            self.held.push(Held {
                entry: entry.clone(),
                content: SensitiveBytes::from_slice(selection.text.as_bytes()),
                expires: now + Duration::from_secs(config.sensitive_ttl_s),
            });
            return Ok(Some(entry));
        }
        if config.max_history == 0 || self.repeats_newest(profile, selection)? {
            return Ok(None);
        }
        let label = sensitivity_label(entry.sensitivity).ok_or_else(|| {
            rusqlite::Error::ToSqlConversionFailure(
                format!("no stored label for {:?}", entry.sensitivity).into(),
            )
        })?;
        let timestamp = i64::try_from(timestamp_ms)
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(e.into()))?;
        let keep = i64::try_from(config.max_history).unwrap_or(i64::MAX);
        let profile_text = profile.as_uuid().to_string();
        let tx = self.db.transaction()?;
        tx.execute(
            "INSERT INTO clipboard_entries VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            rusqlite::params![
                entry.entry_id.as_uuid().to_string(),
                profile_text,
                selection.text,
                entry.content_type,
                label,
                entry.preview,
                timestamp
            ],
        )?;
        tx.execute(
            "DELETE FROM clipboard_entries WHERE profile_id = ?1 AND entry_id NOT IN (
                SELECT entry_id FROM clipboard_entries WHERE profile_id = ?1
                ORDER BY timestamp_ms DESC, entry_id DESC LIMIT ?2)",
            rusqlite::params![profile_text, keep],
        )?;
        tx.commit()?;
        Ok(Some(entry))
    }

    /// Whether `selection` is `profile`'s newest persisted entry.
    fn repeats_newest(
        &self,
        profile: ProfileId,
        selection: &Selection<'_>,
    ) -> rusqlite::Result<bool> {
        match self.db.query_row(
            "SELECT content, content_type FROM clipboard_entries WHERE profile_id = ?1
             ORDER BY timestamp_ms DESC, entry_id DESC LIMIT 1",
            rusqlite::params![profile.as_uuid().to_string()],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        ) {
            Ok((content, content_type)) => {
                Ok(content == selection.text && content_type == selection.content_type)
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// `profile`'s `limit` newest entries, held and persisted, newest first.
    fn history(&self, profile: ProfileId, limit: u32) -> rusqlite::Result<Vec<ClipboardEntry>> {
        let mut entries: Vec<ClipboardEntry> = self
            .db
            .prepare(
                "SELECT entry_id, profile_id, content_type, sensitivity, preview, timestamp_ms
                 FROM clipboard_entries WHERE profile_id = ?1
                 ORDER BY timestamp_ms DESC, entry_id DESC LIMIT ?2",
            )?
            .query_map(
                rusqlite::params![profile.as_uuid().to_string(), limit],
                entry_from_row,
            )?
            .collect::<rusqlite::Result<_>>()?;
        entries.extend(
            self.held
                .iter()
                .filter(|held| held.entry.profile_id == profile)
                .map(|held| held.entry.clone()),
        );
        entries.sort_by(|a, b| {
            b.timestamp_ms
                .cmp(&a.timestamp_ms)
                .then_with(|| b.entry_id.cmp(&a.entry_id))
        });
        entries.truncate(usize::try_from(limit).unwrap_or(usize::MAX));
        Ok(entries)
    }

    /// The content and content type of `entry_id`, `None` when absent or
    /// expired.
    fn content(&self, entry_id: &ClipboardEntryId) -> rusqlite::Result<Option<(String, String)>> {
        if let Some(held) = self
            .held
            .iter()
            .find(|held| held.entry.entry_id == *entry_id)
        {
            return Ok(Some((
                String::from_utf8_lossy(held.content.as_bytes()).into_owned(),
                held.entry.content_type.clone(),
            )));
        }
        match self.db.query_row(
            "SELECT content, content_type FROM clipboard_entries WHERE entry_id = ?1",
            rusqlite::params![entry_id.as_uuid().to_string()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        ) {
            Ok(found) => Ok(Some(found)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Delete `profile`'s entries, held and persisted: how many.
    fn clear(&mut self, profile: ProfileId) -> rusqlite::Result<usize> {
        let deleted = self.db.execute(
            "DELETE FROM clipboard_entries WHERE profile_id = ?1",
            rusqlite::params![profile.as_uuid().to_string()],
        )?;
        let held = self.held.len();
        self.held.retain(|entry| entry.entry.profile_id != profile);
        Ok(deleted + held - self.held.len())
    }

    /// When the next held secret expires.
    fn next_expiry(&self) -> Option<Instant> {
        self.held.iter().map(|held| held.expires).min()
    }

    /// Drop the held secrets expired at `now`: their ids.
    fn expire(&mut self, now: Instant) -> Vec<ClipboardEntryId> {
        let (expired, kept): (Vec<Held>, Vec<Held>) = std::mem::take(&mut self.held)
            .into_iter()
            .partition(|held| held.expires <= now);
        self.held = kept;
        expired
            .into_iter()
            .map(|held| held.entry.entry_id)
            .collect()
    }
}

/// Where entries are filed: the installation namespace profile identities
/// derive from, and the default profile new selections go to.
struct Scope {
    namespace: Option<uuid::Uuid>,
    default: TrustProfileName,
}

impl Scope {
    /// The identity of profile `name`, `None` before `sesame init`.
    fn id(&self, name: &TrustProfileName) -> Option<ProfileId> {
        self.namespace
            .map(|namespace| ProfileId::of_profile(&namespace, name.as_ref()))
    }

    /// The profile of `config` (a configured profile or the configured
    /// default) whose identity is `id`.
    fn name_of(&self, config: &Config, id: ProfileId) -> Option<TrustProfileName> {
        config
            .profiles
            .keys()
            .filter_map(|name| TrustProfileName::try_from(name.as_str()).ok())
            .chain(std::iter::once(config.global.default_profile.clone()))
            .find(|name| self.id(name) == Some(id))
    }

    /// Follow daemon-profile's `DefaultProfileChanged` to `current`. Only
    /// the server-verified daemon-profile identity counts.
    fn follow_default(&mut self, config: &Config, msg: &Message<EventKind>, current: ProfileId) {
        if msg.verified_sender_name.as_deref() != Some(Daemon::Profile.name()) {
            tracing::warn!(
                audit = "security",
                sender = %msg.sender,
                "DefaultProfileChanged from a sender other than daemon-profile ignored"
            );
            return;
        }
        let Some(name) = self.name_of(config, current) else {
            tracing::warn!(
                profile = %current,
                "default profile changed to one that is not configured here"
            );
            return;
        };
        tracing::info!(profile = %name, "new selections go to the new default profile");
        self.default = name;
    }
}

/// The installation namespace from `installation.toml`, `None` before
/// `sesame init` writes it.
fn installation_namespace(layout: &core_layout::Layout) -> Option<uuid::Uuid> {
    match core_config::load_installation(layout) {
        Ok(Some(installation)) => Some(installation.namespace),
        Ok(None) => {
            tracing::info!(
                "no installation identity yet (sesame init): selections are not recorded"
            );
            None
        }
        Err(e) => {
            tracing::error!(error = %e, "installation identity unreadable: selections are not recorded");
            None
        }
    }
}

/// The response to `payload` when it is a clipboard request. A failed
/// query is logged and answered empty: the responses carry no error.
fn respond(history: &mut History, scope: &Scope, payload: &EventKind) -> Option<EventKind> {
    Some(match payload {
        EventKind::ClipboardHistory { profile, limit } => {
            let entries = match scope.id(profile) {
                Some(id) => history.history(id, *limit).unwrap_or_else(|e| {
                    tracing::error!(%profile, error = %e, "ClipboardHistory query failed");
                    vec![]
                }),
                None => vec![],
            };
            tracing::debug!(%profile, count = entries.len(), "ClipboardHistory");
            EventKind::ClipboardHistoryResponse { entries }
        }
        EventKind::ClipboardClear { profile } => {
            let success = match scope.id(profile).map(|id| history.clear(id)) {
                Some(Ok(deleted)) => {
                    tracing::info!(%profile, deleted, "ClipboardClear");
                    true
                }
                Some(Err(e)) => {
                    tracing::error!(%profile, error = %e, "ClipboardClear failed");
                    false
                }
                None => {
                    tracing::warn!(%profile, "ClipboardClear before sesame init");
                    false
                }
            };
            EventKind::ClipboardClearResponse { success }
        }
        EventKind::ClipboardGet { entry_id } => {
            let found = history.content(entry_id).unwrap_or_else(|e| {
                tracing::error!(error = %e, ?entry_id, "ClipboardGet query failed");
                None
            });
            let (content, content_type) = found.unzip();
            EventKind::ClipboardGetResponse {
                content,
                content_type,
            }
        }
        _ => return None,
    })
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    core_daemon::init_logging(cli.log_format)?;
    tracing::info!("daemon-clipboard starting");

    #[cfg(target_os = "linux")]
    {
        platform_linux::security::harden_process();
        platform_linux::security::apply_resource_limits(
            &platform_linux::security::ResourceLimits {
                nofile: 4096,
                memlock_bytes: 0,
            },
        );
    }

    let (layout, config) = core_daemon::startup()?;
    let db = init_db(&layout.clipboard_db()?)?;

    core_types::init_secure_memory();

    // The sandbox is applied on the only thread; the configuration
    // watcher and the capture thread start inside it.
    #[cfg(target_os = "linux")]
    apply_sandbox(&layout, &config)?;

    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("failed to start the async runtime")?
        .block_on(run(&layout, config, History::new(db)))
}

/// The selections captured from the compositor, `None` when capture is
/// unavailable.
#[cfg(target_os = "linux")]
type Captures = Option<tokio::sync::mpsc::Receiver<platform_linux::clipboard::Capture>>;
#[cfg(not(target_os = "linux"))]
type Captures = ();

/// Start capturing the clipboard of the Wayland session, if there is one
/// and its compositor offers data-control.
#[cfg(target_os = "linux")]
fn start_capture(layout: &core_layout::Layout) -> Captures {
    if layout.environment().wayland_display.is_none() {
        tracing::info!("no Wayland session: clipboard capture is off");
        return None;
    }
    let (tx, rx) = tokio::sync::mpsc::channel(16);
    match platform_linux::clipboard::spawn_capture(tx) {
        Ok(()) => {
            tracing::info!("clipboard capture started");
            Some(rx)
        }
        Err(e) => {
            tracing::warn!(error = %e, "clipboard capture is off; history is served");
            None
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn start_capture(_layout: &core_layout::Layout) -> Captures {}

/// What the daemon's own sources produce.
enum Source {
    #[cfg(target_os = "linux")]
    Captured(platform_linux::clipboard::Capture),
    /// A held secret's time is up.
    Expired,
}

/// The next selection or expiry. A closed capture channel (the capture
/// thread ended, logging why) produces nothing more.
async fn next_source(captures: &mut Captures, expiry: Option<Instant>) -> Source {
    let expired = async {
        match expiry {
            Some(at) => tokio::time::sleep_until(at.into()).await,
            None => std::future::pending().await,
        }
    };
    #[cfg(target_os = "linux")]
    {
        let selection = async {
            match captures {
                Some(rx) => match rx.recv().await {
                    Some(capture) => capture,
                    None => std::future::pending().await,
                },
                None => std::future::pending().await,
            }
        };
        tokio::select! {
            capture = selection => Source::Captured(capture),
            () = expired => Source::Expired,
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let () = captures;
        expired.await;
        Source::Expired
    }
}

/// The daemon, from bus connection to shutdown, inside the sandbox.
async fn run(
    layout: &core_layout::Layout,
    config: Config,
    mut history: History,
) -> anyhow::Result<()> {
    let mut scope = Scope {
        namespace: installation_namespace(layout),
        default: config.global.default_profile.clone(),
    };
    let mut config_now = config.clone();
    let mut events = EventLoop::new(
        Shutdown::register()?,
        core_daemon::watch_config(layout, config)?,
    );
    let mut captures = start_capture(layout);
    let mut client = core_daemon::connect_bus(layout, &IDENTITY).await?;
    if let Some(default) = reported_default(&client).await {
        scope.default = default;
    }

    core_daemon::announce_started(&client, &IDENTITY).await;
    #[cfg(target_os = "linux")]
    platform_linux::systemd::notify_ready();
    tracing::info!(profile = %scope.default, "daemon-clipboard ready, entering event loop");

    loop {
        let own = next_source(&mut captures, history.next_expiry());
        match events.next(&mut client, own).await? {
            Wake::Message(msg) => {
                if let EventKind::DefaultProfileChanged { current, .. } = msg.payload {
                    scope.follow_default(&config_now, &msg, current);
                } else if let Some(response) = respond(&mut history, &scope, &msg.payload) {
                    core_daemon::reply(&client, &msg, response).await;
                }
            }
            Wake::ConfigReloaded(reloaded) => {
                config_now = reloaded;
                scope.namespace = installation_namespace(layout);
                core_daemon::announce_config_reloaded(&client, &["clipboard"]).await;
            }
            #[cfg(target_os = "linux")]
            Wake::Own(Source::Captured(mut capture)) => {
                record(&client, &mut history, &scope, &config_now, &capture).await;
                zeroize::Zeroize::zeroize(&mut capture.text);
            }
            Wake::Own(Source::Expired) => {
                for entry_id in history.expire(Instant::now()) {
                    tracing::debug!(?entry_id, "held secret expired");
                    client
                        .publish_or_log(
                            "ClipboardEntryExpired",
                            EventKind::ClipboardEntryExpired { entry_id },
                            SecurityLevel::Internal,
                        )
                        .await;
                }
            }
            Wake::Shutdown(_) => break,
        }
    }

    core_daemon::announce_stopped(&client).await;
    tracing::info!("daemon-clipboard shut down");
    Ok(())
}

/// Record `capture` in the default profile's history and announce the
/// entry (`ClipboardChanged`).
#[cfg(target_os = "linux")]
async fn record(
    client: &BusClient,
    history: &mut History,
    scope: &Scope,
    config: &Config,
    capture: &platform_linux::clipboard::Capture,
) {
    let Some(profile) = scope.id(&scope.default) else {
        tracing::debug!("selection not recorded before sesame init");
        return;
    };
    let clipboard = config
        .profiles
        .get(scope.default.as_ref())
        .map(|p| p.clipboard.clone())
        .unwrap_or_default();
    let selection = Selection {
        content_type: &capture.content_type,
        text: &capture.text,
        secret_hint: capture.password_manager_hint,
    };
    match history.record(profile, &clipboard, &selection, now_ms(), Instant::now()) {
        Ok(Some(entry)) => {
            tracing::debug!(
                entry_id = ?entry.entry_id,
                sensitivity = ?entry.sensitivity,
                "selection recorded"
            );
            client
                .publish_or_log(
                    "ClipboardChanged",
                    EventKind::ClipboardChanged {
                        entry_id: entry.entry_id,
                        sensitivity: entry.sensitivity,
                        content_type: entry.content_type,
                        profile_id: profile,
                    },
                    SecurityLevel::Internal,
                )
                .await;
        }
        Ok(None) => {}
        Err(e) => tracing::error!(error = %e, "selection could not be recorded"),
    }
}

/// The default profile daemon-profile reports, `None` (the configured
/// default stands) when it does not answer.
async fn reported_default(client: &BusClient) -> Option<TrustProfileName> {
    match client
        .request(
            EventKind::StatusRequest,
            SecurityLevel::Internal,
            STATUS_TIMEOUT,
        )
        .await
    {
        Ok(msg) if msg.verified_sender_name.as_deref() == Some(Daemon::Profile.name()) => {
            match msg.payload {
                EventKind::StatusResponse {
                    default_profile, ..
                } => Some(default_profile),
                other => {
                    tracing::warn!(payload = ?other, "unexpected answer to StatusRequest");
                    None
                }
            }
        }
        Ok(msg) => {
            tracing::warn!(sender = %msg.sender, "StatusResponse from a sender other than daemon-profile ignored");
            None
        }
        Err(e) => {
            tracing::warn!(error = %e, "default profile not reported; the configured default stands");
            None
        }
    }
}

/// Apply Landlock + seccomp under `config`'s sandbox floor: bus client,
/// configuration (read), the systemd notification socket, the Wayland
/// socket, and the cache directory holding the history database.
///
/// # Errors
///
/// When a granted location cannot be placed, the kernel is below the
/// floor, or the sandbox cannot be applied: the daemon does not run.
#[cfg(target_os = "linux")]
fn apply_sandbox(layout: &core_layout::Layout, config: &Config) -> anyhow::Result<()> {
    use core_daemon::sandbox::{
        config_rules, ipc_client_rules, notify_rules, seccomp_profile, wayland_rules,
    };
    use platform_linux::sandbox::{FsAccess, LandlockRule};

    let mut rules = ipc_client_rules(layout)?;
    rules.extend(config_rules(layout, FsAccess::ReadOnly)?);
    rules.extend(notify_rules(layout)?);
    rules.extend(wayland_rules(layout)?);
    rules.push(LandlockRule {
        path: layout.cache_dir()?,
        access: FsAccess::ReadWrite,
    });

    // SQLite: file locks and durable writes.
    let seccomp = seccomp_profile(IDENTITY.daemon, &["flock", "fsync", "fdatasync"]);

    core_daemon::sandbox::apply(layout, config, &rules, &seccomp)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SELECT_ENTRY: &str = "SELECT entry_id, profile_id, content_type, sensitivity, preview, timestamp_ms \
         FROM clipboard_entries WHERE entry_id = ?1";

    fn ns() -> uuid::Uuid {
        uuid::Uuid::new_v5(&uuid::Uuid::NAMESPACE_OID, b"installation")
    }

    fn schema() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        init_schema(&conn).unwrap();
        conn
    }

    fn insert(conn: &Connection, entry_id: &str, profile_id: &str, sensitivity: &str, ts: i64) {
        conn.execute(
            "INSERT INTO clipboard_entries VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            rusqlite::params![
                entry_id,
                profile_id,
                "data",
                "text/plain",
                sensitivity,
                "d***",
                ts
            ],
        )
        .unwrap();
    }

    fn decode(conn: &Connection, entry_id: &str) -> rusqlite::Result<ClipboardEntry> {
        conn.query_row(SELECT_ENTRY, rusqlite::params![entry_id], entry_from_row)
    }

    fn profile(name: &str) -> TrustProfileName {
        TrustProfileName::try_from(name).unwrap()
    }

    fn scope(default: &str) -> Scope {
        Scope {
            namespace: Some(ns()),
            default: profile(default),
        }
    }

    fn text(text: &str, secret_hint: bool) -> Selection<'_> {
        Selection {
            content_type: "text/plain;charset=utf-8",
            text,
            secret_hint,
        }
    }

    fn config(max_history: usize, sensitive_ttl_s: u64) -> ClipboardConfig {
        ClipboardConfig {
            max_history,
            sensitive_ttl_s,
            detect_sensitive: true,
        }
    }

    #[test]
    fn init_db_creates_an_idempotent_schema() {
        let dir = tempfile::tempdir().unwrap();
        let conn = init_db(&dir.path().join("clipboard.db")).unwrap();
        init_schema(&conn).unwrap();
        insert(&conn, "e1", "p1", "public", 1000);
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM clipboard_entries", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn every_class_has_one_label() {
        for (class, label) in SENSITIVITY_LABELS {
            assert_eq!(parse_sensitivity(label), Some(class));
            assert_eq!(sensitivity_label(class), Some(label));
        }
    }

    #[test]
    fn unknown_sensitivity_is_not_public() {
        assert_eq!(parse_sensitivity("unknown"), None);
        assert_eq!(parse_sensitivity("Secret"), None);

        let conn = schema();
        let id = uuid::Uuid::now_v7().to_string();
        insert(&conn, &id, &uuid::Uuid::now_v7().to_string(), "unknown", 1);
        assert!(matches!(
            decode(&conn, &id),
            Err(rusqlite::Error::FromSqlConversionFailure(3, _, _))
        ));
    }

    #[test]
    fn malformed_ids_are_errors_not_fresh_ids() {
        let conn = schema();
        let profile = uuid::Uuid::now_v7().to_string();
        insert(&conn, "not-a-uuid", &profile, "public", 1);
        assert!(matches!(
            decode(&conn, "not-a-uuid"),
            Err(rusqlite::Error::FromSqlConversionFailure(0, _, _))
        ));

        let id = uuid::Uuid::now_v7().to_string();
        insert(&conn, &id, "p1", "public", 1);
        assert!(matches!(
            decode(&conn, &id),
            Err(rusqlite::Error::FromSqlConversionFailure(1, _, _))
        ));
    }

    #[test]
    fn negative_timestamp_is_out_of_range() {
        let conn = schema();
        let id = uuid::Uuid::now_v7().to_string();
        insert(&conn, &id, &uuid::Uuid::now_v7().to_string(), "public", -1);
        assert!(matches!(
            decode(&conn, &id),
            Err(rusqlite::Error::IntegralValueOutOfRange(5, -1))
        ));
    }

    #[test]
    fn previews_are_one_line_and_bounded() {
        assert_eq!(preview("a\nb\tc"), "a b c");
        assert_eq!(preview(&"x".repeat(200)).chars().count(), PREVIEW_CHARS);
    }

    #[test]
    fn a_recorded_selection_is_listed_and_served_by_profile_name() {
        let scope = scope("work");
        let work = scope.id(&profile("work")).unwrap();
        let mut history = History::new(schema());
        let entry = history
            .record(
                work,
                &config(10, 30),
                &text("copied", false),
                5,
                Instant::now(),
            )
            .unwrap()
            .unwrap();
        assert_eq!(entry.sensitivity, SensitivityClass::Public);
        assert_eq!(entry.profile_id, work);

        let request = EventKind::ClipboardHistory {
            profile: profile("work"),
            limit: 10,
        };
        assert!(matches!(
            respond(&mut history, &scope, &request),
            Some(EventKind::ClipboardHistoryResponse { entries })
                if entries.len() == 1 && entries[0].entry_id == entry.entry_id
                    && entries[0].preview == "copied"
        ));
        let other = EventKind::ClipboardHistory {
            profile: profile("home"),
            limit: 10,
        };
        assert!(matches!(
            respond(&mut history, &scope, &other),
            Some(EventKind::ClipboardHistoryResponse { entries }) if entries.is_empty()
        ));
        assert!(matches!(
            respond(&mut history, &scope, &EventKind::ClipboardGet { entry_id: entry.entry_id }),
            Some(EventKind::ClipboardGetResponse { content: Some(c), content_type: Some(t) })
                if c == "copied" && t == "text/plain;charset=utf-8"
        ));
    }

    #[test]
    fn a_repeated_selection_is_one_entry_and_history_is_pruned() {
        let work = ProfileId::of_profile(&ns(), "work");
        let mut history = History::new(schema());
        let now = Instant::now();
        let cfg = config(2, 30);
        assert!(
            history
                .record(work, &cfg, &text("a", false), 1, now)
                .unwrap()
                .is_some()
        );
        assert!(
            history
                .record(work, &cfg, &text("a", false), 2, now)
                .unwrap()
                .is_none()
        );
        assert!(
            history
                .record(work, &cfg, &text("b", false), 3, now)
                .unwrap()
                .is_some()
        );
        assert!(
            history
                .record(work, &cfg, &text("c", false), 4, now)
                .unwrap()
                .is_some()
        );
        let previews: Vec<String> = history
            .history(work, 10)
            .unwrap()
            .into_iter()
            .map(|e| e.preview)
            .collect();
        assert_eq!(previews, ["c", "b"]);
        assert!(
            history
                .record(work, &config(0, 30), &text("d", false), 5, now)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn a_secret_is_held_in_memory_until_it_expires() {
        let work = ProfileId::of_profile(&ns(), "work");
        let mut history = History::new(schema());
        let now = Instant::now();
        let entry = history
            .record(work, &config(10, 30), &text("hunter2", true), 7, now)
            .unwrap()
            .unwrap();
        assert_eq!(entry.sensitivity, SensitivityClass::Secret);
        assert_eq!(entry.preview, SECRET_PREVIEW);
        let persisted: i64 = history
            .db
            .query_row("SELECT COUNT(*) FROM clipboard_entries", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(persisted, 0, "a secret is never written to the database");
        assert_eq!(
            history.content(&entry.entry_id).unwrap(),
            Some(("hunter2".into(), "text/plain;charset=utf-8".into()))
        );
        assert_eq!(history.history(work, 10).unwrap().len(), 1);

        assert_eq!(history.next_expiry(), Some(now + Duration::from_secs(30)));
        assert!(history.expire(now).is_empty());
        assert_eq!(
            history.expire(now + Duration::from_secs(30)),
            [entry.entry_id]
        );
        assert_eq!(history.content(&entry.entry_id).unwrap(), None);
        assert_eq!(history.next_expiry(), None);

        // A TTL of 0 keeps no secret; without detection the hint is ignored.
        assert!(
            history
                .record(work, &config(10, 0), &text("x", true), 8, now)
                .unwrap()
                .is_none()
        );
        let undetected = ClipboardConfig {
            detect_sensitive: false,
            ..config(10, 30)
        };
        let public = history
            .record(work, &undetected, &text("y", true), 9, now)
            .unwrap()
            .unwrap();
        assert_eq!(public.sensitivity, SensitivityClass::Public);
    }

    #[test]
    fn clearing_a_profile_removes_held_and_persisted_entries() {
        let scope = scope("work");
        let work = scope.id(&profile("work")).unwrap();
        let home = scope.id(&profile("home")).unwrap();
        let mut history = History::new(schema());
        let now = Instant::now();
        history
            .record(work, &config(10, 30), &text("a", false), 1, now)
            .unwrap();
        history
            .record(work, &config(10, 30), &text("s", true), 2, now)
            .unwrap();
        history
            .record(home, &config(10, 30), &text("h", false), 3, now)
            .unwrap();
        assert!(matches!(
            respond(
                &mut history,
                &scope,
                &EventKind::ClipboardClear {
                    profile: profile("work")
                }
            ),
            Some(EventKind::ClipboardClearResponse { success: true })
        ));
        assert!(history.history(work, 10).unwrap().is_empty());
        assert_eq!(history.history(home, 10).unwrap().len(), 1);
        assert!(respond(&mut history, &scope, &EventKind::StatusRequest).is_none());
    }

    #[test]
    fn before_init_nothing_is_filed_or_cleared() {
        let scope = Scope {
            namespace: None,
            default: profile("work"),
        };
        let mut history = History::new(schema());
        assert_eq!(scope.id(&profile("work")), None);
        assert!(matches!(
            respond(
                &mut history,
                &scope,
                &EventKind::ClipboardClear {
                    profile: profile("work")
                }
            ),
            Some(EventKind::ClipboardClearResponse { success: false })
        ));
    }

    #[test]
    fn the_default_profile_is_resolved_from_its_identity() {
        let config: Config = toml::from_str(
            "[global]\ndefault_profile = \"home\"\n[profiles.work]\n[profiles.home]\n",
        )
        .unwrap();
        let scope = scope("home");
        let work = ProfileId::of_profile(&ns(), "work");
        assert_eq!(scope.name_of(&config, work), Some(profile("work")));
        let unknown = ProfileId::of_profile(&ns(), "elsewhere");
        assert_eq!(scope.name_of(&config, unknown), None);
    }
}
