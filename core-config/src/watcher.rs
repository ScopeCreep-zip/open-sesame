//! Configuration hot-reload: filesystem events and a timer drive one
//! reconciliation of the running configuration with the layers on disk.
//!
//! The watch is level-driven. A reconciliation captures every present
//! layer (`loader::Capture`) and reloads only when the captured bytes
//! differ from the last ones reconciled; filesystem events and the
//! [`RECONCILE_INTERVAL`] timer only decide when it runs. A missed or
//! coalesced event is recovered by periodic reconciliation, subject to I/O
//! and scheduling latency. An event on an unrelated file in a watched
//! directory (the audit log, the vaults) reloads
//! nothing.
//!
//! What is watched are the layers' directories
//! (`loader::LayerSpec::directories`), not the layer files: a layer created
//! after the watcher starts
//! (`sesame init` writing `config.toml` under running daemons) is an entry
//! of a watched directory. A directory that does not exist yet is watched
//! through its nearest existing ancestor and armed itself once it appears.
//! A watch that cannot be added leaves its directory to the timer.

use core_layout::Layout;
use core_types::{ConfigRevision, ConfigStatus, ReconcileStatus, WatchStatus};
use notify::{RecommendedWatcher, RecursiveMode, Watcher};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{RecvTimeoutError, SyncSender, sync_channel};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use tracing::{error, info, warn};

use crate::loader::{Capture, LayerSpec};
use crate::schema::Config;

/// Period between reconciliation deadlines, excluding I/O and scheduling latency.
pub const RECONCILE_INTERVAL: Duration = Duration::from_secs(5);

/// How long a reconciliation woken by an event waits for the writer's
/// further events (an editor's write, rename, and attribute change) before
/// it captures, so one change is reconciled once.
const SETTLE: Duration = Duration::from_millis(100);

enum Wake {
    Event,
    Reconcile(SyncSender<core_types::Result<()>>),
}

/// A handle for requesting reconciliation through the watcher's single loop.
#[derive(Clone)]
pub struct ReconcileTrigger {
    wake: SyncSender<Wake>,
}

impl ReconcileTrigger {
    /// Reconcile now and wait for validation to finish.
    ///
    /// Call from a blocking thread when used by an async runtime.
    ///
    /// # Errors
    ///
    /// The loop stopped, or the current layers could not be accepted.
    pub fn reconcile(&self) -> core_types::Result<()> {
        let (reply, result) = sync_channel(1);
        self.wake.send(Wake::Reconcile(reply)).map_err(|_| {
            core_types::Error::Config("configuration reconciliation stopped".into())
        })?;
        result
            .recv()
            .map_err(|_| core_types::Error::Config("configuration reconciliation stopped".into()))?
    }
}

/// Read-only access to the most recently accepted configuration.
#[derive(Debug, Clone)]
pub struct ConfigState {
    current: Arc<RwLock<AcceptedState>>,
}

#[derive(Debug)]
struct AcceptedState {
    config: Config,
    installation: Option<crate::InstallationConfig>,
    status: ConfigStatus,
    revision: ConfigRevision,
    observation: uuid::Uuid,
}

/// Configuration and installation identity captured under one publication lock.
#[derive(Debug, Clone)]
pub struct ConfigSnapshot {
    /// Process-local acceptance identity, distinguishing repeated source revisions.
    pub observation: uuid::Uuid,
    /// Identity of this accepted candidate, unchanged by failed observations.
    pub revision: ConfigRevision,
    /// The accepted, semantically validated configuration.
    pub config: Config,
    /// Installation identity accepted with this configuration.
    pub installation: Option<crate::InstallationConfig>,
    /// Observation health when this snapshot was acquired.
    pub status: ConfigStatus,
}

impl ConfigState {
    fn new(config: Config) -> Self {
        Self {
            current: Arc::new(RwLock::new(AcceptedState {
                config,
                installation: None,
                revision: ConfigRevision([0; 32]),
                observation: uuid::Uuid::new_v4(),
                status: ConfigStatus {
                    reconciliation: ReconcileStatus::Pending,
                    watch: WatchStatus::Degraded(vec![
                        "watch registration has not completed".into(),
                    ]),
                },
            })),
        }
    }

    /// `view` of the accepted state, under the read lock.
    fn view<T>(&self, view: impl FnOnce(&AcceptedState) -> T) -> core_types::Result<T> {
        self.current
            .read()
            .map(|state| view(&state))
            .map_err(|error| {
                core_types::Error::Config(format!("configuration state lock poisoned: {error}"))
            })
    }

    /// Apply `change` to the accepted state, under the write lock. Only the
    /// reconciliation thread writes; a reader that panicked holding the lock
    /// leaves no state it can publish, so poisoning stops that thread.
    fn update(&self, change: impl FnOnce(&mut AcceptedState)) {
        change(
            &mut self
                .current
                .write()
                .expect("configuration publication lock poisoned"),
        );
    }

    /// Copy one coherent configuration without exposing the publication lock.
    ///
    /// # Errors
    ///
    /// The configuration publication lock is poisoned.
    pub fn snapshot(&self) -> core_types::Result<ConfigSnapshot> {
        self.view(|state| ConfigSnapshot {
            observation: state.observation,
            revision: state.revision,
            config: state.config.clone(),
            installation: state.installation.clone(),
            status: state.status.clone(),
        })
    }

    /// Read the latest reconciliation and native-watch health.
    ///
    /// # Errors
    ///
    /// The configuration publication lock is poisoned.
    pub fn status(&self) -> core_types::Result<ConfigStatus> {
        self.view(|state| state.status.clone())
    }

    fn reconciliation(&self, status: ReconcileStatus) {
        self.update(|state| state.status.reconciliation = status);
    }

    fn watch(&self, status: WatchStatus) {
        self.update(|state| state.status.watch = status);
    }
}

/// What a reconciliation did.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Outcome {
    /// The layers are the ones last reconciled.
    Unchanged,
    /// A validated candidate was published; this does not attest to resource application.
    Accepted,
    /// The layers changed, but their configuration does not load or does
    /// not validate; the current configuration is kept.
    Rejected,
    /// The layers could not be read; the current configuration is kept.
    Unreadable,
}

/// The running configuration and the layers it was reconciled from.
struct Reconciliation {
    layout: Layout,
    current: ConfigState,
    /// The layers last reconciled (applied or rejected); `None` before the
    /// first reconciliation, which therefore always loads.
    last: Option<(Capture, ReconcileStatus)>,
    /// The last unreadable-layers message, logged once until it changes.
    unreadable: Option<String>,
    on_reload: Option<Box<dyn Fn() + Send + Sync>>,
}

impl Reconciliation {
    /// A reconciliation of `layout` into `current` that has not run yet.
    fn new(
        layout: Layout,
        current: ConfigState,
        on_reload: Option<Box<dyn Fn() + Send + Sync>>,
    ) -> Self {
        Self {
            layout,
            current,
            last: None,
            unreadable: None,
            on_reload,
        }
    }

    /// Reconcile the current configuration with the layers on disk.
    fn run(&mut self) -> Outcome {
        let capture = match Capture::of(&self.layout) {
            Ok(capture) => capture,
            Err(e) => {
                let message = e.to_string();
                self.current
                    .reconciliation(ReconcileStatus::Unreadable(message.clone()));
                if self.unreadable.as_ref() != Some(&message) {
                    warn!(error = %message, "configuration layers unreadable, keeping the current configuration");
                    self.unreadable = Some(message);
                }
                return Outcome::Unreadable;
            }
        };
        let recovered = self.unreadable.take().is_some();
        if let Some((previous, status)) = &self.last
            && previous == &capture
        {
            if recovered {
                self.current.reconciliation(status.clone());
            }
            return Outcome::Unchanged;
        }
        let outcome = self.apply(&capture);
        self.last = Some((
            capture,
            self.current
                .status()
                .expect("configuration publication lock poisoned")
                .reconciliation,
        ));
        outcome
    }

    /// Load, validate, and adopt the configuration of `capture`.
    fn apply(&self, capture: &Capture) -> Outcome {
        let (config, installation) = match capture
            .config()
            .and_then(|config| Ok((config, capture.installation()?)))
        {
            Ok(candidate) => candidate,
            Err(e) => {
                warn!(error = %e, "configuration reload rejected, keeping the current configuration");
                self.current
                    .reconciliation(ReconcileStatus::Rejected(e.to_string()));
                return Outcome::Rejected;
            }
        };
        self.current.update(|state| {
            state.config = config;
            state.installation = installation;
            state.revision = capture.revision();
            state.observation = uuid::Uuid::new_v4();
            state.status.reconciliation = ReconcileStatus::Accepted;
        });
        info!("configuration candidate accepted");
        if let Some(cb) = &self.on_reload {
            cb();
        }
        Outcome::Accepted
    }
}

/// The directory to watch for `dir`: `dir` itself when it exists, otherwise
/// its nearest existing ancestor, whose entries announce `dir`'s creation.
fn watch_target(dir: &Path) -> Option<PathBuf> {
    dir.ancestors().find(|d| d.is_dir()).map(Path::to_path_buf)
}

/// The filesystem watches on the layers' directories.
struct Arming {
    layout: Layout,
    state: ConfigState,
    watcher: Option<RecommendedWatcher>,
    wake: SyncSender<Wake>,
    armed: BTreeSet<PathBuf>,
    /// Directories whose watch could not be added, warned about once.
    failed: BTreeSet<PathBuf>,
}

impl Arming {
    /// Watches of `layout`'s layer directories, none registered yet, whose
    /// events wake `wake` and whose health is reported in `state`.
    fn new(layout: Layout, state: ConfigState, wake: SyncSender<Wake>) -> Self {
        Self {
            layout,
            state,
            watcher: None,
            wake,
            armed: BTreeSet::new(),
            failed: BTreeSet::new(),
        }
    }

    /// Watch each layer directory, or its nearest existing ancestor, and
    /// drop the watches no longer needed.
    fn arm(&mut self) {
        self.arm_with(native_watcher);
    }

    fn arm_with(
        &mut self,
        create: impl FnOnce(SyncSender<Wake>) -> notify::Result<RecommendedWatcher>,
    ) {
        if self.watcher.is_none() {
            match create(self.wake.clone()) {
                Ok(watcher) => self.watcher = Some(watcher),
                Err(e) => {
                    warn!(error = %e, "native configuration watcher unavailable; timer reconciliation remains active");
                    self.state.watch(WatchStatus::Degraded(vec![e.to_string()]));
                    return;
                }
            }
        }
        let Some(watcher) = &mut self.watcher else {
            return;
        };
        let dirs = match LayerSpec::of(&self.layout).and_then(|spec| spec.directories()) {
            Ok(dirs) => dirs,
            Err(e) => {
                warn!(error = %e, "configuration directories cannot be placed, reconciling on the timer");
                self.state.watch(WatchStatus::Degraded(vec![e.to_string()]));
                return;
            }
        };
        let wanted: BTreeSet<PathBuf> = dirs.iter().filter_map(|d| watch_target(d)).collect();
        self.failed.retain(|dir| wanted.contains(dir));
        let mut errors = Vec::new();
        // Registrations attach to filesystem objects, not path spellings.
        // Re-register even unchanged paths to recover replacement/remount
        // and backend invalidation when its notification was lost.
        for gone in std::mem::take(&mut self.armed) {
            let _ = watcher.unwatch(&gone);
        }
        for dir in wanted {
            match watcher.watch(&dir, RecursiveMode::NonRecursive) {
                Ok(()) => {
                    self.failed.remove(&dir);
                    self.armed.insert(dir);
                }
                Err(e) => {
                    errors.push(format!("{}: {e}", dir.display()));
                    if self.failed.insert(dir.clone()) {
                        warn!(path = %dir.display(), error = %e, "cannot watch configuration directory, reconciling it on the timer");
                    }
                }
            }
        }
        self.state.watch(if errors.is_empty() {
            WatchStatus::Native
        } else {
            WatchStatus::Degraded(errors)
        });
    }
}

/// Reading configuration must not generate another reconciliation.
fn wakes_reconciliation(event: &notify::Event) -> bool {
    use notify::event::{MetadataKind, ModifyKind};
    event.need_rescan()
        || !(event.kind.is_access()
            || matches!(
                event.kind,
                notify::EventKind::Modify(ModifyKind::Metadata(MetadataKind::AccessTime))
            ))
}

fn native_watcher(wake: SyncSender<Wake>) -> notify::Result<RecommendedWatcher> {
    notify::recommended_watcher(move |res: Result<notify::Event, notify::Error>| {
        match res {
            Ok(event) if !wakes_reconciliation(&event) => return,
            Ok(_) => {}
            Err(e) => warn!(error = %e, "filesystem watcher error; registrations will be renewed"),
        }
        // A full channel already contains a wake covering this event.
        let _ = wake.try_send(Wake::Event);
    })
}

/// Watches the configuration layers and reconciles the running
/// configuration with them.
pub struct ConfigWatcher {
    stop: Arc<AtomicBool>,
    wake: SyncSender<Wake>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl ConfigWatcher {
    /// Create a new config watcher of `layout`'s layers.
    ///
    /// Returns the watcher and a clone of the shared config state.
    ///
    /// # Errors
    ///
    /// The [`with_callback`](Self::with_callback) errors.
    pub fn new(layout: Layout, initial_config: Config) -> core_types::Result<(Self, ConfigState)> {
        Self::with_callback(layout, initial_config, None)
    }

    /// Create a new config watcher of `layout`'s layers, starting from
    /// `initial_config`, with an optional reload notification callback.
    ///
    /// The watches are armed and the initial reconciliation completes before
    /// this returns, so a change made between loading
    /// `initial_config` and arming the watches is not missed, and again on
    /// every filesystem event and every [`RECONCILE_INTERVAL`]. The
    /// callback is invoked after each configuration it
    /// adopts; use it to bridge into async runtimes (e.g. send on a
    /// channel).
    ///
    /// # Errors
    ///
    /// When the reconciliation thread cannot be started. Native watcher
    /// failures use timer reconciliation and are retried.
    pub fn with_callback(
        layout: Layout,
        initial_config: Config,
        on_reload: Option<Box<dyn Fn() + Send + Sync>>,
    ) -> core_types::Result<(Self, ConfigState)> {
        let current = ConfigState::new(initial_config);
        let (wake, wakes) = sync_channel::<Wake>(1);
        let mut arming = Arming::new(layout.clone(), current.clone(), wake.clone());
        arming.arm();
        let mut reconciliation = Reconciliation::new(layout, current.clone(), on_reload);
        reconciliation.run();
        current.status()?.reconciliation.into_result()?;
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = Arc::clone(&stop);
        let thread = std::thread::Builder::new()
            .name("config-reconcile".into())
            .spawn(move || {
                let mut deadline = Instant::now() + RECONCILE_INTERVAL;
                loop {
                    let now = Instant::now();
                    let reply = match wakes.recv_timeout(deadline.saturating_duration_since(now)) {
                        Ok(Wake::Event) => {
                            std::thread::sleep(
                                SETTLE.min(deadline.saturating_duration_since(Instant::now())),
                            );
                            None
                        }
                        Ok(Wake::Reconcile(reply)) => Some(reply),
                        Err(RecvTimeoutError::Timeout) => None,
                        Err(RecvTimeoutError::Disconnected) => break,
                    };
                    if stopping.load(Ordering::Acquire) {
                        break;
                    }
                    arming.arm();
                    reconciliation.run();
                    if let Some(reply) = reply {
                        let result = reconciliation
                            .current
                            .status()
                            .and_then(|status| status.reconciliation.into_result());
                        // The requester stopped waiting; nothing else awaits it.
                        let _ = reply.send(result);
                    }
                    let now = Instant::now();
                    if now >= deadline {
                        deadline = now + RECONCILE_INTERVAL;
                    }
                }
            })
            .map_err(|e| {
                core_types::Error::Config(format!("failed to start the config reconciliation: {e}"))
            })?;
        Ok((
            Self {
                stop,
                wake,
                thread: Some(thread),
            },
            current,
        ))
    }

    /// Obtain a handle for explicit reconciliation requests.
    #[must_use]
    pub fn trigger(&self) -> ReconcileTrigger {
        ReconcileTrigger {
            wake: self.wake.clone(),
        }
    }
}

impl Drop for ConfigWatcher {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        let _ = self.wake.try_send(Wake::Event);
        if let Some(thread) = self.thread.take()
            && thread.join().is_err()
        {
            error!("config reconciliation thread panicked");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc::Receiver;

    #[test]
    fn read_events_do_not_schedule_reconciliation_but_overflow_does() {
        use notify::event::{AccessKind, AccessMode, Flag, MetadataKind, ModifyKind};
        for kind in [
            notify::EventKind::Access(AccessKind::Open(AccessMode::Read)),
            notify::EventKind::Access(AccessKind::Read),
            notify::EventKind::Access(AccessKind::Close(AccessMode::Read)),
            notify::EventKind::Modify(ModifyKind::Metadata(MetadataKind::AccessTime)),
        ] {
            let event = notify::Event::new(kind);
            assert!(!wakes_reconciliation(&event));
            assert!(wakes_reconciliation(&event.set_flag(Flag::Rescan)));
        }
    }

    #[test]
    fn unavailable_native_watcher_does_not_disable_reconciliation() {
        let (_root, layout) = layout();
        let (wake, _wakes) = sync_channel(1);
        let mut arming = Arming::new(layout.clone(), ConfigState::new(Config::default()), wake);
        arming.arm_with(|_| Err(notify::Error::generic("injected initialization failure")));
        assert!(arming.watcher.is_none());
        assert!(matches!(
            arming.state.status().unwrap().watch,
            WatchStatus::Degraded(_)
        ));
        let (mut reconciliation, state) = reconciliation(&layout);
        std::fs::write(layout.config_file().unwrap(), "[profiles.work]\n").unwrap();
        assert_eq!(reconciliation.run(), Outcome::Accepted);
        assert_eq!(profiles(&state), ["work"]);
        arming.arm();
        assert!(arming.watcher.is_some(), "native registration must recover");
        assert_eq!(arming.state.status().unwrap().watch, WatchStatus::Native);
    }

    #[test]
    fn replacement_at_the_same_path_gets_a_new_registration() {
        let (_root, layout) = layout();
        let dir = layout.config_drop_in_dir().unwrap();
        std::fs::create_dir(&dir).unwrap();
        let (wake, wakes) = sync_channel(1);
        let mut arming = Arming::new(layout, ConfigState::new(Config::default()), wake);
        arming.arm();
        std::fs::remove_dir(&dir).unwrap();
        std::fs::create_dir(&dir).unwrap();
        arming.arm();
        // Drain old topology notifications before testing the new registration.
        while wakes.recv_timeout(Duration::from_millis(100)).is_ok() {}
        std::fs::write(dir.join("new.toml"), "[profiles.work]\n").unwrap();
        wakes
            .recv_timeout(Duration::from_secs(2))
            .expect("replacement directory is not watched");
    }

    /// A layout under a fresh root, its configuration directory created.
    fn layout() -> (tempfile::TempDir, Layout) {
        let dir = tempfile::tempdir().unwrap();
        let layout = Layout::under(dir.path());
        std::fs::create_dir_all(layout.config_dir().unwrap()).unwrap();
        (dir, layout)
    }

    /// A watcher of `layout` whose reloads are sent on the returned channel,
    /// with the startup reconciliation's reload already received.
    fn watcher(layout: &Layout) -> (ConfigWatcher, ConfigState, Receiver<()>) {
        let (tx, rx) = std::sync::mpsc::channel();
        let (watcher, state) = ConfigWatcher::with_callback(
            layout.clone(),
            Config::default(),
            Some(Box::new(move || {
                let _ = tx.send(());
            })),
        )
        .unwrap();
        rx.recv_timeout(Duration::from_secs(10))
            .expect("no startup reconciliation");
        (watcher, state, rx)
    }

    /// Within one reconciliation interval and an event's settling time.
    const WITHIN: Duration = Duration::from_secs(10);

    fn profiles(state: &ConfigState) -> Vec<String> {
        state
            .snapshot()
            .unwrap()
            .config
            .profiles
            .keys()
            .cloned()
            .collect()
    }

    /// A reconciliation of `layout` with no watch and no callback.
    fn reconciliation(layout: &Layout) -> (Reconciliation, ConfigState) {
        let current = ConfigState::new(Config::default());
        (
            Reconciliation::new(layout.clone(), current.clone(), None),
            current,
        )
    }

    /// A daemon starts before `sesame init` writes config.toml (the
    /// packages start the daemons at install): the file's creation reloads
    /// the configuration of a watcher started without it.
    #[test]
    fn a_config_file_created_after_the_watcher_starts_reloads() {
        let (_root, layout) = layout();
        let (_watcher, state, rx) = watcher(&layout);
        assert!(profiles(&state).is_empty());

        std::fs::write(layout.config_file().unwrap(), "[profiles.default]\n").unwrap();

        rx.recv_timeout(WITHIN)
            .expect("no reload after config.toml was created");
        assert_eq!(profiles(&state), ["default"]);
    }

    /// Removing a layer changes the configuration: it reloads without it.
    #[test]
    fn removing_a_layer_reloads_without_it() {
        let (_root, layout) = layout();
        let drop_in = layout.config_drop_in_dir().unwrap();
        std::fs::create_dir_all(&drop_in).unwrap();
        std::fs::write(drop_in.join("10-work.toml"), "[profiles.work]\n").unwrap();
        let (_watcher, state, rx) = watcher(&layout);
        assert_eq!(profiles(&state), ["work"]);

        std::fs::remove_file(drop_in.join("10-work.toml")).unwrap();

        rx.recv_timeout(WITHIN)
            .expect("no reload after a layer was removed");
        assert!(profiles(&state).is_empty());
    }

    /// A drop-in directory created after the watcher starts is armed, and
    /// its layers reload.
    #[test]
    fn a_drop_in_directory_created_after_the_watcher_starts_reloads() {
        let (_root, layout) = layout();
        let (_watcher, state, rx) = watcher(&layout);

        let drop_in = layout.config_drop_in_dir().unwrap();
        std::fs::create_dir_all(&drop_in).unwrap();
        std::fs::write(drop_in.join("10-work.toml"), "[profiles.work]\n").unwrap();

        rx.recv_timeout(WITHIN)
            .expect("no reload after a drop-in directory was created");
        assert_eq!(profiles(&state), ["work"]);
    }

    /// The configuration directory itself absent at start (no `sesame init`
    /// yet): it is watched through its ancestor and its layers reload once
    /// it appears.
    #[test]
    fn a_configuration_directory_created_after_the_watcher_starts_reloads() {
        let root = tempfile::tempdir().unwrap();
        let layout = Layout::under(root.path());
        let (_watcher, state, rx) = watcher(&layout);

        std::fs::create_dir_all(layout.config_dir().unwrap()).unwrap();
        std::fs::write(layout.config_file().unwrap(), "[profiles.default]\n").unwrap();

        rx.recv_timeout(WITHIN)
            .expect("no reload after the configuration directory was created");
        assert_eq!(profiles(&state), ["default"]);
    }

    /// Reconciliation is level-driven: a change is applied once, whatever
    /// woke it, and unchanged layers apply nothing.
    #[test]
    fn a_change_is_applied_once_and_unchanged_layers_apply_nothing() {
        let (_root, layout) = layout();
        let (mut reconciliation, current) = reconciliation(&layout);
        assert_eq!(
            reconciliation.run(),
            Outcome::Accepted,
            "the first run loads"
        );
        assert_eq!(reconciliation.run(), Outcome::Unchanged);

        std::fs::write(layout.config_file().unwrap(), "[profiles.work]\n").unwrap();
        assert_eq!(reconciliation.run(), Outcome::Accepted);
        assert_eq!(profiles(&current), ["work"]);
        assert_eq!(reconciliation.run(), Outcome::Unchanged);
    }

    #[test]
    fn recovering_identical_layers_restores_the_result_without_republishing() {
        for contents in ["[profiles.work]\n", "[profiles.work\n"] {
            let (_root, layout) = layout();
            let path = layout.config_file().unwrap();
            std::fs::write(&path, contents).unwrap();
            let (mut reconciliation, state) = reconciliation(&layout);
            let notifications = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let sent = Arc::clone(&notifications);
            reconciliation.on_reload = Some(Box::new(move || {
                sent.fetch_add(1, Ordering::SeqCst);
            }));
            reconciliation.run();
            let before = state.snapshot().unwrap();
            let count = notifications.load(Ordering::SeqCst);

            std::fs::remove_file(&path).unwrap();
            std::fs::create_dir(&path).unwrap();
            assert_eq!(reconciliation.run(), Outcome::Unreadable);
            std::fs::remove_dir(&path).unwrap();
            std::fs::write(&path, contents).unwrap();

            assert_eq!(reconciliation.run(), Outcome::Unchanged);
            let after = state.snapshot().unwrap();
            assert_eq!(after.revision, before.revision);
            assert_eq!(after.status.reconciliation, before.status.reconciliation);
            assert_eq!(notifications.load(Ordering::SeqCst), count);
        }
    }

    /// Files in a layer directory that are not layers reload nothing.
    #[test]
    fn writes_to_files_that_are_not_layers_apply_nothing() {
        let (_root, layout) = layout();
        let (mut reconciliation, _current) = reconciliation(&layout);
        assert_eq!(reconciliation.run(), Outcome::Accepted);
        std::fs::write(layout.audit_log().unwrap(), "{}\n").unwrap();
        assert_eq!(reconciliation.run(), Outcome::Unchanged);
    }

    /// Layers that do not load are rejected; the current configuration is
    /// kept, and the rejection is not retried until the layers change.
    #[test]
    fn a_layer_that_does_not_load_is_rejected_and_the_current_configuration_kept() {
        let (_root, layout) = layout();
        let config = layout.config_file().unwrap();
        std::fs::write(&config, "[profiles.work]\n").unwrap();
        let (mut reconciliation, current) = reconciliation(&layout);
        assert_eq!(reconciliation.run(), Outcome::Accepted);

        std::fs::write(&config, "[profiles.work\n").unwrap();
        assert_eq!(reconciliation.run(), Outcome::Rejected);
        assert!(matches!(
            current.status().unwrap().reconciliation,
            ReconcileStatus::Rejected(_)
        ));
        assert_eq!(profiles(&current), ["work"]);
        assert_eq!(reconciliation.run(), Outcome::Unchanged);

        std::fs::write(&config, "[profiles.home]\n").unwrap();
        assert_eq!(reconciliation.run(), Outcome::Accepted);
        assert_eq!(profiles(&current), ["home"]);
        assert_eq!(
            current.status().unwrap().reconciliation,
            ReconcileStatus::Accepted
        );
    }

    #[test]
    fn construction_finishes_initial_reconciliation_and_snapshots_are_independent() {
        let (_root, layout) = layout();
        std::fs::write(layout.config_file().unwrap(), "[profiles.work]\n").unwrap();
        let (_watcher, state) = ConfigWatcher::new(layout, Config::default()).unwrap();
        let mut snapshot = state.snapshot().unwrap();
        assert!(snapshot.config.profiles.contains_key("work"));
        snapshot.config.profiles.clear();
        assert_eq!(profiles(&state), ["work"]);
        assert_eq!(
            state.status().unwrap().reconciliation,
            ReconcileStatus::Accepted
        );
    }

    #[test]
    fn installation_creation_is_reconciled_with_configuration() {
        let (_root, layout) = layout();
        let (mut reconciliation, state) = reconciliation(&layout);
        reconciliation.run();
        assert!(state.snapshot().unwrap().installation.is_none());
        let installation = crate::InstallationConfig::new(uuid::Uuid::new_v4(), None, None);
        crate::write_installation(&layout, &installation).unwrap();
        assert_eq!(reconciliation.run(), Outcome::Accepted);
        assert_eq!(
            state.snapshot().unwrap().installation.unwrap().id,
            installation.id
        );
        std::fs::write(layout.installation_file().unwrap(), "invalid").unwrap();
        assert_eq!(reconciliation.run(), Outcome::Rejected);
        assert_eq!(
            state.snapshot().unwrap().installation.unwrap().id,
            installation.id
        );
    }

    #[test]
    fn explicit_requests_wait_for_acceptance_and_report_rejection() {
        let (_root, layout) = layout();
        let (watcher, state) = ConfigWatcher::new(layout.clone(), Config::default()).unwrap();
        std::fs::write(layout.config_file().unwrap(), "[profiles.work]\n").unwrap();
        watcher.trigger().reconcile().unwrap();
        assert_eq!(profiles(&state), ["work"]);
        std::fs::write(layout.config_file().unwrap(), "[profiles.work\n").unwrap();
        assert!(watcher.trigger().reconcile().is_err());
        assert_eq!(profiles(&state), ["work"]);
    }

    /// A directory that does not exist is watched through its nearest
    /// existing ancestor.
    #[test]
    fn a_missing_directory_is_watched_through_its_nearest_ancestor() {
        let root = tempfile::tempdir().unwrap();
        let missing = root.path().join("a/b/c");
        assert_eq!(watch_target(&missing), Some(root.path().to_path_buf()));
        std::fs::create_dir_all(root.path().join("a/b")).unwrap();
        assert_eq!(watch_target(&missing), Some(root.path().join("a/b")));
    }
}
