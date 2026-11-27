//! daemon-input: keyboard capture daemon.
//!
//! Captures keyboard events via evdev and translates them with XKB.
//! While daemon-wm holds a grab, key events are forwarded to it over the
//! bus; Alt/Meta releases are forwarded unconditionally.
//!
//! Landlock: /dev/input and its sysfs metadata (read), bus client,
//! configuration (read). No network access beyond local IPC.

mod keyboard;

use anyhow::Context;
use clap::Parser;
use core_daemon::{DaemonIdentity, EventLoop, LogFormat, Shutdown, Wake};
use core_types::{DaemonId, EventKind, InputLayerInfo, SecurityLevel, keysym};

const IDENTITY: DaemonIdentity = DaemonIdentity {
    daemon: core_types::Daemon::Input,
    version: env!("CARGO_PKG_VERSION"),
    capabilities: &["input"],
};

#[derive(Parser, Debug)]
#[command(name = IDENTITY.daemon.name(), about = "Keyboard capture daemon")]
struct Cli {
    #[arg(long, value_enum, default_value = "json", env = "PDS_LOG_FORMAT")]
    log_format: LogFormat,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    core_daemon::init_logging(cli.log_format)?;

    tracing::info!("daemon-input starting");

    #[cfg(target_os = "linux")]
    platform_linux::security::harden_process();

    #[cfg(target_os = "linux")]
    platform_linux::security::apply_resource_limits(&platform_linux::security::ResourceLimits {
        nofile: 4096,
        memlock_bytes: 0,
    });

    let (layout, config) = core_daemon::startup()?;

    core_types::init_secure_memory();

    // The keymap is compiled before the sandbox: its XKB data (under
    // /usr/share/X11/xkb, or the Nix store) and libxkbcommon's
    // real-versus-effective ID check stay outside it. The runtime is
    // current-thread on this thread, so the state never changes threads.
    let xkb = keyboard::XkbContext::new();
    if xkb.is_none() {
        tracing::warn!(
            "failed to initialize XKB context — keyboard forwarding will send raw keycodes without keysym translation"
        );
    }

    // The sandbox is applied on the only thread; the configuration
    // watcher and the keyboard readers start inside it.
    #[cfg(target_os = "linux")]
    apply_sandbox(&layout, &config)?;

    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("failed to start the async runtime")?
        .block_on(run(layout, config, xkb))
}

/// The key event to forward to daemon-wm, if any: every event while
/// `grabbed`; otherwise only Alt/Meta releases. Those are forwarded
/// regardless of the grab because on a single-threaded runtime the
/// `InputGrabRequest` may arrive after the user has already released Alt;
/// without them daemon-wm would miss the release that ends its cycle.
/// Presses are not needed, which bounds the ungrabbed traffic to four
/// keysyms.
fn forwarded(event: EventKind, grabbed: bool) -> Option<EventKind> {
    match event {
        _ if grabbed => Some(event),
        EventKind::InputKeyEvent {
            keyval,
            pressed: false,
            ..
        } if keysym::is_alt_or_meta(keyval) => Some(event),
        _ => None,
    }
}

/// The response to `payload` when it is an input request; grab requests
/// and releases update `grab` (the daemon the keyboard is forwarded to).
fn respond(grab: &mut Option<DaemonId>, payload: &EventKind) -> Option<EventKind> {
    match payload {
        EventKind::InputGrabRequest { requester } => {
            tracing::info!(%requester, "keyboard grab requested");
            *grab = Some(*requester);
            Some(EventKind::InputGrabResponse {
                success: true,
                error: None,
            })
        }
        EventKind::InputGrabRelease { requester } => {
            if grab.as_ref() == Some(requester) {
                tracing::info!(%requester, "keyboard grab released");
                *grab = None;
            } else {
                tracing::debug!(%requester, current = ?grab, "ignoring grab release from non-owner");
            }
            None
        }
        EventKind::InputLayersList => Some(layers_list_response()),
        EventKind::InputStatus => Some(status_response()),
        _ => None,
    }
}

/// The daemon, from keyboard capture and bus connection to shutdown,
/// inside the sandbox, translating keys with `xkb`.
async fn run(
    layout: core_layout::Layout,
    config: core_config::Config,
    mut xkb: Option<keyboard::XkbContext>,
) -> anyhow::Result<()> {
    let mut events = EventLoop::new(
        Shutdown::register()?,
        core_daemon::watch_config(&layout, config)?,
    );
    let mut keyboard_rx = keyboard::spawn_keyboard_readers();
    let mut grab: Option<DaemonId> = None;
    let mut client = core_daemon::connect_bus(&layout, &IDENTITY).await?;

    core_daemon::announce_started(&client, &IDENTITY).await;
    #[cfg(target_os = "linux")]
    platform_linux::systemd::notify_ready();
    tracing::info!("daemon-input ready, entering event loop");

    loop {
        // Once every reader has stopped, the keyboard source is idle.
        let key = async {
            match keyboard_rx.recv().await {
                Some(raw) => raw,
                None => std::future::pending().await,
            }
        };
        match events.next(&mut client, key).await? {
            Wake::Own(raw) => {
                // XKB state is updated for every key, grabbed or not, so
                // modifier tracking is accurate when a grab begins.
                let event = keyboard::translate(xkb.as_mut(), raw);
                if let Some(event) = forwarded(event, grab.is_some()) {
                    // Forwarded keys drive the WM overlay: a lost event
                    // desynchronizes it, so a failed publish ends the daemon.
                    client
                        .publish(event, SecurityLevel::Internal)
                        .await
                        .context("InputKeyEvent publish failed")?;
                }
            }
            Wake::Message(msg) => {
                if let Some(response) = respond(&mut grab, &msg.payload) {
                    core_daemon::reply(&client, &msg, response).await;
                }
            }
            Wake::ConfigReloaded(_) => {
                core_daemon::announce_config_reloaded(&client, &["input"]).await;
            }
            Wake::Shutdown(_) => break,
        }
    }

    core_daemon::announce_stopped(&client).await;
    tracing::info!("daemon-input shut down");
    Ok(())
}

/// Response to `InputLayersList`. evdev remapping is not wired, so the
/// only layer is the active, empty `default` layer.
fn layers_list_response() -> EventKind {
    EventKind::InputLayersListResponse {
        layers: vec![InputLayerInfo {
            name: "default".into(),
            is_active: true,
            remap_count: 0,
        }],
    }
}

/// Response to `InputStatus`: the `default` layer, no grabbed devices,
/// remapping inactive.
fn status_response() -> EventKind {
    EventKind::InputStatusResponse {
        active_layer: "default".into(),
        grabbed_devices: vec![],
        remapping_active: false,
    }
}

/// Apply Landlock + seccomp under `config`'s sandbox floor: bus client,
/// configuration (read), the systemd notification socket, and the evdev
/// device nodes with their sysfs metadata.
///
/// # Errors
///
/// When a granted location cannot be placed, the kernel is below the
/// floor, or the sandbox cannot be applied: the daemon does not run.
#[cfg(target_os = "linux")]
fn apply_sandbox(layout: &core_layout::Layout, config: &core_config::Config) -> anyhow::Result<()> {
    use core_daemon::sandbox::{config_rules, ipc_client_rules, notify_rules, seccomp_profile};
    use platform_linux::sandbox::{FsAccess, LandlockRule};

    let mut rules = ipc_client_rules(layout)?;
    rules.extend(config_rules(layout, FsAccess::ReadOnly)?);
    rules.extend(notify_rules(layout)?);
    rules.extend(
        [
            "/dev/input",
            // evdev enumerate() reads device symlinks and metadata here,
            "/sys/class/input",
            // and follows them to the device nodes' metadata here.
            "/sys/devices",
        ]
        .into_iter()
        .map(|path| LandlockRule {
            path: path.into(),
            access: FsAccess::ReadOnly,
        }),
    );

    let seccomp = seccomp_profile(IDENTITY.daemon, &[]);
    core_daemon::sandbox::apply(layout, config, &rules, &seccomp)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(keyval: u32, pressed: bool) -> EventKind {
        EventKind::InputKeyEvent {
            keyval,
            keycode: 0,
            pressed,
            modifiers: 0,
            unicode: None,
        }
    }

    #[test]
    fn grabbed_keys_all_forward_and_ungrabbed_only_alt_meta_releases() {
        assert!(forwarded(key(0x61, true), true).is_some());
        assert!(forwarded(key(keysym::ALT_L, true), true).is_some());
        assert!(forwarded(key(0x61, false), false).is_none());
        assert!(forwarded(key(keysym::ALT_L, true), false).is_none());
        for keyval in [keysym::META_L, keysym::META_R, keysym::ALT_L, keysym::ALT_R] {
            assert!(forwarded(key(keyval, false), false).is_some());
        }
    }

    #[test]
    fn only_the_grab_owner_releases_it() {
        let (owner, other) = (DaemonId::new(), DaemonId::new());
        let mut grab = None;
        assert!(matches!(
            respond(&mut grab, &EventKind::InputGrabRequest { requester: owner }),
            Some(EventKind::InputGrabResponse { success: true, .. })
        ));
        assert_eq!(grab, Some(owner));
        assert!(respond(&mut grab, &EventKind::InputGrabRelease { requester: other }).is_none());
        assert_eq!(grab, Some(owner));
        respond(&mut grab, &EventKind::InputGrabRelease { requester: owner });
        assert_eq!(grab, None);
    }

    #[test]
    fn layers_list_reports_active_default_layer() {
        let EventKind::InputLayersListResponse { layers } = layers_list_response() else {
            panic!("layers_list_response returned the wrong event kind");
        };
        assert_eq!(layers.len(), 1);
        assert_eq!(layers[0].name, "default");
        assert!(layers[0].is_active);
        assert_eq!(layers[0].remap_count, 0);
    }

    #[test]
    fn status_reports_default_layer_without_remapping() {
        let EventKind::InputStatusResponse {
            active_layer,
            grabbed_devices,
            remapping_active,
        } = status_response()
        else {
            panic!("status_response returned the wrong event kind");
        };
        assert_eq!(active_layer, "default");
        assert!(grabbed_devices.is_empty());
        assert!(!remapping_active);
    }
}
