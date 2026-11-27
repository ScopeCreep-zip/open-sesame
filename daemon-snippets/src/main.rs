//! daemon-snippets: snippet daemon.
//!
//! Holds text snippets in memory, keyed by trust profile and trigger, and
//! answers list, expand, and add requests over the encrypted IPC bus.
//! Expansion returns the stored template verbatim. Snippets come only from
//! `SnippetAdd` and last for the daemon's lifetime (the configuration
//! defines none).
//!
//! Landlock: bus client, configuration (read), systemd notification socket.
//! No network access beyond local IPC.

use anyhow::Context;
use clap::Parser;
use core_daemon::{DaemonIdentity, EventLoop, LogFormat, Shutdown, Wake};
use core_types::{EventKind, SnippetInfo};
use std::collections::BTreeMap;
use std::convert::Infallible;

/// In-memory snippet store: `(profile name, trigger)` to template,
/// ordered so listings are deterministic.
type SnippetMap = BTreeMap<(String, String), String>;

const IDENTITY: DaemonIdentity = DaemonIdentity {
    daemon: core_types::Daemon::Snippets,
    version: env!("CARGO_PKG_VERSION"),
    capabilities: &["snippets", "expansion"],
};

#[derive(Parser, Debug)]
#[command(name = IDENTITY.daemon.name(), about = "Snippet daemon")]
struct Cli {
    #[arg(long, value_enum, default_value = "json", env = "PDS_LOG_FORMAT")]
    log_format: LogFormat,
}

/// Longest preview, in characters, including the `...` marker.
const PREVIEW_CHARS: usize = 80;

/// The template itself when it fits in `PREVIEW_CHARS` characters,
/// otherwise its first `PREVIEW_CHARS - 3` characters followed by `...`.
/// Counts characters, not bytes, so a multibyte template never splits a
/// code point.
fn template_preview(template: &str) -> String {
    if template.chars().count() <= PREVIEW_CHARS {
        return template.to_string();
    }
    let mut preview: String = template.chars().take(PREVIEW_CHARS - 3).collect();
    preview.push_str("...");
    preview
}

/// Snippets defined for `profile`, as `SnippetInfo` previews, ordered by
/// trigger.
fn list_snippets(snippets: &SnippetMap, profile: &str) -> Vec<SnippetInfo> {
    snippets
        .iter()
        .filter(|((p, _), _)| p == profile)
        .map(|((_, trigger), template)| SnippetInfo {
            trigger: trigger.clone(),
            template_preview: template_preview(template),
        })
        .collect()
}

/// The response to `payload` when it is a snippet request.
fn respond(snippets: &mut SnippetMap, payload: &EventKind) -> Option<EventKind> {
    Some(match payload {
        EventKind::SnippetList { profile } => {
            let listed = list_snippets(snippets, profile.as_ref());
            tracing::debug!(%profile, count = listed.len(), "SnippetList");
            EventKind::SnippetListResponse { snippets: listed }
        }
        EventKind::SnippetExpand { profile, trigger } => {
            let expanded = snippets
                .get(&(profile.to_string(), trigger.clone()))
                .cloned();
            tracing::debug!(%profile, %trigger, found = expanded.is_some(), "SnippetExpand");
            EventKind::SnippetExpandResponse { expanded }
        }
        EventKind::SnippetAdd {
            profile,
            trigger,
            template,
        } => {
            snippets.insert((profile.to_string(), trigger.clone()), template.clone());
            tracing::info!(%profile, %trigger, "snippet added");
            EventKind::SnippetAddResponse { success: true }
        }
        _ => return None,
    })
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    core_daemon::init_logging(cli.log_format)?;

    tracing::info!("daemon-snippets starting");

    #[cfg(target_os = "linux")]
    platform_linux::security::harden_process();

    #[cfg(target_os = "linux")]
    platform_linux::security::apply_resource_limits(&platform_linux::security::ResourceLimits {
        nofile: 4096,
        memlock_bytes: 0,
    });

    let (layout, config) = core_daemon::startup()?;

    core_types::init_secure_memory();

    // The sandbox is applied on the only thread; the configuration
    // watcher starts inside it.
    #[cfg(target_os = "linux")]
    apply_sandbox(&layout)?;

    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("failed to start the async runtime")?
        .block_on(run(layout, config))
}

/// The daemon, from bus connection to shutdown, inside the sandbox.
async fn run(layout: core_layout::Layout, config: core_config::Config) -> anyhow::Result<()> {
    let mut events = EventLoop::new(
        Shutdown::register()?,
        core_daemon::watch_config(&layout, config)?,
    );
    let mut client = core_daemon::connect_bus(&layout, &IDENTITY).await?;
    let mut snippets = SnippetMap::new();

    core_daemon::announce_started(&client, &IDENTITY).await;
    #[cfg(target_os = "linux")]
    platform_linux::systemd::notify_ready();
    tracing::info!("daemon-snippets ready, entering event loop");

    loop {
        match events
            .next(&mut client, std::future::pending::<Infallible>())
            .await?
        {
            Wake::Message(msg) => {
                if let Some(response) = respond(&mut snippets, &msg.payload) {
                    core_daemon::reply(&client, &msg, response).await;
                }
            }
            Wake::ConfigReloaded(_) => {
                core_daemon::announce_config_reloaded(&client, &["snippets"]).await;
            }
            Wake::Own(never) => match never {},
            Wake::Shutdown(_) => break,
        }
    }

    core_daemon::announce_stopped(&client).await;

    tracing::info!("daemon-snippets shut down");
    Ok(())
}

/// Apply Landlock + seccomp: bus client, configuration (read), and the
/// systemd notification socket.
///
/// # Errors
///
/// When a granted location cannot be placed or the sandbox cannot be
/// applied: the daemon does not run unsandboxed.
#[cfg(target_os = "linux")]
fn apply_sandbox(layout: &core_layout::Layout) -> anyhow::Result<()> {
    use core_daemon::sandbox::{config_rules, ipc_client_rules, notify_rules, seccomp_profile};
    use platform_linux::sandbox::FsAccess;

    let mut rules = ipc_client_rules(layout)?;
    rules.extend(config_rules(layout, FsAccess::ReadOnly)?);
    rules.extend(notify_rules(layout)?);

    let seccomp = seccomp_profile(IDENTITY.daemon, &[]);
    core_daemon::sandbox::apply(layout, &rules, &seccomp)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn added_snippets_expand_and_list() {
        let profile = core_types::TrustProfileName::try_from("work").unwrap();
        let mut snippets = SnippetMap::new();
        let add = EventKind::SnippetAdd {
            profile: profile.clone(),
            trigger: "sig".into(),
            template: "Regards".into(),
        };
        assert!(matches!(
            respond(&mut snippets, &add),
            Some(EventKind::SnippetAddResponse { success: true })
        ));
        let expand = EventKind::SnippetExpand {
            profile: profile.clone(),
            trigger: "sig".into(),
        };
        assert!(matches!(
            respond(&mut snippets, &expand),
            Some(EventKind::SnippetExpandResponse { expanded: Some(t) }) if t == "Regards"
        ));
        assert!(matches!(
            respond(&mut snippets, &EventKind::SnippetList { profile }),
            Some(EventKind::SnippetListResponse { snippets }) if snippets.len() == 1
        ));
        assert!(respond(&mut snippets, &EventKind::StatusRequest).is_none());
    }

    #[test]
    fn list_snippets_orders_by_trigger() {
        let mut snippets = SnippetMap::new();
        for trigger in ["zeta", "alpha", "mid"] {
            snippets.insert(("work".into(), trigger.into()), trigger.into());
        }
        let triggers: Vec<String> = list_snippets(&snippets, "work")
            .into_iter()
            .map(|s| s.trigger)
            .collect();
        assert_eq!(triggers, ["alpha", "mid", "zeta"]);
    }

    #[test]
    fn list_snippets_scopes_by_profile() {
        let mut snippets = SnippetMap::new();
        snippets.insert(("work".into(), "addr".into()), "123 Main St".into());
        snippets.insert(("personal".into(), "addr".into()), "456 Oak Ave".into());

        let work = list_snippets(&snippets, "work");
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].trigger, "addr");
        assert_eq!(work[0].template_preview, "123 Main St");
        assert!(list_snippets(&snippets, "absent").is_empty());
    }

    #[test]
    fn template_preview_keeps_short_templates() {
        let exact = "a".repeat(PREVIEW_CHARS);
        assert_eq!(template_preview(&exact), exact);
    }

    #[test]
    fn template_preview_truncates_long_templates() {
        let preview = template_preview(&"a".repeat(100));
        assert_eq!(preview.chars().count(), PREVIEW_CHARS);
        assert!(preview.ends_with("..."));
    }

    #[test]
    fn template_preview_counts_characters_not_bytes() {
        // 'é' is 2 bytes: byte 77 falls inside a code point, and a
        // template of 50 such characters (100 bytes) fits in 80 chars.
        let short = "é".repeat(50);
        assert_eq!(template_preview(&short), short);

        let long = "é".repeat(100);
        let preview = template_preview(&long);
        assert_eq!(preview.chars().count(), PREVIEW_CHARS);
        assert_eq!(preview, format!("{}...", "é".repeat(PREVIEW_CHARS - 3)));
    }
}
