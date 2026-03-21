//! Open Sesame CLI — platform orchestration for multi-agent desktop control.
//!
//! All subcommands connect to the IPC bus, send a request, wait for a
//! correlated response, format the output, and exit.
//!
//! Exit codes:
//!   0 — success (or child process exit code for `sesame env`)
//!   1 — error (daemon unreachable, request failed, etc.)
//!   2 — timeout waiting for response

mod audit;
mod cli;
mod clipboard;
mod env;
mod helpers;
mod init;
mod input;
mod ipc;
mod launch;
mod profile;
mod secrets;
mod snippets;
mod ssh;
mod status;
mod unlock;
mod wm;
mod workspace;

use clap::Parser;
use owo_colors::OwoColorize;

use cli::*;

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let cli = Cli::parse();

    if let Err(e) = run(cli).await {
        eprintln!("{}: {e:#}", "error".red().bold());
        std::process::exit(1);
    }
}

async fn run(cli: Cli) -> anyhow::Result<()> {
    match cli.command {
        Command::Init {
            no_keybinding,
            wipe_reset_destroy_all_data,
            org,
            ssh_key,
            password,
            auth_policy,
        } => {
            if wipe_reset_destroy_all_data {
                init::cmd_wipe()
            } else {
                init::cmd_init(no_keybinding, org, ssh_key, password, auth_policy).await
            }
        }
        Command::Status => status::cmd_status().await,
        Command::Unlock { profile } => unlock::cmd_unlock(profile).await,
        Command::Lock { profile } => unlock::cmd_lock(profile).await,
        Command::Profile(sub) => match sub {
            ProfileCmd::List => profile::cmd_profile_list().await,
            ProfileCmd::Activate { name } => profile::cmd_profile_activate(&name).await,
            ProfileCmd::Deactivate { name } => profile::cmd_profile_deactivate(&name).await,
            ProfileCmd::Default { name } => profile::cmd_profile_default(&name).await,
            ProfileCmd::Show { name } => profile::cmd_profile_show(&name),
        },
        Command::Ssh(sub) => match sub {
            SshCmd::Enroll { profile, ssh_key } => ssh::cmd_ssh_enroll(profile, ssh_key).await,
            SshCmd::List { profile } => ssh::cmd_ssh_list(profile).await,
            SshCmd::Revoke { profile } => ssh::cmd_ssh_revoke(profile).await,
        },
        Command::Secret(sub) => match sub {
            SecretCmd::Set { profile, key } => secrets::cmd_secret_set(&profile, &key).await,
            SecretCmd::Get { profile, key } => secrets::cmd_secret_get(&profile, &key).await,
            SecretCmd::Delete { profile, key, yes } => {
                secrets::cmd_secret_delete(&profile, &key, yes).await
            }
            SecretCmd::List { profile } => secrets::cmd_secret_list(&profile).await,
        },
        Command::Audit(sub) => match sub {
            AuditCmd::Verify => audit::cmd_audit_verify(),
            AuditCmd::Tail { count, follow } => audit::cmd_audit_tail(count, follow).await,
        },
        Command::Wm(sub) => match sub {
            WmCmd::List => wm::cmd_wm_list().await,
            WmCmd::Switch { backward } => wm::cmd_wm_switch(backward).await,
            WmCmd::Focus { window_id } => wm::cmd_wm_focus(&window_id).await,
            WmCmd::Overlay { launcher, backward } => wm::cmd_wm_overlay(launcher, backward).await,
            WmCmd::OverlayResident => wm::cmd_wm_overlay_resident().await,
        },
        Command::Launch(sub) => match sub {
            LaunchCmd::Search {
                query,
                max_results,
                profile,
            } => launch::cmd_launch_search(&query, max_results, profile.as_deref()).await,
            LaunchCmd::Run { entry_id, profile } => {
                launch::cmd_launch_run(&entry_id, profile.as_deref()).await
            }
        },
        Command::Clipboard(sub) => match sub {
            ClipboardCmd::History { profile, limit } => {
                clipboard::cmd_clipboard_history(&profile, limit).await
            }
            ClipboardCmd::Clear { profile } => clipboard::cmd_clipboard_clear(&profile).await,
            ClipboardCmd::Get { entry_id } => clipboard::cmd_clipboard_get(&entry_id).await,
        },
        Command::Input(sub) => match sub {
            InputCmd::Layers => input::cmd_input_layers().await,
            InputCmd::Status => input::cmd_input_status().await,
        },
        Command::Snippet(sub) => match sub {
            SnippetCmd::List { profile } => snippets::cmd_snippet_list(&profile).await,
            SnippetCmd::Expand { profile, trigger } => {
                snippets::cmd_snippet_expand(&profile, &trigger).await
            }
            SnippetCmd::Add {
                profile,
                trigger,
                template,
            } => snippets::cmd_snippet_add(&profile, &trigger, &template).await,
        },
        #[cfg(all(target_os = "linux", feature = "desktop"))]
        Command::SetupKeybinding { launcher_key } => {
            platform_linux::cosmic_keys::setup_keybinding(&launcher_key)
                .map_err(|e| anyhow::anyhow!("{e}"))
        }
        #[cfg(all(target_os = "linux", feature = "desktop"))]
        Command::RemoveKeybinding => {
            platform_linux::cosmic_keys::remove_keybinding().map_err(|e| anyhow::anyhow!("{e}"))
        }
        #[cfg(all(target_os = "linux", feature = "desktop"))]
        Command::KeybindingStatus => {
            platform_linux::cosmic_keys::keybinding_status().map_err(|e| anyhow::anyhow!("{e}"))
        }
        Command::Env {
            profile,
            prefix,
            command,
        } => env::cmd_env(profile.as_deref(), prefix.as_deref(), &command).await,
        Command::Export {
            profile,
            format,
            prefix,
        } => env::cmd_export(profile.as_deref(), &format, prefix.as_deref()).await,
        Command::Workspace(sub) => workspace::cmd_workspace(sub).await,
    }
}
