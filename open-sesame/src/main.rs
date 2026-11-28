//! Open Sesame CLI — platform orchestration for multi-agent desktop control.
//!
//! Bus subcommands connect to the IPC bus, send a request, wait for its
//! correlated response, print it, and exit.
//!
//! Exit status:
//!   0 — success; `sesame env` and `sesame workspace shell` exit with the
//!       command's status, `sesame status --doctor --exit-code` with the
//!       check summary
//!   1 — error (daemon unreachable, request refused, invalid input)
//!   2 — a request received no response in time

mod audit;
mod child;
mod clipboard;
mod doctor;
mod enrollment;
mod env;
mod helpers;
mod init;
mod input;
mod ipc;
#[cfg(all(target_os = "linux", feature = "desktop"))]
mod keybinding;
mod keyring;
mod launch;
mod profile;
mod prompt;
mod secrets;
mod snippets;
mod ssh;
mod status;
mod unlock;
mod wm;
mod workspace;

use std::process::ExitCode;

use clap::Parser;
use core_layout::Layout;
use owo_colors::OwoColorize;

use open_sesame::cli::{
    AuditCmd, Cli, ClipboardCmd, Command, InputCmd, KeyringCmd, LaunchCmd, ProfileCmd, SecretCmd,
    SnippetCmd, SshCmd, WmCmd, WorkspaceCmd,
};

/// The exit status of a failed command: 2 when a request timed out, else 1.
fn failure_code(error: &anyhow::Error) -> ExitCode {
    let timed_out = error.chain().any(|cause| {
        matches!(
            cause.downcast_ref::<core_types::Error>(),
            Some(core_types::Error::Timeout { .. })
        )
    });
    ExitCode::from(if timed_out { 2 } else { 1 })
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match core_daemon::init_cli_logging() {
        Ok(()) => run(&Layout::from_process(), cli).await,
        Err(e) => Err(e),
    };
    result.unwrap_or_else(|e| {
        eprintln!("{}: {e:#}", "error".red().bold());
        failure_code(&e)
    })
}

/// `result` as a successful exit.
fn done(result: anyhow::Result<()>) -> anyhow::Result<ExitCode> {
    result.map(|()| ExitCode::SUCCESS)
}

async fn run(layout: &Layout, cli: Cli) -> anyhow::Result<ExitCode> {
    match cli.command {
        Command::Init {
            wipe_reset_destroy_all_data: true,
            ..
        } => done(init::cmd_wipe(layout)),
        Command::Init {
            no_keybinding,
            wipe_reset_destroy_all_data: false,
            org,
            ssh_key,
            password,
            auth_policy,
        } => done(
            init::cmd_init(
                layout,
                no_keybinding,
                org.as_deref(),
                ssh_key.as_ref().map(|value| value.as_deref().into()),
                password,
                auth_policy,
            )
            .await,
        ),
        Command::Status {
            doctor,
            output,
            exit_code,
            quiet,
            rotate_keys,
        } => match (rotate_keys, doctor) {
            (true, _) => done(status::cmd_rotate_keys(layout).await),
            (false, Some(categories)) => {
                doctor::cmd_doctor(layout, &categories, output, exit_code || quiet, quiet).await
            }
            (false, None) => done(status::cmd_status(layout).await),
        },
        Command::Unlock { profile } => done(unlock::cmd_unlock(layout, &profile).await),
        Command::Lock { profile } => done(unlock::cmd_lock(layout, profile).await),
        Command::Profile(sub) => done(run_profile(layout, sub).await),
        Command::Ssh(sub) => done(run_ssh(layout, sub).await),
        Command::Keyring(sub) => done(run_keyring(layout, sub).await),
        Command::Secret(sub) => done(run_secret(layout, sub).await),
        Command::Audit(sub) => done(run_audit(layout, sub).await),
        Command::Wm(sub) => done(run_wm(layout, sub).await),
        Command::Launch(sub) => done(run_launch(layout, sub).await),
        Command::Clipboard(sub) => done(run_clipboard(layout, sub).await),
        Command::Input(InputCmd::Layers) => done(input::cmd_input_layers(layout).await),
        Command::Input(InputCmd::Status) => done(input::cmd_input_status(layout).await),
        Command::Snippet(sub) => done(run_snippet(layout, sub).await),
        #[cfg(all(target_os = "linux", feature = "desktop"))]
        Command::SetupKeybinding { launcher_key } => {
            done(keybinding::cmd_setup(layout, launcher_key).await)
        }
        #[cfg(all(target_os = "linux", feature = "desktop"))]
        Command::RemoveKeybinding => done(keybinding::cmd_remove(layout).await),
        #[cfg(all(target_os = "linux", feature = "desktop"))]
        Command::KeybindingStatus => done(keybinding::cmd_status(layout).await),
        Command::Clone {
            url,
            depth,
            profile,
            no_workspace,
            project,
            include_forks,
            include_archived,
        } => {
            // `sesame clone` is `sesame workspace clone` with its defaults.
            let clone = WorkspaceCmd::Clone {
                url,
                depth,
                profile,
                adopt: true,
                workspace_init: false,
                workspace_update: false,
                no_workspace,
                force: false,
                project,
                include_forks,
                include_archived,
            };
            workspace::cmd_workspace(layout, clone).await
        }
        Command::Env {
            profile,
            prefix,
            command,
        } => env::cmd_env(layout, &profile, prefix.as_deref(), &command).await,
        Command::Export {
            profile,
            format,
            prefix,
        } => done(env::cmd_export(layout, &profile, format, prefix.as_deref()).await),
        Command::Workspace(sub) => workspace::cmd_workspace(layout, sub).await,
    }
}

async fn run_profile(layout: &Layout, sub: ProfileCmd) -> anyhow::Result<()> {
    match sub {
        ProfileCmd::List => profile::cmd_profile_list(layout).await,
        ProfileCmd::Activate { name } => profile::cmd_profile_activate(layout, name).await,
        ProfileCmd::Deactivate { name } => profile::cmd_profile_deactivate(layout, name).await,
        ProfileCmd::Default { name } => profile::cmd_profile_default(layout, name).await,
        ProfileCmd::Show { name } => profile::cmd_profile_show(layout, &name),
    }
}

async fn run_ssh(layout: &Layout, sub: SshCmd) -> anyhow::Result<()> {
    match sub {
        SshCmd::Enroll { profile, ssh_key } => {
            ssh::cmd_ssh_enroll(layout, &profile, ssh_key.as_deref()).await
        }
        SshCmd::List { profile } => ssh::cmd_ssh_list(layout, &profile).await,
        SshCmd::Revoke { profile } => ssh::cmd_ssh_revoke(layout, &profile).await,
    }
}

async fn run_keyring(layout: &Layout, sub: KeyringCmd) -> anyhow::Result<()> {
    match sub {
        KeyringCmd::Enroll { profile } => keyring::cmd_keyring_enroll(layout, &profile).await,
        KeyringCmd::Status { profile, json } => {
            keyring::cmd_keyring_status(layout, &profile, json).await
        }
        KeyringCmd::Revoke { profile } => keyring::cmd_keyring_revoke(layout, &profile).await,
    }
}

async fn run_secret(layout: &Layout, sub: SecretCmd) -> anyhow::Result<()> {
    match sub {
        SecretCmd::Set { profile, key } => secrets::cmd_secret_set(layout, &profile, &key).await,
        SecretCmd::Get { profile, key } => secrets::cmd_secret_get(layout, &profile, &key).await,
        SecretCmd::Delete { profile, key, yes } => {
            secrets::cmd_secret_delete(layout, &profile, &key, yes).await
        }
        SecretCmd::List { profile } => secrets::cmd_secret_list(layout, &profile).await,
    }
}

async fn run_audit(layout: &Layout, sub: AuditCmd) -> anyhow::Result<()> {
    match sub {
        AuditCmd::Verify => audit::cmd_audit_verify(layout),
        AuditCmd::Tail { count, follow } => audit::cmd_audit_tail(layout, count, follow).await,
    }
}

async fn run_launch(layout: &Layout, sub: LaunchCmd) -> anyhow::Result<()> {
    match sub {
        LaunchCmd::Search {
            query,
            max_results,
            profile,
        } => launch::cmd_launch_search(layout, &query, max_results, profile).await,
        LaunchCmd::Run { entry_id, profile } => {
            launch::cmd_launch_run(layout, &entry_id, profile).await
        }
    }
}

async fn run_wm(layout: &Layout, sub: WmCmd) -> anyhow::Result<()> {
    match sub {
        WmCmd::List => wm::cmd_wm_list(layout).await,
        WmCmd::Switch { backward } => wm::cmd_wm_switch(layout, backward).await,
        WmCmd::Focus { window_id } => wm::cmd_wm_focus(layout, &window_id).await,
        WmCmd::Overlay { launcher, backward } => {
            wm::cmd_wm_overlay(layout, launcher, backward).await
        }
        WmCmd::OverlayResident => wm::cmd_wm_overlay_resident(layout).await,
    }
}

async fn run_clipboard(layout: &Layout, sub: ClipboardCmd) -> anyhow::Result<()> {
    match sub {
        ClipboardCmd::History { profile, limit } => {
            clipboard::cmd_clipboard_history(layout, profile, limit).await
        }
        ClipboardCmd::Clear { profile } => clipboard::cmd_clipboard_clear(layout, profile).await,
        ClipboardCmd::Get { entry_id } => clipboard::cmd_clipboard_get(layout, entry_id).await,
    }
}

async fn run_snippet(layout: &Layout, sub: SnippetCmd) -> anyhow::Result<()> {
    match sub {
        SnippetCmd::List { profile } => snippets::cmd_snippet_list(layout, profile).await,
        SnippetCmd::Expand { profile, trigger } => {
            snippets::cmd_snippet_expand(layout, profile, &trigger).await
        }
        SnippetCmd::Add {
            profile,
            trigger,
            template,
        } => snippets::cmd_snippet_add(layout, profile, &trigger, &template).await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timeouts_exit_2_and_other_failures_exit_1() {
        let timeout = anyhow::Error::from(core_types::Error::Timeout {
            operation: "StatusRequest".into(),
            after: std::time::Duration::from_secs(5),
        })
        .context("status failed");
        assert_eq!(failure_code(&timeout), ExitCode::from(2));
        assert_eq!(failure_code(&anyhow::anyhow!("refused")), ExitCode::from(1));
        let ipc = anyhow::Error::from(core_types::Error::Ipc("closed".into()));
        assert_eq!(failure_code(&ipc), ExitCode::from(1));
    }
}
