//! Open Sesame CLI
//!
//! Vimium-style window switcher for COSMIC desktop.

use anyhow::{Context, Result};
use clap::Parser;
use open_sesame::{
    app::App,
    config::{Config, ConfigValidator, Severity, load_config_from_paths},
    core::HintAssignment,
    platform,
    util::load_env_files,
};

/// Open Sesame - Vimium-style window switcher
#[derive(Parser)]
#[command(name = "sesame")]
#[command(version, about, long_about = None)]
struct Cli {
    /// Use a custom configuration file instead of the default
    #[arg(long, short = 'c', value_name = "PATH")]
    config: Option<std::path::PathBuf>,

    /// Print default configuration and exit
    #[arg(long)]
    print_config: bool,

    /// Validate configuration and exit
    #[arg(long)]
    validate_config: bool,

    /// List current windows and exit
    #[arg(long)]
    list_windows: bool,

    /// Setup COSMIC keybinding using activation_key from config (or specify key combo)
    #[arg(long, value_name = "KEY_COMBO")]
    setup_keybinding: Option<Option<String>>,

    /// Remove sesame keybinding from COSMIC
    #[arg(long)]
    remove_keybinding: bool,

    /// Show current keybinding status
    #[arg(long)]
    keybinding_status: bool,

    /// Cycle backward (for Alt+Shift+Tab)
    #[arg(long, short = 'b')]
    backward: bool,

    /// Launcher mode: show full overlay with hints (for Alt+Space)
    /// Without this flag, runs in switcher mode for Alt+Tab behavior
    #[arg(long, short = 'l')]
    launcher: bool,
}

fn main() -> Result<()> {
    // Initialize logging first (all output goes to stderr, never stdout)
    open_sesame::util::log::init();

    // Run CLI
    run_cli()
}

/// Process CLI arguments and run appropriate commands
fn run_cli() -> Result<()> {
    tracing::info!("run_cli: parsing CLI arguments");
    let cli = Cli::parse();
    tracing::info!(
        "run_cli: CLI parsed - list_windows={}, launcher={}, backward={}",
        cli.list_windows,
        cli.launcher,
        cli.backward
    );

    // Handle special commands
    if cli.print_config {
        tracing::info!("run_cli: print_config requested");
        println!("{}", Config::default_toml());
        return Ok(());
    }

    // Load configuration
    tracing::info!("run_cli: loading configuration");
    let config = if let Some(ref config_path) = cli.config {
        tracing::info!("run_cli: using custom config path: {:?}", config_path);
        load_config_from_paths(&[config_path.to_string_lossy().to_string()])
            .context("Failed to load custom configuration")?
    } else {
        Config::load().context("Failed to load configuration")?
    };
    tracing::info!("run_cli: configuration loaded successfully");

    if cli.validate_config {
        let issues = ConfigValidator::validate(&config);
        if issues.is_empty() {
            println!("Configuration is valid");
        } else {
            println!("Configuration issues:");
            for issue in &issues {
                let prefix = match issue.severity {
                    Severity::Error => "ERROR",
                    Severity::Warning => "WARNING",
                };
                println!("  - [{}] {}", prefix, issue.message);
            }
        }
        return Ok(());
    }

    if cli.list_windows {
        tracing::info!("run_cli: --list-windows requested");
        // Executes the launcher startup sequence without UI rendering

        // Load environment files
        tracing::info!("list_windows: loading env files");
        load_env_files(&config.settings.env_files);

        // Enumerate windows
        tracing::info!("list_windows: enumerating windows");
        let windows = platform::enumerate_windows().context("Failed to enumerate windows")?;
        tracing::info!("list_windows: found {} windows", windows.len());

        if windows.is_empty() {
            println!("No windows found");
            tracing::info!("list_windows: exiting - no windows");
            return Ok(());
        }

        println!("=== Window Enumeration ===");
        println!("Found {} windows:", windows.len());
        println!("(Focused window moved to end by Wayland enumeration)");
        for (i, w) in windows.iter().enumerate() {
            let marker = if w.is_focused {
                " <-- FOCUSED (origin)"
            } else {
                ""
            };
            println!(
                "  [{}] {} - {} ({}){}",
                i,
                w.id.as_str(),
                w.app_id,
                w.title,
                marker
            );
        }

        // Show MRU state (for debugging, not used for ordering)
        tracing::info!("list_windows: loading MRU state");
        println!("\n=== MRU State (persistence only, not used for ordering) ===");
        let mru_state = open_sesame::util::load_mru_state();
        println!("Previous window: {:?}", mru_state.previous);
        println!("Current window:  {:?}", mru_state.current);
        tracing::info!(
            "list_windows: MRU state - previous={:?}, current={:?}",
            mru_state.previous,
            mru_state.current
        );

        // Assign hints
        tracing::info!("list_windows: assigning hints");
        let assignment =
            HintAssignment::assign(&windows, |app_id| config.key_for_app(app_id.as_str()));

        println!("\n=== Hint Assignment ===");
        for hint in &assignment.hints {
            println!(
                "  [{}] {} - {} ({})",
                hint.hint,
                hint.app_id,
                hint.title,
                hint.window_id.as_str()
            );
            tracing::info!(
                "list_windows: hint [{}] -> {} ({})",
                hint.hint,
                hint.app_id,
                hint.window_id
            );
        }

        // Show what quick Alt+Tab would do (index 0, not MRU)
        println!("\n=== Quick Switch Target (index 0) ===");
        if let Some(hint) = assignment.hints.first() {
            println!(
                "Quick Alt+Tab would activate: [{}] {} ({})",
                hint.hint, hint.app_id, hint.title
            );
            tracing::info!(
                "list_windows: quick switch target = [{}] {}",
                hint.hint,
                hint.app_id
            );
        } else {
            println!("No windows available for quick switch");
            tracing::info!("list_windows: no hints available");
        }

        tracing::info!("list_windows: completed successfully");
        return Ok(());
    }

    // Handle keybinding commands
    if cli.keybinding_status {
        platform::keybinding_status().context("Failed to check keybinding status")?;
        return Ok(());
    }

    if cli.remove_keybinding {
        platform::remove_keybinding().context("Failed to remove keybinding")?;
        return Ok(());
    }

    if let Some(key_combo_opt) = cli.setup_keybinding {
        // Uses provided key combo, defaults to config activation_key if not specified
        let key_combo = key_combo_opt.unwrap_or_else(|| config.settings.activation_key.clone());
        platform::setup_keybinding(&key_combo).context("Failed to setup keybinding")?;
        return Ok(());
    }

    // Main application flow
    run_launcher(config, cli.backward, cli.launcher)
}

fn run_launcher(config: Config, backward: bool, launcher_mode: bool) -> Result<()> {
    tracing::info!(
        "========== LAUNCHER START: backward={}, launcher_mode={} ==========",
        backward,
        launcher_mode
    );

    // Log MRU state at the very beginning
    let initial_mru = open_sesame::util::load_mru_state();
    tracing::info!(
        "MRU STATE ON ENTRY: previous={:?}, current={:?}",
        initial_mru.previous,
        initial_mru.current
    );

    // Ensures single-instance execution; signals existing instance to cycle if already running
    tracing::info!("Acquiring instance lock...");
    let _lock = match open_sesame::util::InstanceLock::acquire() {
        Ok(lock) => {
            tracing::info!("Lock acquired successfully");
            lock
        }
        Err(e) => {
            tracing::info!("Lock acquisition failed: {:?}", e);
            // Send IPC command to running instance
            if backward {
                tracing::info!("Another instance running, signaling to cycle BACKWARD via IPC");
                open_sesame::util::IpcClient::signal_cycle_backward();
            } else {
                tracing::info!("Another instance running, signaling to cycle FORWARD via IPC");
                open_sesame::util::IpcClient::signal_cycle_forward();
            }
            return Ok(());
        }
    };

    // Start IPC server for receiving commands from other instances
    let ipc_server = match open_sesame::util::IpcServer::start() {
        Ok(server) => {
            tracing::info!("IPC server started");
            Some(server)
        }
        Err(e) => {
            tracing::warn!("Failed to start IPC server: {}. IPC disabled.", e);
            None
        }
    };

    // Load environment files
    load_env_files(&config.settings.env_files);

    // Enumerates windows to detect the window of origin (currently focused window)
    tracing::info!("Enumerating windows to detect WINDOW OF ORIGIN...");
    let windows = platform::enumerate_windows().context("Failed to enumerate windows")?;

    if windows.is_empty() {
        tracing::info!("No windows found, exiting");
        return Ok(());
    }

    // Find and log the WINDOW OF ORIGIN (the focused window when launcher started)
    // Clones window information to avoid holding a borrow on windows
    let window_of_origin: Option<(String, String, String)> =
        windows.iter().find(|w| w.is_focused).map(|w| {
            (
                w.app_id.to_string(),
                w.title.clone(),
                w.id.as_str().to_string(),
            )
        });

    if let Some((ref app_id, ref title, ref id)) = window_of_origin {
        tracing::info!(
            ">>> WINDOW OF ORIGIN (focused when launcher started): {} - {} ({})",
            app_id,
            title,
            id
        );
    } else {
        tracing::warn!(">>> NO WINDOW OF ORIGIN detected (no focused window)");
    }

    // Log all windows before any reordering
    tracing::info!("Windows enumerated ({} total):", windows.len());
    for (i, w) in windows.iter().enumerate() {
        let marker = if w.is_focused { " <-- ORIGIN" } else { "" };
        tracing::info!(
            "  [{}] {} - {} ({}){}",
            i,
            w.app_id,
            w.title,
            w.id.as_str(),
            marker
        );
    }

    // Enumeration places focused window (window of origin) at the end of the list
    tracing::info!("Final window order:");
    for (i, w) in windows.iter().enumerate() {
        let marker = if w.is_focused { " <-- ORIGIN" } else { "" };
        tracing::info!("  [{}] {} - {}{}", i, w.app_id, w.title, marker);
    }

    // Assign hints
    let assignment = HintAssignment::assign(&windows, |app_id| config.key_for_app(app_id.as_str()));
    let hints = assignment.hints;
    tracing::info!("Assigned {} hints", hints.len());

    // Determine quick-switch target (MRU previous window)
    // Used by both Alt+Tab (switcher) and Alt+Space (launcher) for quick switch behavior
    // Prioritizes MRU previous window, falls back to index 0
    let mru_previous = open_sesame::util::get_previous_window();
    let quick_switch_target = if !hints.is_empty() {
        // Check if MRU previous window exists in current window list
        if let Some(ref prev_id) = mru_previous {
            if hints.iter().any(|h| h.window_id.as_str() == prev_id) {
                tracing::info!(
                    "QUICK SWITCH TARGET (MRU previous): {}",
                    hints
                        .iter()
                        .find(|h| h.window_id.as_str() == prev_id)
                        .map(|h| format!("{} - {}", h.app_id, h.title))
                        .unwrap_or_else(|| prev_id.clone())
                );
                Some(prev_id.clone())
            } else {
                tracing::info!("MRU previous {} not in window list, using index 0", prev_id);
                tracing::info!(
                    "QUICK SWITCH TARGET (index 0): {} - {}",
                    hints[0].app_id,
                    hints[0].title
                );
                Some(hints[0].window_id.as_str().to_string())
            }
        } else {
            tracing::info!("No MRU previous, using index 0");
            tracing::info!(
                "QUICK SWITCH TARGET (index 0): {} - {}",
                hints[0].app_id,
                hints[0].title
            );
            Some(hints[0].window_id.as_str().to_string())
        }
    } else {
        None
    };

    // Runs the overlay with quick_switch_target as the previous window identifier
    tracing::info!("Calling App::run...");
    let result = App::run(
        config.clone(),
        hints.clone(),
        quick_switch_target.clone(),
        launcher_mode,
        ipc_server,
    )?;
    tracing::info!("App::run returned: {:?}", result);

    // Handle result
    if let Some((idx, identifier)) = result {
        tracing::info!("RESULT: idx={}, window_id={}", idx, identifier);
        if idx == usize::MAX {
            // Handles launch request (usize::MAX indicates launch rather than window selection)
            tracing::info!("ACTION: Launch key={}", identifier);
            let key = &identifier;
            if let Some(launch_config) = config.launch_config(key) {
                let cmd = launch_config.to_launch_command();
                if let Err(e) = cmd.execute(&config.settings.env_files) {
                    tracing::error!("Failed to launch: {}", e);
                }
            }
        } else if idx < hints.len() {
            // Activate the selected window
            let hint = &hints[idx];
            tracing::info!(
                "ACTION: Activating window idx={} - {} ({})",
                idx,
                hint.app_id,
                hint.title
            );

            // Log MRU state BEFORE change
            let mru_before = open_sesame::util::load_mru_state();
            tracing::info!(
                "MRU BEFORE ACTIVATION: previous={:?}, current={:?}",
                mru_before.previous,
                mru_before.current
            );

            let window_id = open_sesame::WindowId::new(&identifier);
            if let Err(e) = platform::activate_window(&window_id) {
                tracing::error!("Failed to activate window: {}", e);
            } else {
                // Updates MRU tracking with origin window as previous, activated window as current
                let origin_id = window_of_origin.as_ref().map(|(_, _, id)| id.as_str());
                open_sesame::util::save_activated_window(origin_id, &identifier);

                // Log MRU state AFTER change
                let mru_after = open_sesame::util::load_mru_state();
                tracing::info!(
                    "MRU AFTER ACTIVATION: previous={:?}, current={:?}",
                    mru_after.previous,
                    mru_after.current
                );

                // Log the full story
                let origin_name = window_of_origin
                    .as_ref()
                    .map(|(app_id, title, _)| format!("{} - {}", app_id, title));
                let target_name = format!("{} - {}", hint.app_id, hint.title);
                tracing::info!(
                    ">>> SWITCH COMPLETE: {} -> {}",
                    origin_name.as_deref().unwrap_or("(unknown)"),
                    target_name
                );
            }
        }
    } else {
        tracing::info!("ACTION: Cancelled (no window activated)");
    }

    tracing::info!("========== LAUNCHER END ==========");
    Ok(())
}
