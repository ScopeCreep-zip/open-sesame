//! Xtask automation for Open Sesame
//!
//! This crate provides build automation tasks including:
//! - Man page generation
//! - Shell completion generation
//! - Documentation building
//! - Book building

use anyhow::{Context, Result, bail};
use clap::{Arg, ArgAction, Command, Parser};
use clap_complete::{Shell, generate_to};
use clap_mangen::Man;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process;

/// Read the version from the parent Cargo.toml
///
/// This reads ../Cargo.toml and extracts the version field from [package].
/// Returns an error if the file cannot be read or parsed.
fn read_main_package_version() -> Result<String> {
    let cargo_toml_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .context("Failed to get parent directory")?
        .join("Cargo.toml");

    let content =
        fs::read_to_string(&cargo_toml_path).context("Failed to read parent Cargo.toml")?;

    // Parse the TOML to extract version
    let cargo_toml: toml::Value =
        toml::from_str(&content).context("Failed to parse parent Cargo.toml")?;

    let version = cargo_toml
        .get("package")
        .and_then(|p| p.get("version"))
        .and_then(|v| v.as_str())
        .context("Failed to extract version from Cargo.toml")?;

    Ok(version.to_string())
}

/// Xtask automation for Open Sesame
#[derive(Parser)]
#[command(name = "xtask")]
#[command(about = "Build automation tasks for Open Sesame", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Parser)]
enum Commands {
    /// Generate man pages
    Man,
    /// Generate shell completions
    Completions,
    /// Build rustdoc documentation
    Docs,
    /// Build mdBook documentation
    Book,
    /// Run all documentation generation tasks
    All,
    /// Remove all generated documentation
    Clean,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Man => generate_man_pages(),
        Commands::Completions => generate_completions(),
        Commands::Docs => build_rustdoc(),
        Commands::Book => build_mdbook(),
        Commands::All => {
            generate_man_pages()?;
            generate_completions()?;
            build_rustdoc()?;
            build_mdbook()?;
            Ok(())
        }
        Commands::Clean => clean_all(),
    }
}

/// Build the CLI command definition that mirrors src/main.rs
///
/// This function must be kept in sync with the actual CLI in src/main.rs
/// to ensure generated man pages and completions match the real CLI.
///
/// Version is read from the parent Cargo.toml at runtime to ensure
/// generated documentation matches the actual package version.
fn build_cli_command() -> Command {
    // Read version from parent Cargo.toml and leak it to get 'static lifetime
    // This is acceptable because the version is read once and used throughout the program
    let version: &'static str = Box::leak(
        read_main_package_version()
            .unwrap_or_else(|_| "unknown".to_string())
            .into_boxed_str(),
    );

    Command::new("sesame")
        .version(version)
        .author("usrbinkat")
        .about("Open Sesame - Vimium-style window switcher")
        .long_about("Open Sesame - Vimium-style window switcher for COSMIC desktop.\n\n\
            Shows a centered list of all windows with letter hints. Type a letter\n\
            to instantly focus that window, or use arrow keys to navigate.\n\n\
            Features:\n\
            - Clean centered list UI with letter hints\n\
            - Arrow key navigation with visual selection\n\
            - Repeated letter hints for multiple windows (g, gg, ggg)\n\
            - Focus-or-launch: type a key to focus or launch an app\n\
            - Fast window activation via COSMIC protocols\n\
            - Automatic COSMIC keybinding setup\n\n\
            Setup:\n  \
              sesame --setup-keybinding\n  \
              # Or with custom key combo:\n  \
              sesame --setup-keybinding alt+tab\n\n\
            Configuration: ~/.config/open-sesame/config.toml")
        .arg(
            Arg::new("config")
                .short('c')
                .long("config")
                .value_name("PATH")
                .help("Use a custom configuration file instead of the default")
                .required(false)
        )
        .arg(
            Arg::new("print-config")
                .long("print-config")
                .action(ArgAction::SetTrue)
                .help("Print default configuration and exit")
        )
        .arg(
            Arg::new("validate-config")
                .long("validate-config")
                .action(ArgAction::SetTrue)
                .help("Validate configuration and exit")
        )
        .arg(
            Arg::new("list-windows")
                .long("list-windows")
                .action(ArgAction::SetTrue)
                .help("List current windows and exit")
        )
        .arg(
            Arg::new("setup-keybinding")
                .long("setup-keybinding")
                .value_name("KEY_COMBO")
                .num_args(0..=1)
                .require_equals(false)
                .default_missing_value("")
                .help("Setup COSMIC keybinding using activation_key from config (or specify key combo)")
        )
        .arg(
            Arg::new("remove-keybinding")
                .long("remove-keybinding")
                .action(ArgAction::SetTrue)
                .help("Remove sesame keybinding from COSMIC")
        )
        .arg(
            Arg::new("keybinding-status")
                .long("keybinding-status")
                .action(ArgAction::SetTrue)
                .help("Show current keybinding status")
        )
        .arg(
            Arg::new("backward")
                .short('b')
                .long("backward")
                .action(ArgAction::SetTrue)
                .help("Cycle backward (for Alt+Shift+Tab)")
        )
        .arg(
            Arg::new("launcher")
                .short('l')
                .long("launcher")
                .action(ArgAction::SetTrue)
                .help("Launcher mode: show full overlay with hints (for Alt+Space)\n\
                      Without this flag, runs in switcher mode for Alt+Tab behavior")
        )
}

/// Generate man pages for the sesame binary
fn generate_man_pages() -> Result<()> {
    println!("Generating man pages...");

    let out_dir = PathBuf::from("target/man");
    fs::create_dir_all(&out_dir).context("Failed to create target/man directory")?;

    let cmd = build_cli_command();
    let man = Man::new(cmd);
    let man_path = out_dir.join("sesame.1");

    // Generate uncompressed man page
    let mut man_file = fs::File::create(&man_path).context("Failed to create man page file")?;
    man.render(&mut man_file)
        .context("Failed to write man page")?;

    println!("  Created: {}", man_path.display());

    // Compress with gzip
    let man_gz_path = out_dir.join("sesame.1.gz");
    compress_file(&man_path, &man_gz_path).context("Failed to compress man page")?;

    println!("  Created: {}", man_gz_path.display());
    println!("Man page generation complete!");

    Ok(())
}

/// Generate shell completions for bash, zsh, fish, and powershell
fn generate_completions() -> Result<()> {
    println!("Generating shell completions...");

    let out_dir = PathBuf::from("target/completions");
    fs::create_dir_all(&out_dir).context("Failed to create target/completions directory")?;

    let mut cmd = build_cli_command();
    let bin_name = "sesame";

    for &shell in &[Shell::Bash, Shell::Zsh, Shell::Fish, Shell::PowerShell] {
        let path = generate_to(shell, &mut cmd, bin_name, &out_dir)
            .context(format!("Failed to generate {} completion", shell))?;
        println!("  Created: {}", path.display());
    }

    println!("Shell completion generation complete!");

    Ok(())
}

/// Build rustdoc documentation
fn build_rustdoc() -> Result<()> {
    println!("Building rustdoc documentation...");

    let status = process::Command::new("cargo")
        .args(&["doc", "--no-deps", "--workspace"])
        .status()
        .context("Failed to execute cargo doc")?;

    if !status.success() {
        bail!("cargo doc failed with exit code: {:?}", status.code());
    }

    println!("Rustdoc documentation built successfully!");
    println!("  View at: target/doc/open_sesame/index.html");

    Ok(())
}

/// Build mdBook documentation
fn build_mdbook() -> Result<()> {
    println!("Building mdBook documentation...");

    // Check if mdbook is installed
    let mdbook_check = process::Command::new("mdbook").arg("--version").output();

    match mdbook_check {
        Ok(output) if output.status.success() => {
            // mdbook is installed, use it
            println!(
                "  Found mdbook: {}",
                String::from_utf8_lossy(&output.stdout).trim()
            );
        }
        _ => {
            // mdbook not found, install it
            println!("  mdbook not found, installing via cargo...");
            let install_status = process::Command::new("cargo")
                .args(&["install", "mdbook"])
                .status()
                .context("Failed to install mdbook")?;

            if !install_status.success() {
                bail!("Failed to install mdbook");
            }
            println!("  mdbook installed successfully!");
        }
    }

    // Build the book from the docs directory
    let status = process::Command::new("mdbook")
        .args(&["build", "docs"])
        .status()
        .context("Failed to execute mdbook build")?;

    if !status.success() {
        bail!("mdbook build failed with exit code: {:?}", status.code());
    }

    println!("mdBook documentation built successfully!");
    println!("  View at: docs/book/index.html");

    Ok(())
}

/// Remove all generated documentation
fn clean_all() -> Result<()> {
    println!("Cleaning generated documentation...");

    let paths_to_remove = vec![
        "target/man",
        "target/completions",
        "target/doc",
        "docs/book",
    ];

    for path in paths_to_remove {
        let path_buf = PathBuf::from(path);
        if path_buf.exists() {
            if path_buf.is_dir() {
                fs::remove_dir_all(&path_buf)
                    .context(format!("Failed to remove directory: {}", path))?;
                println!("  Removed: {}", path);
            } else {
                fs::remove_file(&path_buf).context(format!("Failed to remove file: {}", path))?;
                println!("  Removed: {}", path);
            }
        }
    }

    println!("Clean complete!");

    Ok(())
}

/// Compress a file using gzip
fn compress_file(input: &Path, output: &Path) -> Result<()> {
    use flate2::Compression;
    use flate2::write::GzEncoder;

    let input_data = fs::read(input).context("Failed to read input file")?;

    let output_file = fs::File::create(output).context("Failed to create output file")?;

    let mut encoder = GzEncoder::new(output_file, Compression::best());
    encoder
        .write_all(&input_data)
        .context("Failed to write compressed data")?;
    encoder.finish().context("Failed to finish compression")?;

    Ok(())
}
