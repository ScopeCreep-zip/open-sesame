//! Build automation for Open Sesame (`cargo xtask <task>`).
//!
//! The man page and shell completions are rendered from
//! `open_sesame::cli::Cli`, the definition the `sesame` binary parses with;
//! its version is the workspace package version. Outputs land in
//! `target/man` and `target/completions`, where the deb, rpm, AUR, and
//! tarball packaging pick them up.

use anyhow::{Context, Result, bail};
use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::{Shell, generate_to};
use clap_mangen::Man;
use flate2::Compression;
use flate2::write::GzEncoder;
use open_sesame::cli::Cli;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process;

/// The installed name of the CLI binary.
const BIN_NAME: &str = "sesame";

/// Build automation tasks for Open Sesame.
#[derive(Parser)]
#[command(name = "xtask")]
struct Xtask {
    #[command(subcommand)]
    task: Task,
}

#[derive(Subcommand)]
enum Task {
    /// Generate the man page: target/man/sesame.1 and sesame.1.gz.
    Man,
    /// Generate bash, zsh, fish, and PowerShell completions in target/completions.
    Completions,
    /// Build rustdoc for the workspace.
    Docs,
    /// Build the mdBook user guide (mdbook from the devshell).
    Book,
    /// Run every generation task.
    All,
    /// Remove all generated documentation.
    Clean,
}

fn main() -> Result<()> {
    match Xtask::parse().task {
        Task::Man => generate_man_page(),
        Task::Completions => generate_completions(),
        Task::Docs => build_rustdoc(),
        Task::Book => build_mdbook(),
        Task::All => {
            generate_man_page()?;
            generate_completions()?;
            build_rustdoc()?;
            build_mdbook()
        }
        Task::Clean => clean_all(),
    }
}

/// The `sesame` command tree.
fn sesame_command() -> clap::Command {
    Cli::command().bin_name(BIN_NAME)
}

/// Render the man page, then a gzip copy of it.
fn generate_man_page() -> Result<()> {
    let out_dir = Path::new("target/man");
    fs::create_dir_all(out_dir).context("create target/man")?;

    let man_path = out_dir.join(format!("{BIN_NAME}.1"));
    let mut page = Vec::new();
    Man::new(sesame_command())
        .render(&mut page)
        .context("render man page")?;
    fs::write(&man_path, &page).with_context(|| format!("write {}", man_path.display()))?;
    println!("created {}", man_path.display());

    let gz_path = out_dir.join(format!("{BIN_NAME}.1.gz"));
    let file =
        fs::File::create(&gz_path).with_context(|| format!("create {}", gz_path.display()))?;
    let mut encoder = GzEncoder::new(file, Compression::best());
    encoder
        .write_all(&page)
        .and_then(|()| encoder.finish().map(drop))
        .with_context(|| format!("write {}", gz_path.display()))?;
    println!("created {}", gz_path.display());
    Ok(())
}

/// Render completions for every packaged shell.
fn generate_completions() -> Result<()> {
    let out_dir = Path::new("target/completions");
    fs::create_dir_all(out_dir).context("create target/completions")?;

    let mut cmd = sesame_command();
    for shell in [Shell::Bash, Shell::Zsh, Shell::Fish, Shell::PowerShell] {
        let path = generate_to(shell, &mut cmd, BIN_NAME, out_dir)
            .with_context(|| format!("generate {shell} completion"))?;
        println!("created {}", path.display());
    }
    Ok(())
}

/// Run `program args` and fail on a non-zero exit.
fn run(program: &str, args: &[&str]) -> Result<()> {
    let status = process::Command::new(program)
        .args(args)
        .status()
        .with_context(|| format!("run {program}; is it on PATH (nix develop)?"))?;
    if !status.success() {
        bail!("{program} {} failed: {status}", args.join(" "));
    }
    Ok(())
}

fn build_rustdoc() -> Result<()> {
    run("cargo", &["doc", "--no-deps", "--workspace"])?;
    println!("rustdoc: target/doc/open_sesame/index.html");
    Ok(())
}

fn build_mdbook() -> Result<()> {
    run("mdbook", &["build", "docs"])?;
    println!("mdBook: docs/book/index.html");
    Ok(())
}

fn clean_all() -> Result<()> {
    for path in [
        "target/man",
        "target/completions",
        "target/doc",
        "docs/book",
    ]
    .into_iter()
    .map(PathBuf::from)
    {
        match fs::remove_dir_all(&path) {
            Ok(()) => println!("removed {}", path.display()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e).with_context(|| format!("remove {}", path.display())),
        }
    }
    Ok(())
}
