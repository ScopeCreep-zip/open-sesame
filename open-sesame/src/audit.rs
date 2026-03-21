use anyhow::Context;
use owo_colors::OwoColorize;

pub(crate) fn cmd_audit_verify() -> anyhow::Result<()> {
    let audit_path = core_config::config_dir().join("audit.jsonl");

    if !audit_path.exists() {
        println!("{}", "No audit log found.".dimmed());
        return Ok(());
    }

    let contents = std::fs::read_to_string(&audit_path).context("failed to read audit log")?;

    match core_profile::verify_chain(&contents, &core_types::AuditHash::Blake3) {
        Ok(count) => {
            println!("{} {} entries verified.", "OK:".green().bold(), count);
        }
        Err(e) => {
            eprintln!(
                "{} audit chain integrity check failed: {e}",
                "FAIL:".red().bold()
            );
            std::process::exit(1);
        }
    }

    Ok(())
}

pub(crate) async fn cmd_audit_tail(count: usize, follow: bool) -> anyhow::Result<()> {
    let audit_path = core_config::config_dir().join("audit.jsonl");

    if !audit_path.exists() {
        println!("{}", "No audit log found.".dimmed());
        return Ok(());
    }

    let contents = std::fs::read_to_string(&audit_path).context("failed to read audit log")?;

    let lines: Vec<&str> = contents.lines().filter(|l| !l.trim().is_empty()).collect();
    let start = lines.len().saturating_sub(count);

    for line in &lines[start..] {
        print_audit_entry(line);
    }

    if !follow {
        return Ok(());
    }

    // --follow: watch for new appends using notify.
    let mut last_len = std::fs::metadata(&audit_path).map(|m| m.len()).unwrap_or(0);

    let (tx, mut rx) = tokio::sync::mpsc::channel::<()>(4);

    let watch_path = audit_path.clone();
    let _watcher = {
        use notify::{EventKind as NotifyEvent, RecommendedWatcher, RecursiveMode, Watcher};

        let mut watcher = RecommendedWatcher::new(
            move |res: Result<notify::Event, notify::Error>| {
                if let Ok(event) = res
                    && matches!(event.kind, NotifyEvent::Modify(_))
                {
                    let _ = tx.blocking_send(());
                }
            },
            notify::Config::default(),
        )
        .context("failed to start file watcher")?;

        watcher
            .watch(
                watch_path.parent().unwrap_or(watch_path.as_ref()),
                RecursiveMode::NonRecursive,
            )
            .context("failed to watch audit log directory")?;

        watcher
    };

    loop {
        tokio::select! {
            Some(()) = rx.recv() => {
                let new_len = std::fs::metadata(&audit_path)
                    .map(|m| m.len())
                    .unwrap_or(0);

                if new_len > last_len {
                    // Read only the new bytes.
                    use std::io::{Read, Seek, SeekFrom};
                    let mut f = std::fs::File::open(&audit_path)?;
                    f.seek(SeekFrom::Start(last_len))?;
                    let mut buf = String::new();
                    f.read_to_string(&mut buf)?;
                    last_len = new_len;

                    for line in buf.lines() {
                        if !line.trim().is_empty() {
                            print_audit_entry(line);
                        }
                    }
                }
            }
            _ = tokio::signal::ctrl_c() => {
                break;
            }
        }
    }

    Ok(())
}

fn print_audit_entry(line: &str) {
    if let Ok(entry) = serde_json::from_str::<serde_json::Value>(line)
        && let Ok(pretty) = serde_json::to_string_pretty(&entry)
    {
        println!("{pretty}");
        println!("---");
        return;
    }
    println!("{line}");
}
