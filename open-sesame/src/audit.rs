use anyhow::Context;
use core_layout::Layout;
use owo_colors::OwoColorize;

pub(crate) fn cmd_audit_verify(layout: &Layout) -> anyhow::Result<()> {
    let audit_path = layout.audit_log()?;
    let algorithm = core_config::load_config(layout)?
        .crypto()
        .context("invalid [crypto] configuration")?
        .audit_hash;
    match core_profile::verify_audit_log(&audit_path, algorithm)
        .context("audit chain integrity check failed")?
    {
        None => println!("{}", "No audit log found.".dimmed()),
        Some(count) => println!("{} {count} entries verified.", "OK:".green().bold()),
    }
    Ok(())
}

pub(crate) async fn cmd_audit_tail(
    layout: &Layout,
    count: usize,
    follow: bool,
) -> anyhow::Result<()> {
    let audit_path = layout.audit_log()?;
    let Some(contents) = core_profile::read_audit_log(&audit_path)? else {
        println!("{}", "No audit log found.".dimmed());
        return Ok(());
    };

    // Only complete lines: an entry caught mid-write is printed whole by the
    // follow loop.
    let complete = complete_lines(contents.as_bytes());
    let text = String::from_utf8_lossy(complete);
    let lines: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
    for line in &lines[lines.len().saturating_sub(count)..] {
        print_audit_entry(line);
    }

    if !follow {
        return Ok(());
    }

    // Resume after the complete lines read, not at the current file length,
    // so neither appends between the read and the watch nor the remainder of
    // a partial entry are skipped.
    let mut last_len = u64::try_from(complete.len()).context("audit log length exceeds u64")?;
    let watch_dir = audit_path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("audit log {} has no parent", audit_path.display()))?
        .to_path_buf();

    let (tx, mut rx) = tokio::sync::mpsc::channel::<()>(4);
    let _watcher = {
        use notify::{EventKind as NotifyEvent, RecommendedWatcher, RecursiveMode, Watcher};

        let mut watcher = RecommendedWatcher::new(
            move |res: Result<notify::Event, notify::Error>| match res {
                // A full channel already holds a pending wake-up, which reads
                // every byte appended so far; a closed one means the tail
                // loop has exited.
                Ok(event) if matches!(event.kind, NotifyEvent::Modify(_)) => {
                    if let Err(tokio::sync::mpsc::error::TrySendError::Closed(())) = tx.try_send(())
                    {
                        tracing::debug!("audit tail stopped; change notification dropped");
                    }
                }
                Ok(_) => {}
                Err(e) => eprintln!("{} audit log watch error: {e}", "WARN:".yellow().bold()),
            },
            notify::Config::default(),
        )
        .context("failed to start file watcher")?;
        watcher
            .watch(&watch_dir, RecursiveMode::NonRecursive)
            .with_context(|| format!("failed to watch {}", watch_dir.display()))?;
        watcher
    };

    loop {
        tokio::select! {
            Some(()) = rx.recv() => {
                let new_len = std::fs::metadata(&audit_path)
                    .with_context(|| format!("failed to stat {}", audit_path.display()))?
                    .len();
                anyhow::ensure!(
                    new_len >= last_len,
                    "{} shrank from {last_len} to {new_len} bytes: the audit log is append-only",
                    audit_path.display()
                );
                if new_len > last_len {
                    use std::io::{Read, Seek, SeekFrom};
                    let mut f = std::fs::File::open(&audit_path)
                        .with_context(|| format!("failed to open {}", audit_path.display()))?;
                    f.seek(SeekFrom::Start(last_len))
                        .with_context(|| format!("failed to seek {}", audit_path.display()))?;
                    let mut buf = Vec::new();
                    f.read_to_end(&mut buf)
                        .with_context(|| format!("failed to read {}", audit_path.display()))?;
                    // Only complete lines: an entry caught mid-write is
                    // read whole on the next change.
                    let complete = complete_lines(&buf);
                    last_len += u64::try_from(complete.len()).context("audit chunk exceeds u64")?;
                    for line in String::from_utf8_lossy(complete)
                        .lines()
                        .filter(|l| !l.trim().is_empty())
                    {
                        print_audit_entry(line);
                    }
                }
            }
            signal = tokio::signal::ctrl_c() => {
                signal.context("failed to wait for Ctrl-C")?;
                break;
            }
        }
    }
    Ok(())
}

/// The prefix of `buf` through its last newline: the lines written in full.
fn complete_lines(buf: &[u8]) -> &[u8] {
    buf.iter()
        .rposition(|&b| b == b'\n')
        .map_or(&[], |last| &buf[..=last])
}

/// One audit entry pretty-printed; a line that is not JSON is printed as
/// it is (`sesame audit verify` reports it).
fn print_audit_entry(line: &str) {
    match serde_json::from_str::<serde_json::Value>(line)
        .and_then(|entry| serde_json::to_string_pretty(&entry))
    {
        Ok(pretty) => {
            println!("{pretty}");
            println!("---");
        }
        Err(_) => println!("{line}"),
    }
}

#[cfg(test)]
mod tests {
    use super::complete_lines;

    #[test]
    fn a_line_caught_mid_write_is_left_for_the_next_read() {
        assert_eq!(complete_lines(b"{\"a\":1}\n{\"b\""), b"{\"a\":1}\n");
        assert_eq!(complete_lines(b"{\"a\":1}\n"), b"{\"a\":1}\n");
        assert_eq!(complete_lines(b"{\"partial\""), b"");
        assert_eq!(complete_lines(b""), b"");
    }
}
