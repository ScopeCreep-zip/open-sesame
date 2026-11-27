//! Interactive input: passwords, secret values, confirmations, and text.
//!
//! With a terminal on stdin each prompt is interactive; with piped stdin
//! the answer is read from it (one line, or all of it for a secret value)
//! and the prompt goes to stderr, so scripts and tests drive every prompt.

use std::io::{BufRead, IsTerminal, Read};

use anyhow::Context;
use core_crypto::SecureVec;
use zeroize::Zeroizing;

fn stdin_is_terminal() -> bool {
    std::io::stdin().is_terminal()
}

/// Remove one trailing line ending (`\n` or `\r\n`).
fn strip_line_ending(buf: &mut String) {
    if buf.ends_with('\n') {
        buf.pop();
        if buf.ends_with('\r') {
            buf.pop();
        }
    }
}

/// One line of piped stdin without its line ending.
fn piped_line(what: &str) -> anyhow::Result<Zeroizing<String>> {
    let mut buf = Zeroizing::new(String::new());
    std::io::stdin()
        .lock()
        .read_line(&mut buf)
        .with_context(|| format!("failed to read {what} from stdin"))?;
    strip_line_ending(&mut buf);
    Ok(buf)
}

/// What a hidden terminal entry asks for.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Hidden {
    /// A password for an existing vault: entered once, never empty.
    Password,
    /// A new password: entered twice, never empty.
    NewPassword,
    /// A secret value: entered once, may be empty.
    Value,
}

/// Hidden entry on the terminal.
fn hidden(prompt: &str, kind: Hidden) -> anyhow::Result<Zeroizing<String>> {
    let mut entry = dialoguer::Password::new().with_prompt(prompt);
    if kind == Hidden::NewPassword {
        entry = entry.with_confirmation(
            "        Confirm",
            "        Passwords don't match, try again",
        );
    }
    if kind == Hidden::Value {
        entry = entry.allow_empty_password(true);
    }
    Ok(Zeroizing::new(
        entry.interact().context("failed to read hidden input")?,
    ))
}

/// A password, hidden on a terminal or one line of piped stdin, moved
/// into locked memory. Empty is refused.
fn read_password(prompt: &str, kind: Hidden) -> anyhow::Result<SecureVec> {
    let entered = if stdin_is_terminal() {
        hidden(prompt, kind)?
    } else {
        piped_line("password")?
    };
    anyhow::ensure!(!entered.is_empty(), "empty password refused ({prompt})");
    let mut secure = SecureVec::for_password();
    for ch in entered.chars() {
        secure.push_char(ch);
    }
    Ok(secure)
}

/// A password for an existing vault. Empty is refused.
///
/// # Errors
///
/// When input cannot be read or the password is empty.
pub(crate) fn password(prompt: &str) -> anyhow::Result<SecureVec> {
    read_password(prompt, Hidden::Password)
}

/// A new password, entered twice on a terminal. Empty is refused.
///
/// # Errors
///
/// When input cannot be read or the password is empty.
pub(crate) fn new_password(prompt: &str) -> anyhow::Result<SecureVec> {
    read_password(prompt, Hidden::NewPassword)
}

/// A secret value: hidden entry on a terminal, else all of stdin with one
/// trailing line ending removed. Empty is a valid value.
///
/// # Errors
///
/// When input cannot be read.
pub(crate) fn secret_value(prompt: &str) -> anyhow::Result<Zeroizing<String>> {
    if stdin_is_terminal() {
        return hidden(prompt, Hidden::Value);
    }
    let mut buf = Zeroizing::new(String::new());
    std::io::stdin()
        .read_to_string(&mut buf)
        .context("failed to read secret value from stdin")?;
    strip_line_ending(&mut buf);
    Ok(buf)
}

/// A yes/no confirmation; anything but `y`/`yes` (any case) is no.
///
/// # Errors
///
/// When input cannot be read.
pub(crate) fn confirm(prompt: &str) -> anyhow::Result<bool> {
    if stdin_is_terminal() {
        return dialoguer::Confirm::new()
            .with_prompt(prompt)
            .default(false)
            .interact()
            .context("failed to read confirmation");
    }
    eprintln!("{prompt} [y/N]");
    Ok(is_yes(&piped_line("confirmation")?))
}

fn is_yes(answer: &str) -> bool {
    matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}

/// A line of text.
///
/// # Errors
///
/// When input cannot be read.
pub(crate) fn text(prompt: &str) -> anyhow::Result<String> {
    if stdin_is_terminal() {
        return dialoguer::Input::new()
            .with_prompt(prompt)
            .interact_text()
            .context("failed to read input");
    }
    eprintln!("{prompt}:");
    Ok(piped_line("input")?.to_string())
}

/// Select one of `items` on a terminal; piped stdin cannot select.
///
/// # Errors
///
/// When stdin is not a terminal (`no_terminal` names the alternative) or
/// the selection is cancelled.
pub(crate) fn select(prompt: &str, items: &[String], no_terminal: &str) -> anyhow::Result<usize> {
    anyhow::ensure!(stdin_is_terminal(), "{no_terminal}");
    dialoguer::Select::new()
        .with_prompt(prompt)
        .items(items)
        .default(0)
        .interact()
        .context("selection cancelled")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_line_ending_is_stripped() {
        for (input, expected) in [
            ("value\n", "value"),
            ("value\r\n", "value"),
            ("value\n\n", "value\n"),
            ("value", "value"),
            ("\n", ""),
        ] {
            let mut buf = input.to_owned();
            strip_line_ending(&mut buf);
            assert_eq!(buf, expected, "{input:?}");
        }
    }

    #[test]
    fn only_y_or_yes_confirms() {
        for yes in ["y", "Y", "yes", " YES "] {
            assert!(is_yes(yes), "{yes}");
        }
        for no in ["", "n", "no", "yess", "sure"] {
            assert!(!is_yes(no), "{no}");
        }
    }
}
