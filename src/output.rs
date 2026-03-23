//! Terminal output helpers for consistent CLI status messaging.

use console::{Color, Term, style};
use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, Ordering};

/// Global verbose-output toggle shared across CLI modules.
static VERBOSE: AtomicBool = AtomicBool::new(false);

/// Returns whether stderr is attached to an interactive terminal.
fn stderr_is_tty() -> bool {
    Term::stderr().is_term()
}

/// Formats a status label with ANSI styling when stderr is interactive.
fn format_label(label: &str, color: Color, is_tty: bool) -> String {
    if is_tty {
        style(label).bold().fg(color).to_string()
    } else {
        label.to_string()
    }
}

/// Writes a single labeled status line to the provided writer.
fn write_labeled(
    label: &str,
    color: Color,
    msg: &str,
    w: &mut dyn Write,
    is_tty: bool,
) -> io::Result<()> {
    let label = format_label(label, color, is_tty);
    if msg.is_empty() {
        writeln!(w, "{label}")
    } else {
        writeln!(w, "{label} {msg}")
    }
}

/// Writes an action-style status line using the caller's TTY preference.
pub fn action_to_with_tty(w: &mut dyn Write, label: &str, msg: &str, is_tty: bool) {
    let _ = write_labeled(label, Color::Cyan, msg, w, is_tty);
}

/// Writes a success-style status line using the caller's TTY preference.
pub fn success_to_with_tty(w: &mut dyn Write, label: &str, msg: &str, is_tty: bool) {
    let _ = write_labeled(label, Color::Green, msg, w, is_tty);
}

/// Writes a failure-style status line using the caller's TTY preference.
pub fn fail_to_with_tty(w: &mut dyn Write, label: &str, msg: &str, is_tty: bool) {
    let _ = write_labeled(label, Color::Red, msg, w, is_tty);
}

/// Writes a note line using the caller's TTY preference.
pub fn note_to_with_tty(w: &mut dyn Write, msg: &str, is_tty: bool) {
    let _ = write_labeled("Note", Color::Yellow, msg, w, is_tty);
}

/// Writes an indented detail line using the caller's TTY preference.
pub fn detail_to_with_tty(w: &mut dyn Write, msg: &str, is_tty: bool) {
    let line = if is_tty {
        style(format!("  {msg}")).dim().to_string()
    } else {
        format!("  {msg}")
    };
    let _ = writeln!(w, "{line}");
}

/// Writes an action-style status line to stderr.
pub fn action(label: &str, msg: &str) {
    action_to_with_tty(&mut io::stderr(), label, msg, stderr_is_tty());
}

/// Writes a success-style status line to stderr.
pub fn success(label: &str, msg: &str) {
    success_to_with_tty(&mut io::stderr(), label, msg, stderr_is_tty());
}

/// Writes a failure-style status line to stderr.
pub fn fail(label: &str, msg: &str) {
    fail_to_with_tty(&mut io::stderr(), label, msg, stderr_is_tty());
}

/// Writes a note line to stderr.
pub fn note(msg: &str) {
    note_to_with_tty(&mut io::stderr(), msg, stderr_is_tty());
}

/// Writes an indented detail line to stderr.
pub fn detail(msg: &str) {
    detail_to_with_tty(&mut io::stderr(), msg, stderr_is_tty());
}

/// Returns whether stderr is attached to an interactive terminal.
pub fn is_stderr_tty() -> bool {
    stderr_is_tty()
}

/// Enables or disables verbose diagnostic output.
pub fn set_verbose(enabled: bool) {
    VERBOSE.store(enabled, Ordering::Relaxed);
}

/// Returns whether verbose diagnostic output is enabled.
pub fn is_verbose() -> bool {
    VERBOSE.load(Ordering::Relaxed)
}
