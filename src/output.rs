use console::{Color, Term, style};
use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, Ordering};

static VERBOSE: AtomicBool = AtomicBool::new(false);

fn stderr_is_tty() -> bool {
    Term::stderr().is_term()
}

fn format_label(label: &str, color: Color, is_tty: bool) -> String {
    if is_tty {
        style(label).bold().fg(color).to_string()
    } else {
        label.to_string()
    }
}

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

pub fn action_to_with_tty(w: &mut dyn Write, label: &str, msg: &str, is_tty: bool) {
    let _ = write_labeled(label, Color::Cyan, msg, w, is_tty);
}

pub fn success_to_with_tty(w: &mut dyn Write, label: &str, msg: &str, is_tty: bool) {
    let _ = write_labeled(label, Color::Green, msg, w, is_tty);
}

pub fn fail_to_with_tty(w: &mut dyn Write, label: &str, msg: &str, is_tty: bool) {
    let _ = write_labeled(label, Color::Red, msg, w, is_tty);
}

pub fn note_to_with_tty(w: &mut dyn Write, msg: &str, is_tty: bool) {
    let _ = write_labeled("Note", Color::Yellow, msg, w, is_tty);
}

pub fn detail_to_with_tty(w: &mut dyn Write, msg: &str, is_tty: bool) {
    let line = if is_tty {
        style(format!("  {msg}")).dim().to_string()
    } else {
        format!("  {msg}")
    };
    let _ = writeln!(w, "{line}");
}

pub fn action(label: &str, msg: &str) {
    action_to_with_tty(&mut io::stderr(), label, msg, stderr_is_tty());
}

pub fn success(label: &str, msg: &str) {
    success_to_with_tty(&mut io::stderr(), label, msg, stderr_is_tty());
}

pub fn fail(label: &str, msg: &str) {
    fail_to_with_tty(&mut io::stderr(), label, msg, stderr_is_tty());
}

pub fn note(msg: &str) {
    note_to_with_tty(&mut io::stderr(), msg, stderr_is_tty());
}

pub fn detail(msg: &str) {
    detail_to_with_tty(&mut io::stderr(), msg, stderr_is_tty());
}

/// Format a detail message for display without writing it.
/// Used when output needs to be routed through a progress bar via `pb.println()`.
pub fn format_detail(msg: &str) -> String {
    if stderr_is_tty() {
        style(format!("  {msg}")).dim().to_string()
    } else {
        format!("  {msg}")
    }
}

pub fn is_stderr_tty() -> bool {
    stderr_is_tty()
}

pub fn set_verbose(enabled: bool) {
    VERBOSE.store(enabled, Ordering::Relaxed);
}

pub fn is_verbose() -> bool {
    VERBOSE.load(Ordering::Relaxed)
}
