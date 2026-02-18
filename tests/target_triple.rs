//! Tests for the compile-time TARGET env var set by build.rs.
//!
//! These tests validate that the binary knows its own platform target triple,
//! which is required for selecting the correct release artifact during self-update.

/// The compile-time TARGET value emitted by build.rs.
const TARGET: &str = env!("TARGET");

#[test]
fn target_is_non_empty() {
    // This assertion is trivially true at compile time (env! would fail on
    // empty), but it documents the contract and catches build script regressions
    // if the emission logic changes.
    #[allow(clippy::const_is_empty)]
    let non_empty = !TARGET.is_empty();
    assert!(non_empty, "TARGET compile-time env var must not be empty");
}

#[test]
fn target_has_minimum_segment_count() {
    // Valid target triples have at least 3 segments (arch-vendor-os or arch-os-env).
    // Most have 3–4: e.g., "aarch64-apple-darwin" (3), "x86_64-unknown-linux-gnu" (4).
    let segments: Vec<&str> = TARGET.split('-').collect();
    assert!(
        segments.len() >= 3,
        "TARGET '{TARGET}' should have at least 3 hyphen-separated segments, got {}",
        segments.len()
    );
}

#[test]
fn target_segments_are_non_empty() {
    for (i, segment) in TARGET.split('-').enumerate() {
        assert!(
            !segment.is_empty(),
            "TARGET '{TARGET}' segment {i} is empty — malformed triple"
        );
    }
}

#[test]
fn target_contains_known_os_identifier() {
    // The target triple must contain a recognized OS identifier that maps to
    // release artifact names. This prevents false positives from malformed
    // values like "aarch64" (missing OS) or accidental sentinels.
    const KNOWN_OS: &[&str] = &["darwin", "linux", "windows", "freebsd", "netbsd", "android"];

    let has_known_os = TARGET.split('-').any(|segment| KNOWN_OS.contains(&segment));

    assert!(
        has_known_os,
        "TARGET '{TARGET}' does not contain a recognized OS identifier (expected one of {KNOWN_OS:?})"
    );
}

#[test]
fn target_is_not_a_placeholder() {
    // Guard against accidental sentinel values that might slip through if
    // the build script is misconfigured.
    let lower = TARGET.to_lowercase();
    assert!(
        lower != "unknown",
        "TARGET must not be the bare string 'unknown'"
    );
    assert!(
        lower != "default",
        "TARGET must not be the bare string 'default'"
    );
}

#[test]
fn target_starts_with_known_architecture() {
    // First segment should be a recognized CPU architecture.
    const KNOWN_ARCH: &[&str] = &[
        "x86_64",
        "aarch64",
        "i686",
        "arm",
        "armv7",
        "powerpc64",
        "powerpc64le",
        "s390x",
        "riscv64gc",
        "mips",
        "mipsel",
        "loongarch64",
    ];

    let arch = TARGET
        .split('-')
        .next()
        .expect("TARGET has at least one segment");

    assert!(
        KNOWN_ARCH.contains(&arch),
        "TARGET '{TARGET}' starts with unrecognized architecture '{arch}' (expected one of {KNOWN_ARCH:?})"
    );
}
