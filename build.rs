// build.rs — Expose the compile-time target triple as a rustc env var.
//
// Cargo provides the `TARGET` env var to build scripts, which contains the
// canonical target triple (e.g., "aarch64-apple-darwin", "x86_64-unknown-linux-gnu").
// We re-export it as `cargo:rustc-env=TARGET=...` so that runtime code can
// access it via `env!("TARGET")` to select the correct release artifact during
// self-update.
//
// This is the single source of truth for platform metadata in the binary.
// Future update specs (02–06) should consume this value directly rather than
// reconstructing target info elsewhere.

fn main() {
    // Cargo always sets `TARGET` for build scripts. Read it directly — this is
    // the canonical value that matches release artifact naming conventions.
    let target = std::env::var("TARGET")
        .expect("TARGET env var not set by Cargo. This should never happen in a normal build.");

    println!("cargo:rustc-env=TARGET={target}");
}
