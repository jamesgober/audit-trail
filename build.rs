//! Detects whether the compiler's standard library can lock files
//! (`File::try_lock`, Rust 1.89). The crate's MSRV is 1.85, so the lock that
//! keeps a second process from appending to an open chain file is compiled
//! in only when the compiler has it.

use std::env;
use std::process::Command;

fn main() {
    println!("cargo::rustc-check-cfg=cfg(audit_trail_file_lock)");
    println!("cargo::rerun-if-changed=build.rs");
    println!("cargo::rerun-if-env-changed=RUSTC");
    if rustc_minor().is_some_and(|minor| minor >= 89) {
        println!("cargo::rustc-cfg=audit_trail_file_lock");
    }
}

/// The minor version of the compiler Cargo builds with: `rustc 1.89.0 (...)`.
fn rustc_minor() -> Option<u32> {
    let rustc = env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
    let output = Command::new(rustc).arg("--version").output().ok()?;
    let text = String::from_utf8(output.stdout).ok()?;
    let version = text.split_whitespace().nth(1)?;
    let mut parts = version.split('.');
    if parts.next()? != "1" {
        return None;
    }
    parts.next()?.parse().ok()
}
