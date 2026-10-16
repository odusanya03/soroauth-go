//! Bakes the resolved stellar-xdr version into the crate so
//! [`require_pinned`](crate::require_pinned) can refuse to run against
//! anything else.

use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    let manifest =
        PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_string()));
    let lock = fs::read_to_string(manifest.join("Cargo.lock")).unwrap_or_default();
    let mut version = "unknown";
    let mut in_stellar_xdr = false;
    for line in lock.lines() {
        let line = line.trim();
        if line == "name = \"stellar-xdr\"" {
            in_stellar_xdr = true;
        } else if in_stellar_xdr && line.starts_with("version = ") {
            version = line.trim_start_matches("version = ").trim_matches('"');
            break;
        } else if line.starts_with("[[package]]") {
            in_stellar_xdr = false;
        }
    }
    println!("cargo:rustc-env=SOROAUTH_STELLAR_XDR_VERSION={version}");
    println!("cargo:rerun-if-changed=Cargo.lock");
}
