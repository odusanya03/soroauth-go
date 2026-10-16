//! soroauth: build, sign and inspect Soroban authorization entries.
//!
//! When a Soroban contract calls `require_auth()` on an address that is not
//! the transaction's source account, the transaction must carry a signed
//! authorization entry for that address — and the signature is not over the
//! entry, but over a `HashIdPreimage` whose shape depends on which
//! credential arm is in use. This crate is that code, for all three address
//! credential arms: legacy `ADDRESS` (CAP-46-11), `ADDRESS_V2` and
//! `ADDRESS_WITH_DELEGATES` including nested delegate trees (CAP-71-01 and
//! CAP-71-02).
//!
//! # Native implementation, deliberately
//!
//! A native Rust implementation and a binding over the C ABI are different
//! projects with different risks. This crate is the former: it decodes with
//! the same [`stellar-xdr`](https://crates.io/crates/stellar-xdr) crate the
//! Soroban host itself uses, so the
//! [parity harness](../../testdata/parity-rust/) that recomputes the golden
//! vectors with that crate is the correctness gate from day one — no
//! binding layer to audit, no memory-ownership boundary to get wrong.
//!
//! # What agreement proves, and what it does not
//!
//! The framing is [`docs/parity.md`](../../docs/parity.md)'s, inherited
//! whole: agreeing with the reference implementations byte for byte is
//! strong evidence and it is not an audit. A bug every offline
//! implementation shares would stay green everywhere; only the host's
//! verdict closes that gap. Anything the ledger knows — whether a key is a
//! signer, whether a nonce was consumed, whether the expiration is still
//! valid — is not in the bytes being compared.
//!
//! # No `unsafe`
//!
//! The crate forbids unsafe code outright (`#![forbid(unsafe_code)]`).
//! There is no unsafe outside any boundary because there is no boundary:
//! XDR, hashing, base32 and ed25519 all come from safe dependencies.
//!
//! # Honesty boundaries
//!
//! Verification reports [`verify::Verdict`] per node — `Verified`,
//! `Unsigned`, `Invalid`, `CannotCheck` — and there is no boolean
//! anywhere. A custom account's signature is whatever its `__check_auth`
//! accepts, so such a node is `CannotCheck`, never verified.

#![forbid(unsafe_code)]

mod address;
mod error;
mod preimage;
mod sign;
mod verify;

pub use address::{format_address, parse_address};
pub use error::Error;
pub use preimage::{payload, preimage};
pub use sign::{
    authorize, signing_key_for_label, validate_delegate_order, with_delegates, AuthorizeOptions,
    Delegate, KeySigner, MAX_ACCOUNT_SIGNATURES, MAX_DECODE_DEPTH,
};
pub use verify::{verify, NodeVerdict, Report, Verdict};

/// The exact stellar-xdr version this crate is pinned to. The value is baked
/// in by `build.rs` from `Cargo.lock`, never typed here.
pub const REQUIRED_STELLAR_XDR_VERSION: &str = "28.0.0";

/// The stellar-xdr version this build resolved, read from `Cargo.lock` by
/// `build.rs`. It is `"unknown"` when the lockfile was absent.
pub const STELLAR_XDR_VERSION: &str = env!("SOROAUTH_STELLAR_XDR_VERSION");

/// Checks that the build resolved the pinned stellar-xdr version.
///
/// The pin policy is in README.md: the version is exact in `Cargo.toml`,
/// the lockfile is committed, and the crate refuses to run against
/// anything else, so a byte-equality result is always attributed to a
/// named reference build.
pub fn require_pinned() -> Result<(), String> {
    if STELLAR_XDR_VERSION != REQUIRED_STELLAR_XDR_VERSION {
        return Err(format!(
            "built against stellar-xdr {STELLAR_XDR_VERSION}, but pinned to \
             {REQUIRED_STELLAR_XDR_VERSION}"
        ));
    }
    Ok(())
}
