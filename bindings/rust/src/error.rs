//! The error type, carrying the same distinctions as the Go sentinels.
//!
//! Every variant names the refusal or fault it reports, so a caller can tell
//! them apart without parsing messages — the same role `errors.Is` plays in
//! Go. Refusals (wrong target, already signed, bad expiration) are the
//! fail-closed outcomes; they are distinct variants rather than one
//! "signing failed", because each calls for a different caller action.

use std::fmt;

/// The error type for every fallible operation in this crate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// A signing payload was requested for a source-account entry, which
    /// carries no signature payload of its own. Mirrors
    /// `soroauth.ErrSourceAccountCredentials`.
    SourceAccountCredentials,
    /// The credentials arm is outside the four defined ones. Mirrors
    /// `soroauth.ErrUnsupportedCredentials`.
    UnsupportedCredentials,
    /// No credential node carries the target address. Mirrors
    /// `soroauth.ErrNoMatchingCredentialNode` and carries the address.
    NoMatchingCredentialNode {
        /// The target address that matched no node.
        address: String,
    },
    /// One address appears twice within a single delegates array, which
    /// CAP-71-01 forbids. Mirrors `soroauth.ErrDuplicateDelegate`.
    DuplicateDelegate {
        /// The offending address.
        address: String,
    },
    /// A produced signature does not verify against its payload. Mirrors
    /// `soroauth.ErrSignatureMismatch`.
    SignatureMismatch,
    /// No signer was provided for an address that needs one. Mirrors
    /// `soroauth.ErrMissingSigner` and carries the address.
    MissingSigner {
        /// The address with no signer.
        address: String,
    },
    /// Signing would overwrite a signature that is already present.
    /// Mirrors `soroauth.ErrAlreadySigned`.
    AlreadySigned,
    /// The expiration ledger is zero, or disagrees with the expiration
    /// already committed to by signatures on the entry. Mirrors
    /// `soroauth.ErrInvalidExpiration`.
    InvalidExpiration,
    /// More signing keys than the host accepts (20). Mirrors
    /// `soroauth.ErrTooManySignatures`.
    TooManySignatures,
    /// Untrusted input exceeds a decode bound. Mirrors
    /// `soroauth.ErrDecodeLimit`.
    DecodeLimit,
    /// The network passphrase is empty. An empty passphrase hashes to a
    /// valid-looking network id for a network that does not exist, so it
    /// is refused rather than silently producing an unusable signature.
    EmptyPassphrase,
    /// An address is not a G… or C… strkey this crate reads. Only those
    /// two appear in authorization entries.
    InvalidAddress(String),
    /// XDR decoding failed for a reason outside the bounded checks.
    MalformedXdr(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::SourceAccountCredentials => {
                write!(
                    f,
                    "credentials are source-account, which carry no signature payload"
                )
            }
            Error::UnsupportedCredentials => write!(f, "unsupported credentials type"),
            Error::NoMatchingCredentialNode { address } => {
                write!(f, "no credential node matches the target address {address}")
            }
            Error::DuplicateDelegate { address } => {
                write!(f, "duplicate delegate address at the same level: {address}")
            }
            Error::SignatureMismatch => {
                write!(f, "signature does not verify against the payload")
            }
            Error::MissingSigner { address } => {
                write!(f, "no signer for address {address}")
            }
            Error::AlreadySigned => write!(f, "credential node is already signed"),
            Error::InvalidExpiration => write!(f, "invalid signature expiration ledger"),
            Error::TooManySignatures => {
                write!(f, "too many signatures for a classic account")
            }
            Error::DecodeLimit => write!(f, "untrusted input exceeds a decode limit"),
            Error::EmptyPassphrase => write!(f, "network passphrase is empty"),
            Error::InvalidAddress(address) => write!(f, "{address} is not a G… or C… address"),
            Error::MalformedXdr(detail) => write!(f, "malformed XDR: {detail}"),
        }
    }
}

impl std::error::Error for Error {}
