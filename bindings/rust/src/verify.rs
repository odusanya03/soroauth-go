//! Offline verification: do the signatures on an entry verify over the
//! payload the entry itself commits to?
//!
//! There are four verdicts, not three, and no boolean anywhere: a signature
//! that is present and does not verify is a different thing to report than
//! an unsigned node or a shape that cannot be checked. Collapsing a failed
//! signature into "unsigned" would let a tampered entry read the same as an
//! entry that was simply never signed, and collapsing `cannot_check` into
//! `false` would erase the distinction the whole library keeps.

use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
use stellar_xdr::{ScAddress, ScVal, SorobanAuthorizationEntry, SorobanCredentials, VecM};

use crate::address::format_address;
use crate::error::Error;
use crate::preimage::{payload, preimage};
use crate::sign::{address_credentials, is_signed};

/// One credential node's offline verification outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// The node carries a classic account signature that verifies over the
    /// payload the entry commits to.
    Verified,
    /// The node carries no signature. Under CAP-71-01 a delegates entry
    /// may legitimately leave its top-level node Void.
    Unsigned,
    /// The node carries a classic account signature that does not verify.
    Invalid,
    /// The node's signature is not the built-in account shape, so offline
    /// code cannot decide it. The normal outcome for a custom account whose
    /// `__check_auth` defines its own shape. Never reported as verified.
    CannotCheck,
}

impl Verdict {
    /// The stable string the Go library and the HTTP surfaces report.
    pub fn as_str(&self) -> &'static str {
        match self {
            Verdict::Verified => "verified",
            Verdict::Unsigned => "unsigned",
            Verdict::Invalid => "invalid",
            Verdict::CannotCheck => "cannot_check",
        }
    }
}

/// The verification outcome for one credential node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeVerdict {
    /// The G… or C… address of the node.
    pub address: String,
    /// The outcome.
    pub verdict: Verdict,
    /// Why, in plain language, when the verdict is not [`Verdict::Verified`].
    pub reason: String,
}

/// The result of [`verify`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    /// The stable credential-type string: `source_account`, `address`,
    /// `address_v2` or `address_with_delegates`.
    pub credential_type: String,
    /// Whether the arm's payload binds the address into the signed bytes
    /// (CAP-71-01): V2 and delegates.
    pub address_bound: bool,
    /// The entry's address, for the three address arms.
    pub address: String,
    /// The expiration the payload was rebuilt with: the value stored on the
    /// entry, never one supplied by the caller.
    pub valid_until_ledger: u32,
    /// One verdict per credential node, top-level first, then the delegate
    /// tree depth-first. Empty for the source-account arm.
    pub nodes: Vec<NodeVerdict>,
    /// A caveat about the whole report, such as the source-account arm
    /// carrying nothing to check.
    pub note: String,
}

impl Report {
    /// Whether every credential node verified. True vacuously when there
    /// are no nodes; unsigned, invalid and cannot-check nodes all make it
    /// false. Verification fails closed.
    pub fn verified(&self) -> bool {
        self.nodes
            .iter()
            .all(|node| node.verdict == Verdict::Verified)
    }
}

/// Checks an entry's signatures against the payload the entry itself
/// commits to, without submitting anything.
///
/// The payload is rebuilt from the entry — its arm, nonce, address,
/// invocation tree and, in particular, the expiration stored on the entry.
/// Only classic account signatures can be decided offline; any other shape
/// is [`Verdict::CannotCheck`], never verified. Whether the signing key is
/// actually a signer of the account, and whether a nonce was consumed, are
/// account-state questions offline code cannot see and does not claim to
/// answer.
pub fn verify(
    entry: &SorobanAuthorizationEntry,
    network_passphrase: &str,
) -> Result<Report, Error> {
    match &entry.credentials {
        SorobanCredentials::SourceAccount => {
            return Ok(Report {
                credential_type: "source_account".to_string(),
                address_bound: false,
                address: String::new(),
                valid_until_ledger: 0,
                nodes: Vec::new(),
                note: "source-account credentials carry no signature payload of their own; \
                    the transaction envelope's signature covers them, so there is nothing here to verify"
                    .to_string(),
            })
        }
        SorobanCredentials::Address(_)
        | SorobanCredentials::AddressV2(_)
        | SorobanCredentials::AddressWithDelegates(_) => {}
    }

    let credentials = address_credentials(&entry.credentials)?;
    let address = format_address(&credentials.address)?;
    let expiration = credentials.signature_expiration_ledger;
    let built = preimage(entry, expiration, network_passphrase)?;
    let payload_bytes = payload(&built)?;

    let mut nodes = Vec::new();
    collect_verdicts(entry, &payload_bytes, &mut nodes)?;
    Ok(Report {
        credential_type: credential_type_name(&entry.credentials).to_string(),
        address_bound: !matches!(&entry.credentials, SorobanCredentials::Address(_)),
        address,
        valid_until_ledger: expiration,
        nodes,
        note: String::new(),
    })
}

/// The stable credential-type string.
fn credential_type_name(credentials: &SorobanCredentials) -> &'static str {
    match credentials {
        SorobanCredentials::SourceAccount => "source_account",
        SorobanCredentials::Address(_) => "address",
        SorobanCredentials::AddressV2(_) => "address_v2",
        SorobanCredentials::AddressWithDelegates(_) => "address_with_delegates",
    }
}

/// Collects one verdict per credential node: the top-level node, then the
/// delegate tree depth-first.
fn collect_verdicts(
    entry: &SorobanAuthorizationEntry,
    payload_bytes: &[u8; 32],
    out: &mut Vec<NodeVerdict>,
) -> Result<(), Error> {
    let credentials = address_credentials(&entry.credentials)?;
    out.push(verify_node(
        &credentials.address,
        &credentials.signature,
        payload_bytes,
    )?);
    if let SorobanCredentials::AddressWithDelegates(with_delegates) = &entry.credentials {
        collect_delegate_verdicts(&with_delegates.delegates, payload_bytes, out, 1)?;
    }
    Ok(())
}

/// Collects verdicts under one delegates array.
fn collect_delegate_verdicts(
    delegates: &VecM<stellar_xdr::SorobanDelegateSignature>,
    payload_bytes: &[u8; 32],
    out: &mut Vec<NodeVerdict>,
    depth: u32,
) -> Result<(), Error> {
    if depth > crate::sign::MAX_DECODE_DEPTH {
        return Err(Error::DecodeLimit);
    }
    for node in delegates.iter() {
        out.push(verify_node(&node.address, &node.signature, payload_bytes)?);
        collect_delegate_verdicts(&node.nested_delegates, payload_bytes, out, depth + 1)?;
    }
    Ok(())
}

/// Decides one credential node's verdict.
fn verify_node(
    address: &ScAddress,
    signature: &ScVal,
    payload_bytes: &[u8; 32],
) -> Result<NodeVerdict, Error> {
    let formatted = format_address(address)?;
    if !is_signed(signature) {
        return Ok(NodeVerdict {
            address: formatted,
            verdict: Verdict::Unsigned,
            reason: "the node carries no signature (Void or an empty vector)".to_string(),
        });
    }
    // A node addressed to a contract can never be decided here: the value
    // it holds is whatever that contract's __check_auth expects.
    if !matches!(address, ScAddress::Account(_)) {
        return Ok(NodeVerdict {
            address: formatted,
            verdict: Verdict::CannotCheck,
            reason: "the node addresses a C… contract; only the contract's __check_auth defines \
                whether its signature is valid, so this cannot be checked offline"
                .to_string(),
        });
    }
    let (public_key, raw_signature) = match parse_account_signature(signature) {
        Ok(parts) => parts,
        Err(detail) => {
            return Ok(NodeVerdict {
                address: formatted,
                verdict: Verdict::CannotCheck,
                reason: format!(
                    "the signature is not the built-in {{public_key, signature}} account shape; \
                    only the account's own logic defines its validity, so this cannot be \
                    checked offline ({detail})"
                ),
            })
        }
    };
    let verifying_key =
        VerifyingKey::from_bytes(&public_key).map_err(|_| Error::SignatureMismatch)?;
    let signature = Signature::from_bytes(&raw_signature);
    if verifying_key.verify(payload_bytes, &signature).is_err() {
        return Ok(NodeVerdict {
            address: formatted,
            verdict: Verdict::Invalid,
            reason: "the stored signature does not verify over the payload the entry commits to"
                .to_string(),
        });
    }
    Ok(NodeVerdict {
        address: formatted,
        verdict: Verdict::Verified,
        reason: String::new(),
    })
}

/// Reads back the single `{public_key, signature}` map the host decodes as
/// one account signature. Anything else is unreadable, which the caller
/// reports as [`Verdict::CannotCheck`] rather than a verdict.
fn parse_account_signature(value: &ScVal) -> Result<([u8; 32], [u8; 64]), String> {
    let entries = match value {
        ScVal::Vec(Some(vec)) => &vec.0,
        other => {
            return Err(format!(
                "signature is {}, not the built-in account vector",
                scval_type_name(other)
            ))
        }
    };
    if entries.len() != 1 {
        return Err(format!(
            "signature vector holds {} entries, want exactly 1",
            entries.len()
        ));
    }
    let map = match &entries[0] {
        ScVal::Map(Some(map)) => &map.0,
        other => {
            return Err(format!(
                "signature vector holds {}, not a map",
                scval_type_name(other)
            ))
        }
    };
    let mut public_key: Option<Vec<u8>> = None;
    let mut signature: Option<Vec<u8>> = None;
    for entry in map.iter() {
        let name = match &entry.key {
            ScVal::Symbol(symbol) => String::try_from(symbol.0.clone()).unwrap_or_default(),
            _ => continue,
        };
        let bytes = match &entry.val {
            ScVal::Bytes(bytes) => bytes.0.to_vec(),
            _ => return Err(format!("signature field {name:?} is not bytes")),
        };
        match name.as_str() {
            "public_key" => public_key = Some(bytes),
            "signature" => signature = Some(bytes),
            _ => {}
        }
    }
    let public_key = public_key.ok_or_else(|| "signature map is missing public_key".to_string())?;
    let signature = signature.ok_or_else(|| "signature map is missing signature".to_string())?;
    if public_key.len() != 32 {
        return Err(format!(
            "signature public key is {} bytes, want 32",
            public_key.len()
        ));
    }
    if signature.len() != 64 {
        return Err(format!("signature is {} bytes, want 64", signature.len()));
    }
    let mut public_key_array = [0u8; 32];
    public_key_array.copy_from_slice(&public_key);
    let mut signature_array = [0u8; 64];
    signature_array.copy_from_slice(&signature);
    Ok((public_key_array, signature_array))
}

/// A short name for an ScVal in error strings.
fn scval_type_name(value: &ScVal) -> &'static str {
    match value {
        ScVal::Bool(_) => "bool",
        ScVal::Void => "void",
        ScVal::Error(_) => "error",
        ScVal::U32(_) => "u32",
        ScVal::I32(_) => "i32",
        ScVal::U64(_) => "u64",
        ScVal::I64(_) => "i64",
        ScVal::Timepoint(_) => "timepoint",
        ScVal::Duration(_) => "duration",
        ScVal::U128(_) => "u128",
        ScVal::I128(_) => "i128",
        ScVal::U256(_) => "u256",
        ScVal::I256(_) => "i256",
        ScVal::Bytes(_) => "bytes",
        ScVal::String(_) => "string",
        ScVal::Symbol(_) => "symbol",
        ScVal::Vec(_) => "vec",
        ScVal::Map(_) => "map",
        ScVal::Address(_) => "address",
        ScVal::ContractInstance(_) => "contract instance",
        ScVal::LedgerKeyContractInstance => "ledger key contract instance",
        ScVal::LedgerKeyNonce(_) => "ledger key nonce",
        ScVal::ExecutableTag(_) => "executable tag",
    }
}
