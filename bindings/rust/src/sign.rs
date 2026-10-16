//! Signing: key derivation, single and multisig authorization, and the
//! CAP-71-01 delegate tree.
//!
//! Every node signs the same payload, bound to the top-level address, and
//! the expiration signed over and the expiration stored are set from one
//! argument so they can never disagree. Caller input is never mutated:
//! every function returning a modified entry clones first.

use ed25519_dalek::{Signer as _, SigningKey, Verifier as _};
use sha2::{Digest, Sha256};
use stellar_xdr::{
    BytesM, ScAddress, ScBytes, ScMap, ScMapEntry, ScSymbol, ScVal, ScVec,
    SorobanAddressCredentials, SorobanAddressCredentialsWithDelegates, SorobanAuthorizationEntry,
    SorobanCredentials, SorobanDelegateSignature, StringM, VecM,
};

use crate::address::{address_bytes, format_address, parse_address};
use crate::error::Error;
use crate::preimage::{payload, preimage};

/// The host's cap on classic-account signatures: 20
/// (rs-soroban-env
/// soroban-env-host/src/builtin_contracts/account_contract.rs:25).
pub const MAX_ACCOUNT_SIGNATURES: usize = 20;

/// The traversal bound for delegate and invocation walks. Entries from
/// elsewhere are untrusted input, so every recursive walk refuses past 64
/// levels with [`Error::DecodeLimit`].
pub const MAX_DECODE_DEPTH: u32 = 64;

/// A signer: one ed25519 key, or a classic-account multisig set.
///
/// Keys are derived from the same labels the Go tests use — SHA-256 of the
/// label as the seed — so signatures reproduce byte for byte.
#[derive(Debug)]
pub enum KeySigner {
    /// One key, signing for its own address.
    Single(SigningKey),
    /// A classic account with several keys, sorted strictly ascending by
    /// raw public key and capped at [`MAX_ACCOUNT_SIGNATURES`], which is
    /// what the host requires.
    Multisig {
        /// The G… account the signatures belong to.
        account: String,
        /// The signing keys.
        keys: Vec<SigningKey>,
    },
}

impl KeySigner {
    /// Derives a single-key signer from a label, the way the test vectors
    /// derive theirs: SHA-256 of the label as the seed. These keys are
    /// public; never fund them.
    pub fn from_label(label: &str) -> Self {
        KeySigner::Single(signing_key_for_label(label))
    }

    /// The address signatures are written for: the key's own address, or
    /// the multisig account.
    pub fn address(&self) -> Result<String, Error> {
        match self {
            KeySigner::Single(key) => Ok(account_address(key)),
            KeySigner::Multisig { account, .. } => Ok(account.clone()),
        }
    }

    /// Builds the multisig signer, enforcing the host's rules up front:
    /// at least one key, at most [`MAX_ACCOUNT_SIGNATURES`], sorted by raw
    /// public key with duplicates refused.
    pub fn multisig(account: &str, mut keys: Vec<SigningKey>) -> Result<Self, Error> {
        parse_address(account).and_then(|address| match address {
            ScAddress::Account(_) => Ok(()),
            _ => Err(Error::InvalidAddress(account.to_string())),
        })?;
        if keys.is_empty() {
            return Err(Error::MissingSigner {
                address: account.to_string(),
            });
        }
        if keys.len() > MAX_ACCOUNT_SIGNATURES {
            return Err(Error::TooManySignatures);
        }
        keys.sort_by(|a, b| {
            a.verifying_key()
                .as_bytes()
                .cmp(b.verifying_key().as_bytes())
        });
        for pair in keys.windows(2) {
            if pair[0].verifying_key().as_bytes() == pair[1].verifying_key().as_bytes() {
                return Err(Error::MissingSigner {
                    address: account.to_string(),
                });
            }
        }
        Ok(KeySigner::Multisig {
            account: account.to_string(),
            keys,
        })
    }

    /// Signs the payload, verifying the output before returning it: one
    /// verification is cheap compared to a damaged key producing a
    /// signature that is only discovered on-chain, after fees are paid.
    fn sign_payload(&self, payload: &[u8; 32]) -> Result<ScVal, Error> {
        let mut maps = Vec::new();
        match self {
            KeySigner::Single(key) => maps.push(account_signature(key, payload)?),
            KeySigner::Multisig { keys, .. } => {
                for key in keys {
                    maps.push(account_signature(key, payload)?);
                }
            }
        }
        let vec = VecM::try_from(maps).map_err(|error| Error::MalformedXdr(error.to_string()))?;
        Ok(ScVal::Vec(Some(ScVec(vec))))
    }
}

/// Derives the signing key for a label: SHA-256 of the label as the seed.
pub fn signing_key_for_label(label: &str) -> SigningKey {
    let digest = Sha256::digest(label.as_bytes());
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&digest);
    SigningKey::from_bytes(&seed)
}

/// The G… address of a signing key.
fn account_address(key: &SigningKey) -> String {
    stellar_strkey::ed25519::PublicKey(key.verifying_key().to_bytes()).to_string()
}

/// The single `{public_key, signature}` map the host decodes as one
/// `AccountEd25519Signature`, verifying the signature before returning it.
fn account_signature(key: &SigningKey, payload: &[u8; 32]) -> Result<ScVal, Error> {
    let signature = key.sign(payload);
    if key.verifying_key().verify(payload, &signature).is_err() {
        return Err(Error::SignatureMismatch);
    }
    let public_key = key.verifying_key().to_bytes();
    let signature_bytes = signature.to_bytes();
    let public_key_bytes = BytesM::try_from(public_key.to_vec())
        .map_err(|error| Error::MalformedXdr(error.to_string()))?;
    let signature_byte_vec = BytesM::try_from(signature_bytes.to_vec())
        .map_err(|error| Error::MalformedXdr(error.to_string()))?;
    let public_key_symbol = ScSymbol(
        StringM::try_from("public_key").map_err(|error| Error::MalformedXdr(error.to_string()))?,
    );
    let signature_symbol = ScSymbol(
        StringM::try_from("signature").map_err(|error| Error::MalformedXdr(error.to_string()))?,
    );
    // Entries are written in key order — "public_key" before "signature" —
    // because an ScMap is required to be sorted by key.
    let map = ScMap(
        VecM::try_from(vec![
            ScMapEntry {
                key: ScVal::Symbol(public_key_symbol),
                val: ScVal::Bytes(ScBytes(public_key_bytes)),
            },
            ScMapEntry {
                key: ScVal::Symbol(signature_symbol),
                val: ScVal::Bytes(ScBytes(signature_byte_vec)),
            },
        ])
        .map_err(|error| Error::MalformedXdr(error.to_string()))?,
    );
    Ok(ScVal::Map(Some(map)))
}

/// Options for [`authorize`].
#[derive(Default)]
pub struct AuthorizeOptions {
    /// The credential node the signature is written onto. Defaults to the
    /// signer's own address. A signature is only ever written onto a node
    /// whose address equals this target; when nothing matches, the call
    /// fails with [`Error::NoMatchingCredentialNode`] rather than writing
    /// the signature somewhere it does not belong.
    pub target: Option<String>,
    /// Permits writing over a node that already carries a signature.
    /// The delegates-arm expiration guard is never lifted by this.
    pub allow_resign: bool,
}

/// Signs `entry` and returns a signed copy, leaving the input untouched.
///
/// Source-account entries are returned unchanged: the transaction
/// envelope's own signature covers that arm, so there is nothing to sign.
/// `valid_until_ledger` is both signed over and written into the returned
/// entry, so the two can never disagree; zero is refused.
pub fn authorize(
    entry: &SorobanAuthorizationEntry,
    signer: &KeySigner,
    valid_until_ledger: u32,
    network_passphrase: &str,
    options: &AuthorizeOptions,
) -> Result<SorobanAuthorizationEntry, Error> {
    if entry.credentials == SorobanCredentials::SourceAccount {
        return Ok(entry.clone());
    }
    address_credentials(&entry.credentials)?;
    if valid_until_ledger == 0 {
        return Err(Error::InvalidExpiration);
    }

    let default_target = signer.address()?;
    let target = options.target.as_ref().unwrap_or(&default_target);
    if target.is_empty() {
        return Err(Error::MissingSigner {
            address: String::new(),
        });
    }
    let target_address = parse_address(target)?;
    let target_encoded = address_bytes(&target_address)?;

    let mut signed = entry.clone();
    let is_delegates = matches!(
        signed.credentials,
        SorobanCredentials::AddressWithDelegates(_)
    );
    if is_delegates {
        validate_delegate_order(&signed)?;
    }

    let mut matches = Vec::new();
    collect_matching_nodes(&signed, &target_encoded, &mut matches)?;
    if matches.is_empty() {
        return Err(Error::NoMatchingCredentialNode {
            address: target.clone(),
        });
    }

    // In a delegates entry every node commits to one shared payload that
    // includes the expiration (CAP-71-01). Once any node is signed, the
    // expiration is fixed; signing another node at a different expiration
    // would leave the signatures disagreeing. AllowResign never lifts this.
    if is_delegates {
        let stored = stored_expiration(&signed)?;
        if stored != valid_until_ledger && any_node_signed(&signed)? {
            return Err(Error::InvalidExpiration);
        }
    }

    // Checked before signing, so a remote signer is never asked to approve
    // something that is about to be thrown away.
    if !options.allow_resign {
        for signature in &matches {
            if is_signed(signature) {
                return Err(Error::AlreadySigned);
            }
        }
    }

    let built = preimage(&signed, valid_until_ledger, network_passphrase)?;
    let payload_bytes = payload(&built)?;
    let signature = signer.sign_payload(&payload_bytes)?;

    set_stored_expiration(&mut signed, valid_until_ledger)?;
    apply_signature(&mut signed, &target_encoded, &signature)?;
    Ok(signed)
}

/// One delegate of the tree [`with_delegates`] wraps an entry with, in the
/// order the caller passes them: sorting is proven, not assumed.
pub struct Delegate {
    /// The delegate's G… or C… address.
    pub address: String,
    /// Delegates nested under this one.
    pub nested: Vec<Delegate>,
}

/// Wraps an address or V2 entry's credentials in the delegates arm carrying
/// the given tree, returning a new entry.
///
/// Simulation never produces the delegates arm on its own; this assembles
/// the wrapper, and signatures are filled in afterwards with [`authorize`].
/// Each delegates array is sorted by the XDR encoding of the address and
/// checked for duplicates within that level, as CAP-71-01 requires; the
/// same address at two different levels is allowed. An already-signed
/// entry is refused: wrapping changes the payload the old signature was
/// made over.
pub fn with_delegates(
    entry: &SorobanAuthorizationEntry,
    valid_until_ledger: u32,
    delegates: Vec<Delegate>,
    top_signature: Option<ScVal>,
) -> Result<SorobanAuthorizationEntry, Error> {
    let credentials = match &entry.credentials {
        SorobanCredentials::Address(credentials) => credentials.clone(),
        SorobanCredentials::AddressV2(credentials) => credentials.clone(),
        SorobanCredentials::SourceAccount => return Err(Error::UnsupportedCredentials),
        SorobanCredentials::AddressWithDelegates(_) => return Err(Error::UnsupportedCredentials),
    };
    if valid_until_ledger == 0 {
        return Err(Error::InvalidExpiration);
    }
    if is_signed(&credentials.signature) {
        return Err(Error::AlreadySigned);
    }
    let nodes = build_delegate_nodes(delegates, 1)?;
    Ok(SorobanAuthorizationEntry {
        credentials: SorobanCredentials::AddressWithDelegates(
            SorobanAddressCredentialsWithDelegates {
                address_credentials: SorobanAddressCredentials {
                    address: credentials.address,
                    nonce: credentials.nonce,
                    signature_expiration_ledger: valid_until_ledger,
                    signature: top_signature.unwrap_or(ScVal::Void),
                },
                delegates: VecM::try_from(nodes)
                    .map_err(|error| Error::MalformedXdr(error.to_string()))?,
            },
        ),
        root_invocation: entry.root_invocation.clone(),
    })
}

/// Checks that every delegates array of an entry is sorted by the XDR
/// encoding of the address with no duplicates within a level (CAP-71-01).
pub fn validate_delegate_order(entry: &SorobanAuthorizationEntry) -> Result<(), Error> {
    match &entry.credentials {
        SorobanCredentials::AddressWithDelegates(credentials) => {
            check_delegate_level(&credentials.delegates, 1)
        }
        _ => Ok(()),
    }
}

/// Reports whether a credential node's signature field holds a real
/// signature rather than a placeholder.
///
/// Both placeholders occur in practice: CAP-71-01 permits a Void
/// top-level signature when only delegates authenticate, and simulation
/// and the JS reference both use an empty vector as the value to fill in.
pub fn is_signed(value: &ScVal) -> bool {
    match value {
        ScVal::Void => false,
        ScVal::Vec(None) => false,
        ScVal::Vec(Some(vec)) => !vec.is_empty(),
        _ => true,
    }
}

/// The address credentials any address-based arm carries. Source-account
/// and unknown arms are refused with their own errors.
pub(crate) fn address_credentials(
    credentials: &SorobanCredentials,
) -> Result<SorobanAddressCredentials, Error> {
    match credentials {
        SorobanCredentials::SourceAccount => Err(Error::SourceAccountCredentials),
        SorobanCredentials::Address(credentials) => Ok(credentials.clone()),
        SorobanCredentials::AddressV2(credentials) => Ok(credentials.clone()),
        SorobanCredentials::AddressWithDelegates(credentials) => {
            Ok(credentials.address_credentials.clone())
        }
    }
}

/// Builds delegate signature nodes from the caller's tree, sorting each
/// level by the XDR encoding of the address.
fn build_delegate_nodes(
    delegates: Vec<Delegate>,
    depth: u32,
) -> Result<Vec<SorobanDelegateSignature>, Error> {
    check_depth(depth)?;
    let mut keyed: Vec<(Vec<u8>, SorobanDelegateSignature)> = Vec::with_capacity(delegates.len());
    for delegate in delegates {
        let address = parse_address(&delegate.address)?;
        let encoded = address_bytes(&address)?;
        let nested = build_delegate_nodes(delegate.nested, depth + 1)?;
        keyed.push((
            encoded,
            SorobanDelegateSignature {
                address,
                signature: ScVal::Void,
                nested_delegates: VecM::try_from(nested)
                    .map_err(|error| Error::MalformedXdr(error.to_string()))?,
            },
        ));
    }
    keyed.sort_by(|a, b| a.0.cmp(&b.0));
    for pair in keyed.windows(2) {
        if pair[0].0 == pair[1].0 {
            return Err(Error::DuplicateDelegate {
                address: format_address(&pair[1].1.address)?,
            });
        }
    }
    Ok(keyed.into_iter().map(|(_, node)| node).collect())
}

/// Checks one delegates level for order and duplicates.
fn check_delegate_level(
    delegates: &VecM<SorobanDelegateSignature>,
    depth: u32,
) -> Result<(), Error> {
    check_depth(depth)?;
    let mut previous: Option<Vec<u8>> = None;
    for node in delegates.iter() {
        let encoded = address_bytes(&node.address)?;
        if let Some(previous) = previous {
            if previous >= encoded {
                if previous == encoded {
                    return Err(Error::DuplicateDelegate {
                        address: format_address(&node.address)?,
                    });
                }
                return Err(Error::MalformedXdr(
                    "delegates array is not sorted by address".to_string(),
                ));
            }
        }
        previous = Some(encoded);
        check_delegate_level(&node.nested_delegates, depth + 1)?;
    }
    Ok(())
}

/// Refuses a traversal past the decode bound.
fn check_depth(depth: u32) -> Result<(), Error> {
    if depth > MAX_DECODE_DEPTH {
        return Err(Error::DecodeLimit);
    }
    Ok(())
}

/// Collects clones of the signatures on nodes whose address equals the
/// target encoding.
fn collect_matching_nodes(
    entry: &SorobanAuthorizationEntry,
    target: &[u8],
    matches: &mut Vec<ScVal>,
) -> Result<(), Error> {
    let credentials = address_credentials(&entry.credentials)?;
    if address_bytes(&credentials.address)? == target {
        matches.push(credentials.signature.clone());
    }
    if let SorobanCredentials::AddressWithDelegates(with_delegates) = &entry.credentials {
        collect_matching_delegates(&with_delegates.delegates, target, matches, 1)?;
    }
    Ok(())
}

/// Collects matching signatures under one delegates array.
fn collect_matching_delegates(
    delegates: &VecM<SorobanDelegateSignature>,
    target: &[u8],
    matches: &mut Vec<ScVal>,
    depth: u32,
) -> Result<(), Error> {
    check_depth(depth)?;
    for node in delegates.iter() {
        if address_bytes(&node.address)? == target {
            matches.push(node.signature.clone());
        }
        collect_matching_delegates(&node.nested_delegates, target, matches, depth + 1)?;
    }
    Ok(())
}

/// Whether any credential node in the entry already carries a signature.
fn any_node_signed(entry: &SorobanAuthorizationEntry) -> Result<bool, Error> {
    let credentials = address_credentials(&entry.credentials)?;
    if is_signed(&credentials.signature) {
        return Ok(true);
    }
    if let SorobanCredentials::AddressWithDelegates(with_delegates) = &entry.credentials {
        return any_delegate_signed(&with_delegates.delegates, 1);
    }
    Ok(false)
}

/// Whether any delegate under one array already carries a signature.
fn any_delegate_signed(
    delegates: &VecM<SorobanDelegateSignature>,
    depth: u32,
) -> Result<bool, Error> {
    check_depth(depth)?;
    for node in delegates.iter() {
        if is_signed(&node.signature) {
            return Ok(true);
        }
        if any_delegate_signed(&node.nested_delegates, depth + 1)? {
            return Ok(true);
        }
    }
    Ok(false)
}

/// The expiration the entry currently stores.
fn stored_expiration(entry: &SorobanAuthorizationEntry) -> Result<u32, Error> {
    Ok(address_credentials(&entry.credentials)?.signature_expiration_ledger)
}

/// Sets the stored expiration to the value signed over.
fn set_stored_expiration(
    entry: &mut SorobanAuthorizationEntry,
    valid_until_ledger: u32,
) -> Result<(), Error> {
    match &mut entry.credentials {
        SorobanCredentials::Address(credentials) => {
            credentials.signature_expiration_ledger = valid_until_ledger;
        }
        SorobanCredentials::AddressV2(credentials) => {
            credentials.signature_expiration_ledger = valid_until_ledger;
        }
        SorobanCredentials::AddressWithDelegates(credentials) => {
            credentials.address_credentials.signature_expiration_ledger = valid_until_ledger;
        }
        SorobanCredentials::SourceAccount => return Err(Error::SourceAccountCredentials),
    }
    Ok(())
}

/// Writes the signature onto every node whose address equals the target.
fn apply_signature(
    entry: &mut SorobanAuthorizationEntry,
    target: &[u8],
    signature: &ScVal,
) -> Result<(), Error> {
    let matches_top = {
        let credentials = address_credentials(&entry.credentials)?;
        address_bytes(&credentials.address)? == target
    };
    if matches_top {
        match &mut entry.credentials {
            SorobanCredentials::Address(credentials) => credentials.signature = signature.clone(),
            SorobanCredentials::AddressV2(credentials) => {
                credentials.signature = signature.clone();
            }
            SorobanCredentials::AddressWithDelegates(credentials) => {
                credentials.address_credentials.signature = signature.clone();
            }
            SorobanCredentials::SourceAccount => {}
        }
    }
    if let SorobanCredentials::AddressWithDelegates(credentials) = &mut entry.credentials {
        apply_signature_delegates(&mut credentials.delegates, target, signature, 1)?;
    }
    Ok(())
}

/// Writes the signature onto matching delegates under one array.
fn apply_signature_delegates(
    delegates: &mut VecM<SorobanDelegateSignature>,
    target: &[u8],
    signature: &ScVal,
    depth: u32,
) -> Result<(), Error> {
    check_depth(depth)?;
    for node in delegates.iter_mut() {
        if address_bytes(&node.address)? == target {
            node.signature = signature.clone();
        }
        apply_signature_delegates(&mut node.nested_delegates, target, signature, depth + 1)?;
    }
    Ok(())
}
