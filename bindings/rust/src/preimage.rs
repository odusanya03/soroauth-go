//! The preimage an entry commits to, and the payload a signer signs.
//!
//! The signer never signs the entry. It signs `SHA-256(XDR(HashIdPreimage))`,
//! and which preimage variant applies is decided by the credentials arm
//! (CAP-46-11 for the legacy arm, CAP-71-01 for V2 and delegates):
//!
//! | Arm | Preimage variant | Address in the signed bytes |
//! | --- | ---------------- | --------------------------- |
//! | source-account | none | n/a |
//! | address (legacy) | `SOROBAN_AUTHORIZATION` (9) | no |
//! | address_v2 | `SOROBAN_AUTHORIZATION_WITH_ADDRESS` (10) | yes |
//! | address_with_delegates | `..._WITH_ADDRESS` (10), bound to the top-level address | yes |

use sha2::{Digest, Sha256};
use stellar_xdr::{
    Hash, HashIdPreimage, HashIdPreimageSorobanAuthorization,
    HashIdPreimageSorobanAuthorizationWithAddress, Limits, ScAddress, SorobanAuthorizationEntry,
    SorobanAuthorizedInvocation, SorobanCredentials, WriteXdr,
};

use crate::error::Error;

/// Builds the [`HashIdPreimage`] a signer must sign to authorize `entry`.
///
/// `valid_until_ledger` is the expiration committed into the payload. It is
/// the parameter, deliberately not whatever the entry currently carries:
/// the caller decides how long the signature lives. The network id is
/// `SHA-256(passphrase)`; an empty passphrase is refused rather than
/// silently producing a signature no network accepts.
///
/// Source-account credentials have no payload and return
/// [`Error::SourceAccountCredentials`]; an unknown arm returns
/// [`Error::UnsupportedCredentials`].
pub fn preimage(
    entry: &SorobanAuthorizationEntry,
    valid_until_ledger: u32,
    network_passphrase: &str,
) -> Result<HashIdPreimage, Error> {
    if network_passphrase.is_empty() {
        return Err(Error::EmptyPassphrase);
    }
    let network_id = Hash(sha256(network_passphrase.as_bytes()));
    let invocation: SorobanAuthorizedInvocation = entry.root_invocation.clone();

    match &entry.credentials {
        SorobanCredentials::SourceAccount => Err(Error::SourceAccountCredentials),
        // ENVELOPE_TYPE_SOROBAN_AUTHORIZATION (9): the address is not in
        // the signed bytes. CAP-46-11.
        SorobanCredentials::Address(credentials) => Ok(HashIdPreimage::SorobanAuthorization(
            HashIdPreimageSorobanAuthorization {
                network_id,
                nonce: credentials.nonce,
                signature_expiration_ledger: valid_until_ledger,
                invocation,
            },
        )),
        // ENVELOPE_TYPE_SOROBAN_AUTHORIZATION_WITH_ADDRESS (10): bound to
        // the top-level address. CAP-71-01.
        SorobanCredentials::AddressV2(credentials) => Ok(with_address(
            network_id,
            credentials.nonce,
            valid_until_ledger,
            credentials.address.clone(),
            invocation,
        )),
        // The delegates arm signs the same address-bound payload as V2,
        // bound to the top-level address: every node signs this one
        // payload. CAP-71-01.
        SorobanCredentials::AddressWithDelegates(credentials) => Ok(with_address(
            network_id,
            credentials.address_credentials.nonce,
            valid_until_ledger,
            credentials.address_credentials.address.clone(),
            invocation,
        )),
    }
}

/// Builds the address-bound preimage variant shared by the V2 and delegates
/// arms.
fn with_address(
    network_id: Hash,
    nonce: i64,
    signature_expiration_ledger: u32,
    address: ScAddress,
    invocation: SorobanAuthorizedInvocation,
) -> HashIdPreimage {
    HashIdPreimage::SorobanAuthorizationWithAddress(HashIdPreimageSorobanAuthorizationWithAddress {
        network_id,
        nonce,
        signature_expiration_ledger,
        address,
        invocation,
    })
}

/// The 32 bytes a signer actually signs: the SHA-256 of the preimage's XDR
/// encoding.
pub fn payload(preimage: &HashIdPreimage) -> Result<[u8; 32], Error> {
    let encoded = preimage
        .to_xdr(Limits::none())
        .map_err(|error| Error::MalformedXdr(error.to_string()))?;
    Ok(sha256(&encoded))
}

/// SHA-256 of `data`.
fn sha256(data: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}
