//! G… and C… addresses: parsing, formatting, and XDR comparison.
//!
//! Addresses are compared by their XDR encoding throughout this crate,
//! exactly as the Go library compares them: the comparison is over the
//! same bytes the protocol orders (CAP-71-01 sorts delegates that way)
//! and the host checks, never over strkey strings.

use stellar_xdr::{AccountId, ContractId, Hash, Limits, PublicKey, ScAddress, Uint256, WriteXdr};

use crate::error::Error;

/// Parses a G… account or C… contract address into its XDR form.
///
/// Only those two appear in authorization entries; anything else is
/// [`Error::InvalidAddress`].
pub fn parse_address(address: &str) -> Result<ScAddress, Error> {
    let strkey = stellar_strkey::Strkey::from_string(address)
        .map_err(|_| Error::InvalidAddress(address.to_string()))?;
    match strkey {
        stellar_strkey::Strkey::PublicKeyEd25519(key) => Ok(ScAddress::Account(AccountId(
            PublicKey::PublicKeyTypeEd25519(Uint256(key.0)),
        ))),
        stellar_strkey::Strkey::Contract(contract) => {
            Ok(ScAddress::Contract(ContractId(Hash(contract.0))))
        }
        _ => Err(Error::InvalidAddress(address.to_string())),
    }
}

/// Formats an XDR address as its G… or C… strkey.
pub fn format_address(address: &ScAddress) -> Result<String, Error> {
    match address {
        ScAddress::Account(AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(raw)))) => {
            Ok(stellar_strkey::ed25519::PublicKey(*raw).to_string())
        }
        ScAddress::Contract(ContractId(Hash(raw))) => {
            Ok(stellar_strkey::Contract(*raw).to_string())
        }
        _ => Err(Error::InvalidAddress(
            "<non-account, non-contract address>".to_string(),
        )),
    }
}

/// The XDR encoding of an address: the comparison key for credential nodes
/// and the sort key for delegate arrays.
pub fn address_bytes(address: &ScAddress) -> Result<Vec<u8>, Error> {
    address
        .to_xdr(Limits::none())
        .map_err(|error| Error::MalformedXdr(error.to_string()))
}
