//! The correctness gate: every golden vector replayed with byte equality.
//!
//! For each case in `testdata/vectors/` the test asserts the preimage
//! bytes, the payload hash, and — after replaying every recorded signing
//! step — the final signed entry are byte-identical to the reference. A
//! run that checks nothing fails, and no test ever writes to a vector.

use std::fs;
use std::path::PathBuf;

use serde_json::Value;
use stellar_xdr::{Limits, ReadXdr, SorobanAuthorizationEntry, WriteXdr};

use soroauth::{
    authorize, payload, preimage, require_pinned, signing_key_for_label, verify, with_delegates,
    AuthorizeOptions, Delegate, KeySigner,
};

/// One signing step, as recorded by the vector.
struct Step {
    label: String,
    for_address: Option<String>,
    multisig: Option<Vec<String>>,
}

/// One delegate node, as recorded before sorting.
struct RecordedDelegate {
    address: String,
    nested: Vec<RecordedDelegate>,
}

fn delegate(value: &Value) -> RecordedDelegate {
    RecordedDelegate {
        address: value
            .get("address")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        nested: value
            .get("nested")
            .and_then(Value::as_array)
            .map(|nodes| nodes.iter().map(delegate).collect())
            .unwrap_or_default(),
    }
}

fn to_delegates(recorded: &[RecordedDelegate]) -> Vec<Delegate> {
    recorded
        .iter()
        .map(|node| Delegate {
            address: node.address.clone(),
            nested: to_delegates(&node.nested),
        })
        .collect()
}

fn signer_for_step(step: &Step) -> KeySigner {
    match &step.multisig {
        None => KeySigner::from_label(&step.label),
        Some(labels) => {
            let account = KeySigner::from_label(&step.label)
                .address()
                .expect("the multisig account address");
            let keys = labels
                .iter()
                .map(|label| signing_key_for_label(label))
                .collect();
            KeySigner::multisig(&account, keys).expect("building the multisig signer")
        }
    }
}

fn vector_paths() -> Vec<PathBuf> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/vectors");
    let mut paths: Vec<PathBuf> = fs::read_dir(&dir)
        .unwrap_or_else(|error| panic!("reading {}: {error}", dir.display()))
        .map(|entry| entry.expect("reading a vector entry").path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
        .collect();
    paths.sort();
    assert!(
        !paths.is_empty(),
        "no golden vectors found; the gate proved nothing"
    );
    paths
}

#[test]
fn golden_vectors_replay_with_byte_equality() {
    require_pinned().expect("the crate must run against its pinned stellar-xdr");
    let mut checked = 0;
    for path in vector_paths() {
        let text = fs::read_to_string(&path).expect("reading a vector");
        let vector: Value = serde_json::from_str(&text).expect("parsing a vector");
        let name = vector
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or("unnamed")
            .to_string();

        let valid_until_ledger = vector
            .get("valid_until_ledger")
            .and_then(Value::as_u64)
            .unwrap_or_else(|| panic!("{name}: valid_until_ledger is missing"))
            as u32;
        let network_passphrase = vector
            .get("network_passphrase")
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("{name}: network_passphrase is missing"));
        let unsigned_xdr = vector
            .get("unsigned_entry_xdr")
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("{name}: unsigned_entry_xdr is missing"));
        let entry = SorobanAuthorizationEntry::from_xdr_base64(unsigned_xdr, Limits::none())
            .unwrap_or_else(|error| panic!("{name}: decoding the unsigned entry: {error}"));

        // Source-account entries pass through unchanged.
        if entry.credentials == stellar_xdr::SorobanCredentials::SourceAccount {
            let options = AuthorizeOptions::default();
            let signer = KeySigner::from_label("soroauth-vector-signer-1");
            let passed = authorize(
                &entry,
                &signer,
                valid_until_ledger,
                network_passphrase,
                &options,
            )
            .unwrap_or_else(|error| panic!("{name}: passing through: {error}"));
            assert_eq!(
                passed.to_xdr(Limits::none()).expect("encoding"),
                entry.to_xdr(Limits::none()).expect("encoding"),
                "{name}: source-account entry was mutated"
            );
            checked += 1;
            continue;
        }

        // The wrap itself, for vectors that record a pre-wrap entry:
        // rebuild from the recorded unsorted input, proving the sort.
        if let Some(pre_wrap) = vector.get("pre_wrap_entry_xdr").and_then(Value::as_str) {
            if pre_wrap.is_empty() {
                // No wrap recorded for this vector.
            } else {
                let before = SorobanAuthorizationEntry::from_xdr_base64(pre_wrap, Limits::none())
                    .unwrap_or_else(|error| panic!("{name}: decoding the pre-wrap entry: {error}"));
                let recorded: Vec<RecordedDelegate> = vector
                    .get("delegates")
                    .and_then(Value::as_array)
                    .map(|nodes| nodes.iter().map(delegate).collect())
                    .unwrap_or_default();
                let wrapped =
                    with_delegates(&before, valid_until_ledger, to_delegates(&recorded), None)
                        .unwrap_or_else(|error| panic!("{name}: wrapping delegates: {error}"));
                assert_eq!(
                    wrapped.to_xdr(Limits::none()).expect("encoding"),
                    entry.to_xdr(Limits::none()).expect("encoding"),
                    "{name}: rebuilt delegates differ from the reference"
                );
            }
        }

        // The preimage bytes.
        let want_preimage = vector
            .get("preimage_xdr")
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("{name}: preimage_xdr is missing"));
        let built = preimage(&entry, valid_until_ledger, network_passphrase)
            .unwrap_or_else(|error| panic!("{name}: building the preimage: {error}"));
        let got_preimage = built
            .to_xdr_base64(Limits::none())
            .expect("encoding the preimage");
        assert_eq!(got_preimage, want_preimage, "{name}: preimage differs");

        // The payload hash.
        let want_payload = vector
            .get("payload_hex")
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("{name}: payload_hex is missing"));
        let got_payload = payload(&built).expect("hashing the preimage");
        assert_eq!(
            hex::encode(got_payload),
            want_payload,
            "{name}: payload differs"
        );

        // The signed entry, after replaying every recorded step.
        let steps: Vec<Step> = vector
            .get("steps")
            .and_then(Value::as_array)
            .map(|steps| {
                steps
                    .iter()
                    .map(|step| Step {
                        label: step
                            .get("signer_label")
                            .and_then(Value::as_str)
                            .unwrap_or("")
                            .to_string(),
                        for_address: step
                            .get("for_address")
                            .and_then(Value::as_str)
                            .map(str::to_string),
                        multisig: step.get("multisig").and_then(|multisig| {
                            multisig
                                .get("signer_labels")
                                .and_then(Value::as_array)
                                .map(|labels| {
                                    labels
                                        .iter()
                                        .filter_map(Value::as_str)
                                        .map(str::to_string)
                                        .collect()
                                })
                        }),
                    })
                    .collect()
            })
            .unwrap_or_default();
        let mut signed = entry.clone();
        for step in &steps {
            let signer = signer_for_step(step);
            let options = AuthorizeOptions {
                target: step.for_address.clone(),
                allow_resign: false,
            };
            signed = authorize(
                &signed,
                &signer,
                valid_until_ledger,
                network_passphrase,
                &options,
            )
            .unwrap_or_else(|error| panic!("{name}: signing as {}: {error}", step.label));
            // Each step fills its own target: every node naming it must
            // verify now. Nodes for other addresses may legitimately stay
            // unsigned — an unsigned node fails only if the account's
            // policy requires it, which offline code cannot know.
            let target = step
                .for_address
                .clone()
                .unwrap_or_else(|| signer.address().expect("signer address"));
            let report = verify(&signed, network_passphrase)
                .unwrap_or_else(|error| panic!("{name}: verifying after {}: {error}", step.label));
            // The expected verdict follows the Go library's rule exactly:
            // one classic account map verifies; a multisig vector of maps
            // is not the built-in shape and is cannot_check (never a
            // boolean, never verified).
            let expect_cannot_check = step.multisig.is_some();
            let mut filled = 0;
            for node in &report.nodes {
                if node.address == target {
                    let want = if expect_cannot_check {
                        soroauth::Verdict::CannotCheck
                    } else {
                        soroauth::Verdict::Verified
                    };
                    assert_eq!(
                        node.verdict, want,
                        "{name}: target node {} is {:?} after signing",
                        node.address, node.verdict
                    );
                    filled += 1;
                } else {
                    assert!(
                        node.verdict != soroauth::Verdict::Invalid
                            && node.verdict != soroauth::Verdict::CannotCheck,
                        "{name}: node {} is {:?} after signing",
                        node.address,
                        node.verdict
                    );
                }
            }
            assert!(filled > 0, "{name}: step target {target} names no node");
        }
        let want_signed = vector
            .get("signed_entry_xdr")
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("{name}: signed_entry_xdr is missing"));
        let got_signed = signed.to_xdr_base64(Limits::none()).expect("encoding");
        assert_eq!(got_signed, want_signed, "{name}: signed entry differs");
        checked += 1;
    }
    assert!(
        checked > 0,
        "no vectors were checked; the gate proved nothing"
    );
}
