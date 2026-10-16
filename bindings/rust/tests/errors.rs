//! The error distinctions: every refusal a caller can act on has its own
//! variant, and producing each one is asserted here rather than trusted.

use stellar_xdr::{
    InvokeContractArgs, ScAddress, ScSymbol, ScVal, SorobanAddressCredentials,
    SorobanAuthorizationEntry, SorobanAuthorizedFunction, SorobanAuthorizedInvocation,
    SorobanCredentials, StringM, VecM,
};

use soroauth::{
    authorize, parse_address, preimage, signing_key_for_label, verify, with_delegates,
    AuthorizeOptions, Delegate, Error, KeySigner, Verdict,
};

const PASSPHRASE: &str = "Test SDF Network ; September 2015";
const VALID_UNTIL: u32 = 1234567;

fn address(label: &str) -> ScAddress {
    parse_address(
        &stellar_strkey::ed25519::PublicKey(
            signing_key_for_label(label).verifying_key().to_bytes(),
        )
        .to_string(),
    )
    .expect("parsing a test address")
}

fn invocation() -> SorobanAuthorizedInvocation {
    SorobanAuthorizedInvocation {
        function: SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
            contract_address: address("soroauth-rust-contract"),
            function_name: ScSymbol(StringM::try_from("transfer").expect("a short function name")),
            args: VecM::try_from(Vec::new()).expect("an empty argument list"),
        }),
        sub_invocations: VecM::try_from(Vec::new()).expect("no sub-invocations"),
    }
}

fn legacy_entry(label: &str) -> SorobanAuthorizationEntry {
    SorobanAuthorizationEntry {
        credentials: SorobanCredentials::Address(SorobanAddressCredentials {
            address: address(label),
            nonce: 1,
            signature_expiration_ledger: VALID_UNTIL,
            signature: ScVal::Void,
        }),
        root_invocation: invocation(),
    }
}

#[test]
fn refusals_are_distinct() {
    let entry = legacy_entry("soroauth-rust-signer");
    let signer = KeySigner::from_label("soroauth-rust-signer");

    // An empty passphrase hashes to a network that does not exist.
    assert_eq!(
        preimage(&entry, VALID_UNTIL, "").unwrap_err(),
        Error::EmptyPassphrase
    );

    // Source-account entries carry no payload.
    let source = SorobanAuthorizationEntry {
        credentials: SorobanCredentials::SourceAccount,
        root_invocation: invocation(),
    };
    assert_eq!(
        preimage(&source, VALID_UNTIL, PASSPHRASE).unwrap_err(),
        Error::SourceAccountCredentials
    );

    // A target that names no node fails instead of signing elsewhere.
    let elsewhere = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF";
    let options = AuthorizeOptions {
        target: Some(elsewhere.to_string()),
        allow_resign: false,
    };
    let err = authorize(&entry, &signer, VALID_UNTIL, PASSPHRASE, &options).unwrap_err();
    assert_eq!(
        err,
        Error::NoMatchingCredentialNode {
            address: elsewhere.to_string()
        }
    );

    // Zero is already expired, not permissive.
    let options = AuthorizeOptions::default();
    assert_eq!(
        authorize(&entry, &signer, 0, PASSPHRASE, &options).unwrap_err(),
        Error::InvalidExpiration
    );

    // The second signature needs an explicit opt-in.
    let signed = authorize(&entry, &signer, VALID_UNTIL, PASSPHRASE, &options).expect("signing");
    assert_eq!(
        authorize(&signed, &signer, VALID_UNTIL, PASSPHRASE, &options).unwrap_err(),
        Error::AlreadySigned
    );
    let resigned = authorize(
        &signed,
        &signer,
        VALID_UNTIL,
        PASSPHRASE,
        &AuthorizeOptions {
            target: None,
            allow_resign: true,
        },
    )
    .expect("resigning with opt-in");
    assert!(verify(&resigned, PASSPHRASE).expect("verifying").verified());
}

#[test]
fn delegate_rules_are_distinct() {
    let entry = legacy_entry("soroauth-rust-signer");

    // A repeat at one level is refused and names the address.
    let dup = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF";
    let err = with_delegates(
        &entry,
        VALID_UNTIL,
        vec![
            Delegate {
                address: dup.to_string(),
                nested: Vec::new(),
            },
            Delegate {
                address: dup.to_string(),
                nested: Vec::new(),
            },
        ],
        None,
    )
    .unwrap_err();
    match err {
        Error::DuplicateDelegate { address } => assert_eq!(address, dup),
        other => panic!("want DuplicateDelegate, got {other:?}"),
    }

    // Twenty-one keys exceed the host's cap.
    let keys: Vec<_> = (0..21)
        .map(|i| signing_key_for_label(&format!("soroauth-rust-bulk-{i}")))
        .collect();
    assert_eq!(
        KeySigner::multisig(
            "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF",
            keys
        )
        .unwrap_err(),
        Error::TooManySignatures
    );
}

#[test]
fn verify_keeps_four_verdicts() {
    assert_eq!(Verdict::Verified.as_str(), "verified");
    assert_eq!(Verdict::Unsigned.as_str(), "unsigned");
    assert_eq!(Verdict::Invalid.as_str(), "invalid");
    assert_eq!(Verdict::CannotCheck.as_str(), "cannot_check");

    // An unsigned node is reported, not failed.
    let entry = legacy_entry("soroauth-rust-signer");
    let report = verify(&entry, PASSPHRASE).expect("verifying an unsigned entry");
    assert!(!report.verified());
    assert_eq!(report.nodes.len(), 1);
    assert_eq!(report.nodes[0].verdict, Verdict::Unsigned);

    // A non-classic shape cannot be checked, never verified.
    let mut custom = legacy_entry("soroauth-rust-signer");
    if let SorobanCredentials::Address(credentials) = &mut custom.credentials {
        credentials.signature = ScVal::Bool(true);
    }
    let report = verify(&custom, PASSPHRASE).expect("verifying a custom shape");
    assert!(!report.verified());
    assert_eq!(report.nodes[0].verdict, Verdict::CannotCheck);

    // A signature over other bytes is invalid, not unsigned.
    let signer = KeySigner::from_label("soroauth-rust-signer");
    let options = AuthorizeOptions::default();
    let mut signed =
        authorize(&entry, &signer, VALID_UNTIL, PASSPHRASE, &options).expect("signing");
    if let SorobanCredentials::Address(credentials) = &mut signed.credentials {
        credentials.signature_expiration_ledger = VALID_UNTIL + 1;
    }
    let report = verify(&signed, PASSPHRASE).expect("verifying a tampered entry");
    assert!(!report.verified());
    assert_eq!(report.nodes[0].verdict, Verdict::Invalid);

    // The signed entry verifies.
    let signed = authorize(&entry, &signer, VALID_UNTIL, PASSPHRASE, &options).expect("signing");
    let report = verify(&signed, PASSPHRASE).expect("verifying");
    assert!(report.verified());
    assert_eq!(report.nodes[0].verdict, Verdict::Verified);
}
