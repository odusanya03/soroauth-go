# soroauth (Rust)

A Rust crate exposing the same operations the Go library exposes, for tooling
that already depends on `stellar-xdr` and `soroban-sdk`.

## Native implementation, deliberately

A native Rust implementation and a binding over the C ABI are different projects
with different risks, and this crate is the former, stated here so the choice is
on the record:

- There is no binding layer to audit and no memory-ownership boundary to get
  wrong: XDR, hashing and ed25519 all come from safe dependencies, and the crate
  carries `#![forbid(unsafe_code)]` — there is no `unsafe` outside a justified
  boundary because there is no boundary.
- The parity harness in [`testdata/parity-rust`](../../testdata/parity-rust)
  becomes the correctness gate from the start: it recomputes the vectors with
  the same `stellar-xdr` crate the Soroban host decodes with, and this crate
  decodes with that same crate, so a disagreement names a real divergence rather
  than a binding artifact.

The C ABI issue (`feat(bindings): C shared library and header`, still open) is
therefore not a dependency of this crate; a future C-ABI binding would be a
different crate with its own audit surface.

## Pin policy

`stellar-xdr` is pinned exactly (`=28.0.0`, the release carrying the CAP-71
arms), `Cargo.lock` is committed, tests run with `--locked`, and `build.rs`
bakes the resolved version into the crate so `require_pinned` refuses to run
against anything else. The same exactness covers every other dependency; see
`Cargo.toml`. Never widen a pin to a range: a byte-equality result is only
evidence when it comes from a named build.

## What it proves

```sh
cargo test --locked   # every golden vector, byte for byte
```

`tests/golden.rs` replays every vector in `testdata/vectors/`: the preimage
bytes, the payload hash, and — after replaying every recorded signing step,
including the 20-key multisig vector and the depth-57 delegate chain — the final
signed entry. A run that checks nothing fails. `tests/errors.rs` asserts each
refusal has its own error variant, mirroring the Go sentinels, and that
verification keeps four verdicts with no boolean anywhere.

## What agreement does and does not establish

The framing is [`docs/parity.md`](../../docs/parity.md)'s, inherited whole:
reproducing the reference bytes is strong evidence and it is not an audit. A bug
every offline implementation shares would stay green everywhere; only the host's
verdict closes that gap, and only for the entries actually submitted. Anything
the ledger knows — signer membership, consumed nonces, expiration at submission
time — is not in the bytes being compared.
