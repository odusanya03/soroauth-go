# soroauth-jvm

A JVM library over the soroauth signing core, published to a Maven repository as
`org.soroauth:soroauth-jvm`.

## On the C ABI dependency

This binding's issue notes it depends on the C ABI issue; that issue
(`feat(bindings): C shared library and header`) is still open, so this library
does not wait for it. The signing path here is pure JVM — it installs without a
local Go or Rust toolchain — and the native surface is kept to exactly two
symbols (`SoroauthVersion`, `SoroauthSha256Hex`, in `native/`), which is what
proves the bundling, the per-platform selection, and the FFM marshalling work. A
fuller native surface belongs to the C ABI work, not to this binding.

## Install

```xml
<dependency>
  <groupId>org.soroauth</groupId>
  <artifactId>soroauth-jvm</artifactId>
  <version>0.1.0</version>
</dependency>
```

Minimum version: **JDK 22**, the first release with the Foreign Function and
Memory API final (JEP 454). The FFM binding in this artifact sets the floor;
`maven.compiler.release` states it, and CI runs the suite on 22 to prove the
minimum rather than only the newest release. JNI is deliberately not used: FFM
is the maintained foreign interface, with no generated stubs.

## What it does

```java
// The payload a signer signs.
String payloadHex = Soroauth.payloadHex(preimageBase64Xdr);

// Sign an entry with a 32-byte seed; the signed entry comes back as base64 XDR.
String signed = Soroauth.authorize(unsignedEntryBase64Xdr, seed, validUntilLedger, passphrase, targetAddress);

// Check an entry without submitting it.
VerificationReport report = Soroauth.verify(signedEntryBase64Xdr, passphrase);
for (NodeVerdict node : report.nodes()) {
  System.out.println(node.address() + " " + node.verdict().wireName());
}
```

`verify` returns a report with a `Verdict` per node — `VERIFIED`, `UNSIGNED`,
`INVALID`, `CANNOT_CHECK` — and there is no boolean anywhere a `cannot_check`
could dissolve into. A custom account's signature is whatever its `__check_auth`
accepts, so such a node is `CANNOT_CHECK`, never verified.

## Exceptions

Every failure is a `SoroauthException` with a `kind()`: `REFUSAL` is the library
declining (fail-closed, mirrors a Go sentinel), `FAULT` is something breaking on
the way there. The mapping:

| Go sentinel                   | JVM exception                             | Kind    |
| ----------------------------- | ----------------------------------------- | ------- |
| `ErrSourceAccountCredentials` | `SourceAccount`                           | refusal |
| `ErrUnsupportedCredentials`   | `UnsupportedCredentials`                  | refusal |
| `ErrNoMatchingCredentialNode` | `NoMatchingNode` (carries the address)    | refusal |
| `ErrDuplicateDelegate`        | `DuplicateDelegate` (carries the address) | refusal |
| `ErrSignatureMismatch`        | `SignatureMismatch`                       | refusal |
| `ErrMissingSigner`            | `MissingSigner`                           | refusal |
| `ErrAlreadySigned`            | `AlreadySigned`                           | refusal |
| `ErrInvalidExpiration`        | `InvalidExpiration`                       | refusal |
| `ErrTooManySignatures`        | `TooManySignatures`                       | refusal |
| `ErrDecodeLimit`              | `DecodeLimit`                             | refusal |
| empty passphrase              | `EmptyPassphrase`                         | refusal |
| —                             | `InvalidAddress`, `MalformedXdr`          | fault   |

## Native libraries

Libraries ship inside the jar under `native/<os>-<arch>/` (`libsoroauth.so` on
Linux, `libsoroauth.dylib` on macOS). They are build output, never committed:
`native/build.sh` compiles them with `go build` in `c-shared` mode, and CI
builds one per runner OS before running the suite. `NativeLoader.resourcePath`
is the selection mechanism — pure function of OS and architecture, unit-tested
without any binary present — and `NativeSoroauthTest` links the built library
and asserts its version and a SHA-256 round trip across the boundary.

## What the tests prove

```sh
mvn test                      # pure-JVM suite: golden replay, exceptions, loader selection
native/build.sh && mvn test  # plus the FFM binding against a fresh library
```

`GoldenVectorsTest` replays every vector in `testdata/vectors/` through the JVM
API: the payload hash, and — after replaying every recorded signing step,
including the 20-key multisig vector and the depth-57 delegate chain — the final
signed entry, byte for byte. A run that checks nothing fails.
