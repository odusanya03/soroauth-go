# Using soroauth from the browser

Passkey signing happens in the browser: the page derives the bytes it is about
to sign — the authorization preimage and its 32-byte payload — instead of
trusting a server to hand over a payload. This page covers installing the
package, loading the WebAssembly module, and a minimal working snippet. It is an
index, not a second reference: the API table, the load options, and the build
instructions live in [`wasm/ts/README.md`](../wasm/ts/README.md) and
[`wasm/README.md`](../wasm/README.md), which are the source of truth. If this
page and those disagree, those win — open an issue saying so.

For the full passkey flow — the browser ceremony, assertion transport, backend
verification, and what is (and is not) proven about it — read
[passkeys](passkeys.md). For a runnable page that does all of this against
testnet, see [the demo](#the-demo).

## Install

```sh
npm install @soroauth/wasm
```

The published tarball ships the compiled `soroauth.wasm` together with the
matching `wasm_exec.js` (`dist/`). Any Go wasm module needs the shim from the
toolchain that built it; do not substitute a different version
(`wasm/ts/README.md`, "About the Go runtime").

To build the core from source instead — for example to check it against this
checkout — run `./wasm/build.sh` (or `make wasm`) from the repository root,
which writes `wasm/dist/soroauth.wasm` and the matching shim. `make wasm-check`
then replays every golden vector through that build and asserts byte-identical
output to the native library, so the browser path is proven against the same
bytes as everything else.

## Load

With a bundler:

```ts
import { loadSoroauth } from "@soroauth/wasm";
// The Go runtime shim ships in the package; import it for its side effect so
// globalThis.Go exists before loading.
import "@soroauth/wasm/wasm_exec.js";
import wasmUrl from "@soroauth/wasm/soroauth.wasm?url"; // Vite-style asset import

const soroauth = await loadSoroauth({
  wasm: wasmUrl,
  go: globalThis.Go,
});
```

With a plain script tag, load `wasm_exec.js` first and import the module from
its URL; [`wasm/ts/README.md`](../wasm/ts/README.md) ("Usage (script tag)") has
the exact tags. `loadSoroauth` also accepts raw bytes instead of a URL, plus
`fetchImpl`, `timeoutMs`, and `globalObject` overrides — all documented there,
not repeated here.

Every failure is a thrown `SoroauthError` carrying the module's own message;
there are no numeric error codes.

## Minimal working snippet

Derive the payload locally, sign it with a passkey, write the signature back
onto the entry. Two entry types have no payload: source-account entries throw
(`SOROBAN_CREDENTIALS_SOURCE_ACCOUNT` is covered by the transaction envelope's
own signature — drop such entries from this flow), and a delegates-arm entry's
payload is bound to the top-level address with `forAddress` naming the node
being signed ([passkeys](passkeys.md#step-0-the-browser-derives-the-payload)).

```ts
// entryBase64Xdr comes from simulateTransaction in record mode, exactly as in
// the README's Quickstart.
const { payloadHex } = soroauth.preimage(
  entryBase64Xdr,
  validUntilLedger,
  networkPassphrase,
);

// The payload is the WebAuthn challenge in this guide's scheme: the browser
// ceremony signs bytes it derived itself, so a server cannot substitute what
// is being approved. See passkeys.md Steps 0-1 for why.
const challenge = Uint8Array.from(
  payloadHex.match(/../g).map((h) => parseInt(h, 16)),
);
const assertion = await navigator.credentials.get({
  publicKey: {
    challenge,
    rpId: window.location.hostname,
    allowCredentials: [{ type: "public-key", id: credentialId }],
    userVerification: "required",
    timeout: 60_000,
  },
});

// The assertion goes to the backend, which verifies it (challenge binding,
// UP/UV flags, ES256 signature) and builds the signature ScVal. The resulting
// ScVal, as base64 XDR, comes back here and is written onto the entry:
const signedEntry = soroauth.writeSignature(
  entryBase64Xdr,
  validUntilLedger,
  networkPassphrase,
  walletAddress, // "" means the entry's own top-level address
  signatureScvalBase64Xdr,
);
```

What this snippet deliberately leaves out, and where it lives:

- **Assertion verification and the ScVal shape** — the backend half — are in
  [passkeys](passkeys.md) (Steps 2–3). The browser never decides whether an
  assertion is valid.
- **Submission** still needs the two-pass simulation flow: re-simulate in
  enforce mode with the signed entries, re-assemble, sign the envelope as the
  fee payer, and submit (README, "The two-pass simulation requirement"). The
  wrapper does not submit transactions or estimate resource fees.
- **`authorizeWithSeed`** (deterministic ed25519 signing from a raw seed) is for
  local tests and demos only — never ship a seed to a browser.

## Signing with Freighter / Stellar Wallets Kit

The passkey flow above is the case where the browser itself is the signer. The
far more common browser case is a user with Freighter installed: the dapp
derives the payload locally with this same package, the wallet signs it, and the
result is verified before use. This connects `adapters/walletsdk` and `wasm/ts`
rather than adding a third piece.

```ts
// The payload is derived locally, exactly as in the passkey snippet.
const { payloadHex } = soroauth.preimage(entryBase64Xdr, validUntilLedger, networkPassphrase);

// The extension signs; the receipt carries what it claims it signed for.
const receipt = await freighterApi.signAuthEntry(entryBase64Xdr, {
  validUntil: validUntilLedger,
  networkPassphrase,
  address,
  payloadHex,
});

// The wallet's output is checked, not assumed: verify the signed entry
// under the expected passphrase (here via the verification service; in Go
// with walletsdk.SignViaFreighter) before running the enforce pass.
const report = await verifyEntry(receipt.signedAuthEntry, networkPassphrase);
if (!report.verified) {
  // Rejection, a locked wallet and a wrong network are distinct, handled
  // states — see the example. A signature for a different network is
  // caught here by the passphrase check, never trusted.
  throw new Error(`wallet result did not verify: ${JSON.stringify(report.nodes)}`);
}
```

[`examples/wallet-freighter`](../examples/wallet-freighter/README.md) is the
working page for this flow, with the three states handled and the enforce pass
still ahead of it. Its `app.test.mjs` checks the classification, the
wrong-network detection and the verify-before-use gate without a browser; its
README states plainly which wallet versions that page was written against and
what a live extension run still has to record. The Go half of the same states is
`walletsdk.SignViaFreighter`, whose tests replay a golden vector through a
wallet stub and assert byte-identical output.

## The demo

[`examples/browser-passkey`](../examples/browser-passkey/README.md) is a
self-contained page that does the whole loop: it builds a native-XLM SAC
`transfer`, simulates in record mode, derives the payload in the browser with
this package, runs the passkey ceremony with the payload as the challenge,
verifies the assertion, writes the signature, re-simulates in enforce mode,
submits to testnet, and prints the hash with an explorer link.

To run it, build the core and serve the repository over localhost (WebAuthn
needs a secure context, and a `file://` page usually cannot fetch the wasm
file):

```sh
./wasm/build.sh            # writes wasm/dist/soroauth.wasm + wasm_exec.js
python3 -m http.server 8000
```

then open `http://localhost:8000/examples/browser-passkey/`. Its README names
what else is required — a passkey wallet contract deployed on testnet and a fee
payer — and its verification status: the page itself cannot run in CI (no
browser, no authenticator), but `app.test.mjs` (`make demo-check`) checks the
flow's SDK calls, credential-arm walk, and signature shape against the same
pinned `@stellar/stellar-sdk@17.1.0` the page loads, and has already caught real
bugs.
