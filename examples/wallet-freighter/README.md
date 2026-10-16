# Freighter / Stellar Wallets Kit example

A working example signing a Soroban authorization entry through a real wallet
extension, connecting the two pieces that already exist:
[`adapters/walletsdk`](../../adapters/walletsdk/doc.go) on the Go side and the
[`@soroauth/wasm`](../../wasm/ts/README.md) signing core in the browser.

## The flow end to end

1. The dapp simulates the transaction in **record** mode and takes the unsigned
   authorization entry, exactly as the README's Quickstart does.
2. The page derives the payload **locally** with `soroauth.preimage(...)` from
   `@soroauth/wasm`, so it knows what it is approving. A source-account entry
   has no payload and is dropped from this flow.
3. The page calls the extension's `signAuthEntry` with the entry, the expiration
   ledger, the network passphrase and the target address.
4. The wallet's output is **checked, not assumed**: the signed entry is verified
   (here against the verification service's `/verify`, in Go with
   `walletsdk.SignViaFreighter`) under the expected passphrase before it is
   used.
5. The signed entry goes back through simulation in **enforce** mode, the
   transaction is re-assembled from that pass, and only then submitted. Skipping
   the enforce pass repeats the classic fee error: signing changes what the
   transaction costs.

## The three handled states

Rejection, a locked wallet and a wrong network are distinct, handled states, in
the page and in `SignViaFreighter`:

| State         | Page                  | Go                                             |
| ------------- | --------------------- | ---------------------------------------------- |
| User rejects  | `WalletRejectedError` | `ErrWalletRejected`                            |
| Wallet locked | `WalletLockedError`   | `ErrWalletLocked`                              |
| Wrong network | `WrongNetworkError`   | `ErrWrongNetwork` (`WrongNetworkError` fields) |

A wallet that returns a signature for a different network is caught by the
passphrase check: the signature verifies under the other network's payload and
not under the expected one, so the failure names both passphrases. The wallet is
never trusted to have used the right one. Anything else — an undecodable entry,
a signature that verifies nowhere — is corruption, not one of the three states.

## Running it

```sh
npm test            # the logic check: node app.test.mjs (runs in CI)
./wasm/build.sh     # the signing core the page loads
python3 -m http.server 8000
```

then open `http://localhost:8000/examples/wallet-freighter/` with Freighter
installed, paste the record-mode entry, and sign.

## Which wallet versions were tested

Stated plainly, as the issue requires:

- `app.test.mjs` (`npm test`, runs in CI) drives `app.js` with a stub wallet
  implementing the `@stellar/freighter-api` `signAuthEntry` shape. It proves the
  classification, the wrong-network detection and the verify-before-use gate —
  not an extension.
- The page and the Go adapter are written against `@stellar/freighter-api@4.1.0`
  and Stellar Wallets Kit `1.x`.
- No live extension run happens in CI: there is no browser and no wallet there.
  A live run against testnet with Freighter installed is a manual step; when it
  happens, record the extension version and the transaction hash here.
