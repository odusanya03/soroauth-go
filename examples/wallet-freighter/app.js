// The Freighter / Stellar Wallets Kit signing flow.
//
// examples/browser-passkey proves the wasm core signs in a browser with a
// passkey. The far more common browser case is a user with Freighter
// installed, and this is that path: the dapp derives the payload locally
// with @soroauth/wasm, the wallet signs it, and this module checks what
// comes back before handing it out.
//
// The wallet is injected rather than imported so the logic is testable
// without an extension: app.test.mjs drives this module with a stub wallet
// whose behavior matches @stellar/freighter-api. index.html wires the real
// one. Nothing here submits a transaction: the signed entry must go back
// through simulation in enforce mode first (see the README).

const NAMED_NETWORKS = {
  "Test SDF Network ; September 2015": "testnet",
  "Test SDF Future Network ; September 2015": "futurenet",
  "Public Global Stellar Network ; September 2015": "public",
};

export class WalletRejectedError extends Error {
  constructor() {
    super("the wallet request was rejected in the wallet");
    this.name = "WalletRejectedError";
    this.code = "WALLET_REJECTED";
  }
}

export class WalletLockedError extends Error {
  constructor() {
    super("the wallet is locked");
    this.name = "WalletLockedError";
    this.code = "WALLET_LOCKED";
  }
}

export class WrongNetworkError extends Error {
  constructor(expected, actual) {
    super(`want ${expected}, wallet signed for ${actual}`);
    this.name = "WrongNetworkError";
    this.code = "WRONG_NETWORK";
    this.expected = expected;
    this.actual = actual;
  }
}

/**
 * Translate a raw extension error into one of the three handled states.
 * Anything unrecognized is rethrown unchanged: an unknown wallet failure
 * must not read as a user rejection.
 */
export function classifyWalletError(err) {
  const message = String((err && err.message) || err || "");
  if (/declined|rejected|denied|user.+cancel|cancelled|canceled/i.test(message)) {
    return new WalletRejectedError();
  }
  if (/locked/i.test(message)) {
    return new WalletLockedError();
  }
  throw err;
}

/**
 * Check the wallet's signed entry against the golden-vector path: the entry
 * must carry a verifiable signature for the expected network. verifyReport
 * is the report the backend (or soroauth verify) produced for the returned
 * entry under the expected passphrase; expectedPassphrase names that
 * network.
 *
 * A wallet that returns a signature for a different network is caught here:
 * when the expected report does not verify, the actual network is read off
 * the wallet's receipt (which network it claims) and reported distinctly
 * rather than trusted. Pass claimedPassphrase as "" when the wallet names
 * none, and the failure stays a generic invalid signature.
 */
export function checkWalletResult(verifyReport, expectedPassphrase, claimedPassphrase) {
  if (verifyReport && verifyReport.verified === true) {
    return verifyReport;
  }
  const nodes = (verifyReport && verifyReport.nodes) || [];
  const invalid = nodes.filter((n) => n.verdict === "invalid");
  if (invalid.length > 0 && claimedPassphrase && claimedPassphrase !== expectedPassphrase) {
    throw new WrongNetworkError(expectedPassphrase, claimedPassphrase);
  }
  const err = new Error("the wallet's signature does not verify over the entry");
  err.code = "INVALID_SIGNATURE";
  err.report = verifyReport;
  throw err;
}

/**
 * Sign one authorization entry through an installed wallet.
 *
 * wallet is the extension API ({ signAuthEntry }), soroauth is the loaded
 * @soroauth/wasm core, and verifyEntry is a function taking the signed
 * entry and returning its verification report under the expected network
 * (in the example page this POSTs to the verification service; in tests it
 * is a stub). The resolved states are: signed (returns the entry),
 * rejected, locked, or wrong-network — each a distinct error.
 *
 * What comes back still needs the enforce simulation pass before it can be
 * submitted; see SignViaFreighter in adapters/walletsdk, which enforces the
 * same states in Go.
 */
export async function signWithFreighter({
  wallet,
  soroauth,
  verifyEntry,
  entryXdr,
  validUntilLedger,
  networkPassphrase,
  address,
}) {
  if (!wallet || typeof wallet.signAuthEntry !== "function") {
    throw new Error("no wallet extension with signAuthEntry is installed");
  }

  // Derive the payload locally so the page knows what it is approving;
  // a source-account entry has no payload and is dropped from this flow.
  let payload;
  try {
    ({ payloadHex: payload } = soroauth.preimage(entryXdr, validUntilLedger, networkPassphrase));
  } catch (err) {
    throw new Error(`deriving the payload: ${err.message}`);
  }

  let signedEntryXdr;
  let claimedNetwork = "";
  try {
    const receipt = await wallet.signAuthEntry(entryXdr, {
      validUntil: validUntilLedger,
      networkPassphrase,
      address,
      payloadHex: payload,
    });
    signedEntryXdr = receipt.signedAuthEntry || receipt.signedEntryXdr || receipt;
    claimedNetwork = receipt.networkPassphrase || "";
    if (typeof signedEntryXdr !== "string") {
      throw new Error("the wallet returned no signed entry");
    }
  } catch (err) {
    if (err && (err.code === "WALLET_REJECTED" || err.code === "WALLET_LOCKED" || err.code === "WRONG_NETWORK")) {
      throw err;
    }
    throw classifyWalletError(err);
  }

  // The wallet's output is checked, not assumed.
  const report = await verifyEntry(signedEntryXdr, networkPassphrase);
  checkWalletResult(report, networkPassphrase, claimedNetwork);
  return { signedEntryXdr, payloadHex: payload };
}
