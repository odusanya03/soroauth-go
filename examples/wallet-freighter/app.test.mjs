// A Node check for the Freighter example's logic.
//
// The example page needs a browser with Freighter installed, so CI cannot
// run it end to end. This check runs everything about it that does not: the
// wallet-error classification, the wrong-network detection, the
// verified-against-the-golden-path gate, and the payload-first flow. It is
// the same shape as examples/browser-passkey/app.test.mjs: a list of named
// checks that fails loudly.
//
// Run from the repository root:
//
//     node examples/wallet-freighter/app.test.mjs

import {
  WalletRejectedError,
  WalletLockedError,
  WrongNetworkError,
  classifyWalletError,
  checkWalletResult,
  signWithFreighter,
} from "./app.js";

let failures = 0;
const check = (condition, description) => {
  if (condition) {
    console.log(`ok   - ${description}`);
  } else {
    failures++;
    console.error(`FAIL - ${description}`);
  }
};

const TESTNET = "Test SDF Network ; September 2015";
const PUBLIC = "Public Global Stellar Network ; September 2015";

// --- error classification -------------------------------------------------

check(classifyWalletError(new Error("User declined access")) instanceof WalletRejectedError,
  "a declined request classifies as rejected");
check(classifyWalletError(new Error("request rejected by user")) instanceof WalletRejectedError,
  "a rejected request classifies as rejected");
check(classifyWalletError(new Error("wallet is locked")) instanceof WalletLockedError,
  "a locked wallet classifies as locked");

let rethrown = null;
try {
  classifyWalletError(new Error("connection reset by peer"));
} catch (err) {
  rethrown = err;
}
check(rethrown && rethrown.message === "connection reset by peer",
  "an unknown wallet failure is rethrown, never misread as a rejection");

// --- result checking -------------------------------------------------------

const verifiedReport = { verified: true, nodes: [{ address: "G...", verdict: "verified" }] };
check(checkWalletResult(verifiedReport, TESTNET, "") === verifiedReport,
  "a verified report passes through");

try {
  checkWalletResult({ verified: false, nodes: [{ address: "G...", verdict: "invalid" }] }, TESTNET, PUBLIC);
  check(false, "an invalid signature for another network throws");
} catch (err) {
  check(err instanceof WrongNetworkError && err.expected === TESTNET && err.actual === PUBLIC,
    "an invalid signature for another network names both passphrases");
}

try {
  checkWalletResult({ verified: false, nodes: [{ address: "G...", verdict: "invalid" }] }, TESTNET, "");
  check(false, "an invalid signature with no claimed network throws");
} catch (err) {
  check(err.code === "INVALID_SIGNATURE" && !(err instanceof WrongNetworkError),
    "an invalid signature with no claimed network is corruption, not wrong-network");
}

// --- the full flow ----------------------------------------------------------

const stubSoroauth = {
  preimage: () => ({ payloadHex: "ab".repeat(32) }),
};
const stubVerify = async () => verifiedReport;

const happyWallet = {
  signAuthEntry: async (entryXdr, opts) => {
    if (opts.networkPassphrase !== TESTNET) throw new Error("stub: unexpected network");
    return { signedAuthEntry: "SIGNED", networkPassphrase: TESTNET };
  },
};
const happy = await signWithFreighter({
  wallet: happyWallet,
  soroauth: stubSoroauth,
  verifyEntry: stubVerify,
  entryXdr: "UNSIGNED",
  validUntilLedger: 1234567,
  networkPassphrase: TESTNET,
  address: "G...",
});
check(happy.signedEntryXdr === "SIGNED" && happy.payloadHex === "ab".repeat(32),
  "the happy path returns the wallet's entry and the local payload");

const rejectingWallet = {
  signAuthEntry: async () => { throw new Error("User declined access"); },
};
try {
  await signWithFreighter({
    wallet: rejectingWallet, soroauth: stubSoroauth, verifyEntry: stubVerify,
    entryXdr: "UNSIGNED", validUntilLedger: 1234567, networkPassphrase: TESTNET, address: "G...",
  });
  check(false, "a wallet rejection throws");
} catch (err) {
  check(err instanceof WalletRejectedError, "a wallet rejection stays a rejection end to end");
}

const lockedWallet = {
  signAuthEntry: async () => { throw new Error("wallet is locked"); },
};
try {
  await signWithFreighter({
    wallet: lockedWallet, soroauth: stubSoroauth, verifyEntry: stubVerify,
    entryXdr: "UNSIGNED", validUntilLedger: 1234567, networkPassphrase: TESTNET, address: "G...",
  });
  check(false, "a locked wallet throws");
} catch (err) {
  check(err instanceof WalletLockedError, "a locked wallet stays locked end to end");
}

const wrongNetworkWallet = {
  signAuthEntry: async () => ({ signedAuthEntry: "SIGNED", networkPassphrase: PUBLIC }),
};
const stubVerifyInvalid = async () => ({ verified: false, nodes: [{ address: "G...", verdict: "invalid" }] });
try {
  await signWithFreighter({
    wallet: wrongNetworkWallet, soroauth: stubSoroauth, verifyEntry: stubVerifyInvalid,
    entryXdr: "UNSIGNED", validUntilLedger: 1234567, networkPassphrase: TESTNET, address: "G...",
  });
  check(false, "a wrong-network signature throws");
} catch (err) {
  check(err instanceof WrongNetworkError && err.actual === PUBLIC,
    "a wrong-network signature is caught, never trusted");
}

try {
  await signWithFreighter({
    wallet: {}, soroauth: stubSoroauth, verifyEntry: stubVerify,
    entryXdr: "UNSIGNED", validUntilLedger: 1234567, networkPassphrase: TESTNET, address: "G...",
  });
  check(false, "a missing extension throws");
} catch (err) {
  check(/no wallet extension/.test(err.message), "a missing extension fails with a named error");
}

if (failures > 0) {
  console.error(`${failures} check(s) failed`);
  process.exit(1);
}
console.log("all Freighter example checks passed");
