package walletsdk

import (
	"context"
	"errors"
	"fmt"

	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/soroauth/soroauth-go"
)

var (
	// ErrWalletRejected is returned when the user rejects the signing
	// request in the wallet UI.
	//
	// It is distinct from every other failure on purpose: a rejection is
	// the user saying no, and the dapp answers it with UI (a "try again"
	// button), not with a retry loop or an error report.
	ErrWalletRejected = errors.New("the wallet request was rejected in the wallet")

	// ErrWalletLocked is returned when the wallet is locked and cannot
	// sign until the user unlocks it.
	//
	// It calls for a different user action than a rejection (unlock the
	// wallet, then try again), so it is a different error rather than a
	// message on a shared one.
	ErrWalletLocked = errors.New("the wallet is locked")

	// ErrWrongNetwork is returned when the wallet returns a signature for
	// a different network than the dapp asked for.
	//
	// A wallet that signs with the wrong passphrase produces a signature
	// that the expected network's host will reject on-chain, after fees
	// are paid. This package does not trust the wallet to have used the
	// right one: it verifies the returned entry against the expected
	// passphrase, and when that fails it checks the other named networks
	// before reporting. The wrapped error names both passphrases.
	ErrWrongNetwork = errors.New("the wallet signed for a different network")
)

// WrongNetworkError is returned when the wallet signs for a different
// network than requested, and exposes both passphrases as fields so
// callers can recover them with errors.As instead of parsing the message.
//
// It wraps ErrWrongNetwork, so errors.Is keeps matching the sentinel.
type WrongNetworkError struct {
	// Expected is the passphrase the dapp asked the wallet to sign for.
	Expected string

	// Actual is the passphrase the returned signature verifies under.
	Actual string
}

// Error implements error.
func (e *WrongNetworkError) Error() string {
	return ErrWrongNetwork.Error()
}

// Unwrap returns ErrWrongNetwork so errors.Is keeps working.
func (e *WrongNetworkError) Unwrap() error {
	return ErrWrongNetwork
}

// FreighterSignRequest is what the dapp asks the wallet to sign.
type FreighterSignRequest struct {
	// EntryXDR is the base64 unsigned authorization entry, as simulation
	// returned it in record mode.
	EntryXDR string

	// ValidUntilLedger is the absolute expiration ledger the signature
	// must commit to.
	ValidUntilLedger uint32

	// NetworkPassphrase is the network the dapp wants the signature for.
	NetworkPassphrase string

	// Address is the credential-node address the signature belongs to.
	Address string
}

// FreighterSignResponse is what the wallet hands back.
type FreighterSignResponse struct {
	// SignedEntryXDR is the base64 entry with the wallet's signature on
	// it. It is verified, not trusted; see SignViaFreighter.
	SignedEntryXDR string
}

// FreighterWallet is the wallet-extension side of the Freighter flow, in
// the shape Freighter and Stellar Wallets Kit expose it.
//
// A real extension is connected by a small function that translates this
// interface to the extension's API (see examples/wallet-freighter); tests
// and the example's logic check use a fake. The contract is:
//
//   - a user rejection comes back as an error wrapping ErrWalletRejected;
//   - a locked wallet comes back as an error wrapping ErrWalletLocked;
//   - anything else the wallet reports is returned unwrapped and fails
//     the call.
//
// What the wallet claims about the network is never trusted: the returned
// entry is verified cryptographically before it is handed out.
type FreighterWallet interface {
	// SignAuthEntry asks the wallet to sign the entry described by req
	// and returns the signed entry.
	SignAuthEntry(ctx context.Context, req FreighterSignRequest) (FreighterSignResponse, error)
}

// freighterNetworks are the passphrases a wrong-network signature is
// checked against. The expected network is always tried first, by
// VerifyEntry below; these are the fallbacks that let a failure name the
// network the wallet actually used instead of reporting corruption.
var freighterNetworks = []string{
	"Test SDF Network ; September 2015",
	"Test SDF Future Network ; September 2015",
	"Public Global Stellar Network ; September 2015",
}

// SignViaFreighter signs one authorization entry through a Freighter-style
// wallet and verifies what comes back before handing it out.
//
// The wallet's output is checked, not assumed: the returned entry is run
// through soroauth.VerifyEntry against the expected passphrase, and every
// credential node naming address must verify. A signature that verifies
// under a different named network is refused with a WrongNetworkError
// naming both passphrases — a wallet that signs for the wrong network must
// be caught here, not on-chain after fees. A rejection and a locked wallet
// keep their own sentinels, so the dapp can tell the three states apart.
//
// The caller's entry is not modified. What comes back still has to go
// through the enforce simulation pass before it can be submitted: signing
// changes what the transaction costs, so a transaction assembled from the
// record-mode pass carries too small a resource fee. See Signed.
func SignViaFreighter(
	ctx context.Context,
	wallet FreighterWallet,
	entry xdr.SorobanAuthorizationEntry,
	validUntilLedger uint32,
	networkPassphrase string,
	address string,
) (xdr.SorobanAuthorizationEntry, error) {
	if err := ctx.Err(); err != nil {
		return xdr.SorobanAuthorizationEntry{}, fmt.Errorf("walletsdk: sign via freighter: %w", err)
	}
	if wallet == nil {
		return xdr.SorobanAuthorizationEntry{}, fmt.Errorf("walletsdk: sign via freighter: %w", soroauth.ErrMissingSigner)
	}

	encoded, err := xdr.MarshalBase64(entry)
	if err != nil {
		return xdr.SorobanAuthorizationEntry{}, fmt.Errorf("walletsdk: sign via freighter: encoding the entry: %w", err)
	}

	resp, err := wallet.SignAuthEntry(ctx, FreighterSignRequest{
		EntryXDR:          encoded,
		ValidUntilLedger:  validUntilLedger,
		NetworkPassphrase: networkPassphrase,
		Address:           address,
	})
	if err != nil {
		if errors.Is(err, ErrWalletRejected) {
			return xdr.SorobanAuthorizationEntry{}, fmt.Errorf("walletsdk: sign via freighter: %w", err)
		}
		if errors.Is(err, ErrWalletLocked) {
			return xdr.SorobanAuthorizationEntry{}, fmt.Errorf("walletsdk: sign via freighter: %w", err)
		}
		return xdr.SorobanAuthorizationEntry{}, fmt.Errorf("walletsdk: sign via freighter: the wallet failed: %w", err)
	}

	var signed xdr.SorobanAuthorizationEntry
	if err := xdr.SafeUnmarshalBase64(resp.SignedEntryXDR, &signed); err != nil {
		return xdr.SorobanAuthorizationEntry{}, fmt.Errorf("walletsdk: sign via freighter: the wallet returned an undecodable entry: %w", err)
	}

	report, err := soroauth.VerifyEntry(signed, networkPassphrase)
	if err != nil {
		return xdr.SorobanAuthorizationEntry{}, fmt.Errorf("walletsdk: sign via freighter: verifying the wallet's entry: %w", err)
	}

	nodes := nodesForAddress(report, address)
	if len(nodes) == 0 {
		return xdr.SorobanAuthorizationEntry{}, fmt.Errorf("walletsdk: sign via freighter: %s: %w", address, ErrSignatureNotFound)
	}
	for _, node := range nodes {
		switch node.Verdict {
		case soroauth.VerdictVerified:
		case soroauth.VerdictUnsigned:
			return xdr.SorobanAuthorizationEntry{}, fmt.Errorf("walletsdk: sign via freighter: node %s came back unsigned: %w", node.Address, ErrUnreadableSignature)
		case soroauth.VerdictCannotCheck:
			return xdr.SorobanAuthorizationEntry{}, fmt.Errorf("walletsdk: sign via freighter: node %s is not a classic account signature: %w", node.Address, ErrUnreadableSignature)
		default:
			actual := networkSignedFor(signed, networkPassphrase)
			if actual != "" {
				return xdr.SorobanAuthorizationEntry{}, fmt.Errorf(
					"walletsdk: sign via freighter: want %q, wallet signed for %q: %w",
					networkPassphrase, actual, &WrongNetworkError{Expected: networkPassphrase, Actual: actual})
			}
			return xdr.SorobanAuthorizationEntry{}, fmt.Errorf("walletsdk: sign via freighter: node %s: %w", node.Address, ErrSignatureNotByKey)
		}
	}
	return signed, nil
}

// nodesForAddress returns the verdicts for the credential nodes naming
// address.
func nodesForAddress(report soroauth.VerificationReport, address string) []soroauth.NodeVerdict {
	var out []soroauth.NodeVerdict
	for _, node := range report.Nodes {
		if node.Address == address {
			out = append(out, node)
		}
	}
	return out
}

// networkSignedFor reports the named network the entry's signatures verify
// under, or "" when none of them does. The expected network is skipped by
// the caller having failed already; it is included here anyway so the
// function reads standalone.
func networkSignedFor(entry xdr.SorobanAuthorizationEntry, except string) string {
	for _, candidate := range freighterNetworks {
		if candidate == except {
			continue
		}
		report, err := soroauth.VerifyEntry(entry, candidate)
		if err != nil {
			continue
		}
		if report.Verified() {
			return candidate
		}
	}
	return ""
}
