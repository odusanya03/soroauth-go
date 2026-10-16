package walletsdk

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/soroauth/soroauth-go"
)

// fakeFreighterWallet is a FreighterWallet that signs with a local key for
// a chosen passphrase, or fails as told. The passphrase it signs for is the
// wallet's choice, not the dapp's: setting it to anything but the expected
// one is how the tests produce a wrong-network wallet.
type fakeFreighterWallet struct {
	signer         soroauth.Signer
	signPassphrase string
	err            error
}

func (f *fakeFreighterWallet) SignAuthEntry(ctx context.Context, req FreighterSignRequest) (FreighterSignResponse, error) {
	if f.err != nil {
		return FreighterSignResponse{}, f.err
	}
	var entry xdr.SorobanAuthorizationEntry
	if err := xdr.SafeUnmarshalBase64(req.EntryXDR, &entry); err != nil {
		return FreighterSignResponse{}, err
	}
	signed, err := soroauth.AuthorizeEntry(ctx, entry, f.signer,
		req.ValidUntilLedger, f.signPassphrase, soroauth.ForAddress(req.Address))
	if err != nil {
		return FreighterSignResponse{}, err
	}
	encoded, err := xdr.MarshalBase64(signed)
	if err != nil {
		return FreighterSignResponse{}, err
	}
	return FreighterSignResponse{SignedEntryXDR: encoded}, nil
}

// freighterVector reads the one golden vector the wallet tests replay.
// The vectors are owned by testdata/vectors; this reads only the fields
// the golden-path assertion needs.
func freighterVector(t *testing.T) (unsigned, signed, passphrase string, validUntil uint32) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "vectors", "legacy_single_testnet.json"))
	if err != nil {
		t.Fatalf("reading the golden vector: %v", err)
	}
	var v struct {
		NetworkPassphrase string `json:"network_passphrase"`
		ValidUntilLedger  uint32 `json:"valid_until_ledger"`
		UnsignedEntryXDR  string `json:"unsigned_entry_xdr"`
		SignedEntryXDR    string `json:"signed_entry_xdr"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("decoding the golden vector: %v", err)
	}
	return v.UnsignedEntryXDR, v.SignedEntryXDR, v.NetworkPassphrase, v.ValidUntilLedger
}

// TestSignViaFreighterMatchesTheGoldenPath signs the golden unsigned entry
// through the wallet and asserts the bytes equal the recorded signed entry.
// The wallet's output is checked against the golden-vector path, not
// assumed: these are the same bytes the JS reference produced.
func TestSignViaFreighterMatchesTheGoldenPath(t *testing.T) {
	unsignedXDR, wantSignedXDR, passphrase, validUntil := freighterVector(t)

	kp := testKeypair(t, "soroauth-vector-signer-1")
	wallet := &fakeFreighterWallet{
		signer:         soroauth.NewEd25519Signer(kp),
		signPassphrase: passphrase,
	}

	var entry xdr.SorobanAuthorizationEntry
	if err := xdr.SafeUnmarshalBase64(unsignedXDR, &entry); err != nil {
		t.Fatalf("decoding the unsigned entry: %v", err)
	}
	signed, err := SignViaFreighter(context.Background(), wallet, entry, validUntil, passphrase, kp.Address())
	if err != nil {
		t.Fatalf("signing via the wallet: %v", err)
	}
	got, err := signed.MarshalBinary()
	if err != nil {
		t.Fatalf("marshalling the signed entry: %v", err)
	}
	var want xdr.SorobanAuthorizationEntry
	if err := xdr.SafeUnmarshalBase64(wantSignedXDR, &want); err != nil {
		t.Fatalf("decoding the recorded signed entry: %v", err)
	}
	wantBytes, err := want.MarshalBinary()
	if err != nil {
		t.Fatalf("marshalling the recorded entry: %v", err)
	}
	if string(got) != string(wantBytes) {
		t.Error("the wallet's signed entry is not byte-identical to the golden vector's")
	}
}

// TestSignViaFreighterStatesAreDistinct asserts the three handled wallet
// states — rejection, locked wallet, wrong network — are distinct errors,
// so a dapp can answer each with its own UI.
func TestSignViaFreighterStatesAreDistinct(t *testing.T) {
	unsignedXDR, _, passphrase, validUntil := freighterVector(t)

	var entry xdr.SorobanAuthorizationEntry
	if err := xdr.SafeUnmarshalBase64(unsignedXDR, &entry); err != nil {
		t.Fatalf("decoding the unsigned entry: %v", err)
	}
	kp := testKeypair(t, "soroauth-vector-signer-1")

	rejected, err := SignViaFreighter(context.Background(),
		&fakeFreighterWallet{err: ErrWalletRejected}, entry, validUntil, passphrase, kp.Address())
	if !errors.Is(err, ErrWalletRejected) {
		t.Fatalf("rejection error = %v, want ErrWalletRejected", err)
	}
	if errors.Is(err, ErrWalletLocked) || errors.Is(err, ErrWrongNetwork) {
		t.Fatalf("rejection error %v matches another state's sentinel", err)
	}
	_ = rejected

	locked, err := SignViaFreighter(context.Background(),
		&fakeFreighterWallet{err: ErrWalletLocked}, entry, validUntil, passphrase, kp.Address())
	if !errors.Is(err, ErrWalletLocked) {
		t.Fatalf("locked error = %v, want ErrWalletLocked", err)
	}
	if errors.Is(err, ErrWalletRejected) || errors.Is(err, ErrWrongNetwork) {
		t.Fatalf("locked error %v matches another state's sentinel", err)
	}
	_ = locked

	wrongNetwork := &fakeFreighterWallet{
		signer:         soroauth.NewEd25519Signer(kp),
		signPassphrase: "Public Global Stellar Network ; September 2015",
	}
	_, err = SignViaFreighter(context.Background(), wrongNetwork, entry, validUntil, passphrase, kp.Address())
	if !errors.Is(err, ErrWrongNetwork) {
		t.Fatalf("wrong-network error = %v, want ErrWrongNetwork", err)
	}
	if errors.Is(err, ErrWalletRejected) || errors.Is(err, ErrWalletLocked) {
		t.Fatalf("wrong-network error %v matches another state's sentinel", err)
	}
	var detail *WrongNetworkError
	if !errors.As(err, &detail) {
		t.Fatalf("wrong-network error %v carries no passphrases", err)
	}
	if detail.Expected != passphrase {
		t.Errorf("expected passphrase = %q, want %q", detail.Expected, passphrase)
	}
	if detail.Actual != "Public Global Stellar Network ; September 2015" {
		t.Errorf("actual passphrase = %q, want the public network", detail.Actual)
	}
}

// tamperingFreighterWallet signs correctly and then flips a byte in the
// returned signature. The result verifies under no network: it is
// corruption, not a wrong network.
type tamperingFreighterWallet struct {
	inner *fakeFreighterWallet
}

func (w *tamperingFreighterWallet) SignAuthEntry(ctx context.Context, req FreighterSignRequest) (FreighterSignResponse, error) {
	resp, err := w.inner.SignAuthEntry(ctx, req)
	if err != nil {
		return resp, err
	}
	var entry xdr.SorobanAuthorizationEntry
	if err := xdr.SafeUnmarshalBase64(resp.SignedEntryXDR, &entry); err != nil {
		return resp, err
	}
	sig := entry.Credentials.Address.Signature
	vec := *sig.Vec
	m := *(*vec)[0].Map
	for i := range *m {
		if (*m)[i].Key.Sym != nil && string(*(*m)[i].Key.Sym) == "signature" {
			raw := *(*m)[i].Val.Bytes
			raw[0] ^= 0xff
		}
	}
	encoded, err := xdr.MarshalBase64(entry)
	if err != nil {
		return resp, err
	}
	return FreighterSignResponse{SignedEntryXDR: encoded}, nil
}

// TestSignViaFreighterRefusesCorruption asserts a signature that verifies
// under no named network is refused as corruption, not misreported as a
// wrong network.
func TestSignViaFreighterRefusesCorruption(t *testing.T) {
	unsignedXDR, _, passphrase, validUntil := freighterVector(t)

	var entry xdr.SorobanAuthorizationEntry
	if err := xdr.SafeUnmarshalBase64(unsignedXDR, &entry); err != nil {
		t.Fatalf("decoding the unsigned entry: %v", err)
	}
	kp := testKeypair(t, "soroauth-vector-signer-1")

	// Signed correctly, then tampered on the way back: well-formed, but
	// nobody's signature over any network's payload.
	wallet := &tamperingFreighterWallet{inner: &fakeFreighterWallet{
		signer:         soroauth.NewEd25519Signer(kp),
		signPassphrase: passphrase,
	}}
	_, err := SignViaFreighter(context.Background(), wallet, entry, validUntil, passphrase, kp.Address())
	if !errors.Is(err, ErrSignatureNotFound) && !errors.Is(err, ErrSignatureNotByKey) {
		t.Fatalf("corrupt signature error = %v, want a signature refusal", err)
	}
	if errors.Is(err, ErrWrongNetwork) {
		t.Fatalf("corrupt signature error %v misreports a wrong network", err)
	}
}
