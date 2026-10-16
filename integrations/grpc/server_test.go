package grpc

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/stellar/go-stellar-sdk/keypair"
	"github.com/stellar/go-stellar-sdk/xdr"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	"github.com/soroauth/soroauth-go"
	"github.com/soroauth/soroauth-go/remote"

	soroauthv1 "github.com/soroauth/soroauth-go/integrations/grpc/gen"
)

// vectorStep is one signing call a golden vector records, in order.
type vectorStep struct {
	SignerLabel string  `json:"signer_label"`
	ForAddress  *string `json:"for_address"`
	Multisig    *struct {
		SignerLabels []string `json:"signer_labels"`
	} `json:"multisig,omitempty"`
}

// vector is the subset of a golden vector this package replays. The vectors
// themselves are owned by testdata/vectors and are never edited here; this
// struct reads only the fields the parity assertions need.
type vector struct {
	Name              string       `json:"name"`
	NetworkPassphrase string       `json:"network_passphrase"`
	ValidUntilLedger  uint32       `json:"valid_until_ledger"`
	UnsignedEntryXDR  string       `json:"unsigned_entry_xdr"`
	SignedEntryXDR    string       `json:"signed_entry_xdr"`
	Steps             []vectorStep `json:"steps"`
}

// loadVectors reads every golden vector, failing the test when there are
// none: a parity run that checks nothing must not pass.
func loadVectors(t *testing.T) []vector {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join("..", "..", "testdata", "vectors", "*.json"))
	if err != nil {
		t.Fatalf("globbing the vector directory: %v", err)
	}
	if len(paths) == 0 {
		t.Fatal("no golden vectors found; run this test from the module so ../../testdata/vectors resolves")
	}
	vectors := make([]vector, 0, len(paths))
	for _, path := range paths {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("reading %s: %v", path, err)
		}
		var v vector
		if err := json.Unmarshal(raw, &v); err != nil {
			t.Fatalf("decoding %s: %v", path, err)
		}
		vectors = append(vectors, v)
	}
	return vectors
}

// keypairForLabel derives the key the vector generator derives, so the test
// signs as the vector did.
func keypairForLabel(t *testing.T, label string) *keypair.Full {
	t.Helper()
	kp, err := keypair.FromRawSeed(sha256.Sum256([]byte(label)))
	if err != nil {
		t.Fatalf("deriving the keypair for %q: %v", label, err)
	}
	return kp
}

// signerForStep returns the signer a recorded step calls for: a single
// ed25519 signer, or — for the multisig vector — a classic-account multisig
// signer over the recorded keys.
func signerForStep(t *testing.T, step vectorStep) soroauth.Signer {
	t.Helper()
	if step.Multisig == nil {
		return soroauth.NewEd25519Signer(keypairForLabel(t, step.SignerLabel))
	}
	kps := make([]*keypair.Full, 0, len(step.Multisig.SignerLabels))
	for _, label := range step.Multisig.SignerLabels {
		kps = append(kps, keypairForLabel(t, label))
	}
	signer, err := soroauth.NewAccountMultiSigner(keypairForLabel(t, step.SignerLabel).Address(), kps...)
	if err != nil {
		t.Fatalf("building the multisig signer for %q: %v", step.SignerLabel, err)
	}
	return signer
}

// stepTarget is the credential-node address a step signs for: the recorded
// for_address, or the signer's own address when the vector records none.
func stepTarget(step vectorStep, signer soroauth.Signer) string {
	if step.ForAddress != nil {
		return *step.ForAddress
	}
	return signer.Address()
}

// keySet collects one signer per address over every vector step, so both
// surfaces sign with the same keys.
func keySet(t *testing.T, vectors []vector) map[string]soroauth.Signer {
	t.Helper()
	set := make(map[string]soroauth.Signer)
	for _, v := range vectors {
		for _, step := range v.Steps {
			signer := signerForStep(t, step)
			set[signer.Address()] = signer
		}
	}
	return set
}

// serve starts the gRPC service over an in-memory connection and returns a
// client for it.
func serve(t *testing.T, signers map[string]soroauth.Signer) soroauthv1.SoroauthServiceClient {
	t.Helper()
	list := make([]soroauth.Signer, 0, len(signers))
	for _, signer := range signers {
		list = append(list, signer)
	}
	listener := bufconn.Listen(1 << 20)
	server := grpc.NewServer()
	soroauthv1.RegisterSoroauthServiceServer(server, NewServer(list...))
	go func() {
		_ = server.Serve(listener)
	}()
	t.Cleanup(server.Stop)

	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return listener.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("dialing the test server: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return soroauthv1.NewSoroauthServiceClient(conn)
}

// serveHTTP starts one remote.Server per signer behind a single URL,
// routing by the request's address. It is the HTTP surface the gRPC
// service is asserted against.
func serveHTTP(t *testing.T, signers map[string]soroauth.Signer) string {
	t.Helper()
	servers := make(map[string]*remote.Server, len(signers))
	for address, signer := range signers {
		servers[address] = remote.NewServer(signer)
	}
	mux := http.NewServeMux()
	mux.HandleFunc(remote.Path, func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "reading the request", http.StatusBadRequest)
			return
		}
		var req remote.Request
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, "malformed request", http.StatusBadRequest)
			return
		}
		server, ok := servers[req.Address]
		if !ok {
			http.Error(w, "no key for "+req.Address, http.StatusBadRequest)
			return
		}
		r2 := r.Clone(r.Context())
		r2.Body = io.NopCloser(bytes.NewReader(body))
		r2.ContentLength = int64(len(body))
		server.ServeHTTP(w, r2)
	})
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening on loopback: %v", err)
	}
	go func() {
		_ = http.Serve(listener, mux)
	}()
	return "http://" + listener.Addr().String()
}

// signViaHTTP signs one step through the HTTP surface: the remote signer
// produces the signature over the step's payload, and AuthorizeEntry writes
// it onto the target node.
func signViaHTTP(ctx context.Context, t *testing.T, baseURL string, entry xdr.SorobanAuthorizationEntry,
	signer soroauth.Signer, target string, validUntil uint32, passphrase string) xdr.SorobanAuthorizationEntry {
	t.Helper()
	preimage, err := soroauth.Preimage(entry, validUntil, passphrase)
	if err != nil {
		t.Fatalf("building the preimage: %v", err)
	}
	payload, err := soroauth.Payload(preimage)
	if err != nil {
		t.Fatalf("hashing the preimage: %v", err)
	}
	remoteSigner := remote.NewSigner(baseURL, signer.Address())
	signature, err := remoteSigner.Sign(ctx, preimage, payload)
	if err != nil {
		t.Fatalf("HTTP sign for %s: %v", target, err)
	}
	signed, err := soroauth.AuthorizeEntry(ctx, entry,
		soroauth.SignerFunc(signer.Address(), func(context.Context, xdr.HashIdPreimage, [32]byte) (xdr.ScVal, error) {
			return signature, nil
		}),
		validUntil, passphrase, soroauth.ForAddress(target))
	if err != nil {
		t.Fatalf("writing the HTTP signature for %s: %v", target, err)
	}
	return signed
}

// TestSignMatchesHTTPRemote is the parity gate for signing: the gRPC and
// HTTP surfaces return equivalent results for the same inputs.
//
// Every golden vector's recorded signing steps are replayed once through
// this service and once through the HTTP remote surface holding the same
// keys, and the two signed entries must be byte-identical after every step.
func TestSignMatchesHTTPRemote(t *testing.T) {
	vectors := loadVectors(t)
	signers := keySet(t, vectors)
	grpcClient := serve(t, signers)
	baseURL := serveHTTP(t, signers)

	checked := 0
	for _, v := range vectors {
		if len(v.Steps) == 0 {
			continue
		}
		var grpcEntry, httpEntry xdr.SorobanAuthorizationEntry
		if err := xdr.SafeUnmarshalBase64(v.UnsignedEntryXDR, &grpcEntry); err != nil {
			t.Fatalf("%s: decoding the unsigned entry: %v", v.Name, err)
		}
		httpEntry = grpcEntry

		for i, step := range v.Steps {
			signer := signerForStep(t, step)
			target := stepTarget(step, signer)

			grpcResp, err := grpcClient.Sign(context.Background(), &soroauthv1.SignRequest{
				Entry:            mustMarshalBase64(t, grpcEntry),
				ValidUntilLedger: v.ValidUntilLedger,
				Network:          v.NetworkPassphrase,
				Address:          target,
			})
			if err != nil {
				t.Fatalf("%s step %d: gRPC sign: %v", v.Name, i, err)
			}
			if err := xdr.SafeUnmarshalBase64(grpcResp.SignedEntry, &grpcEntry); err != nil {
				t.Fatalf("%s step %d: decoding the gRPC-signed entry: %v", v.Name, i, err)
			}

			httpEntry = signViaHTTP(context.Background(), t, baseURL, httpEntry,
				signer, target, v.ValidUntilLedger, v.NetworkPassphrase)

			grpcBytes, err := grpcEntry.MarshalBinary()
			if err != nil {
				t.Fatalf("%s step %d: marshalling the gRPC entry: %v", v.Name, i, err)
			}
			httpBytes, err := httpEntry.MarshalBinary()
			if err != nil {
				t.Fatalf("%s step %d: marshalling the HTTP entry: %v", v.Name, i, err)
			}
			if !bytes.Equal(grpcBytes, httpBytes) {
				t.Errorf("%s step %d: gRPC and HTTP signed entries differ", v.Name, i)
			}
		}
		checked++
	}
	if checked == 0 {
		t.Fatal("no vectors were checked; the parity run proved nothing")
	}
	t.Logf("checked %d vectors", checked)
}

// TestVerifyMatchesEngine is the parity gate for verification: the gRPC
// Verify response carries the same report soroauth.VerifyEntry returns for
// the same inputs, for every signed golden entry. When the engine refuses
// an entry, the service must refuse it too rather than report on it.
func TestVerifyMatchesEngine(t *testing.T) {
	vectors := loadVectors(t)
	grpcClient := serve(t, keySet(t, vectors))

	checked := 0
	for _, v := range vectors {
		var entry xdr.SorobanAuthorizationEntry
		if err := xdr.SafeUnmarshalBase64(v.SignedEntryXDR, &entry); err != nil {
			t.Fatalf("%s: decoding the signed entry: %v", v.Name, err)
		}
		want, engineErr := soroauth.VerifyEntry(entry, v.NetworkPassphrase)

		got, err := grpcClient.Verify(context.Background(), &soroauthv1.VerifyRequest{
			Entry:   v.SignedEntryXDR,
			Network: v.NetworkPassphrase,
		})
		if engineErr != nil {
			if err == nil {
				t.Errorf("%s: engine refused the entry (%v) but gRPC reported on it", v.Name, engineErr)
			}
			continue
		}
		if err != nil {
			t.Fatalf("%s: gRPC verify: %v", v.Name, err)
		}

		if got.CredentialType != want.CredentialType || got.Address != want.Address ||
			got.ValidUntilLedger != want.ValidUntilLedger || got.Verified != want.Verified() ||
			got.AddressBound != want.AddressBound || len(got.Nodes) != len(want.Nodes) {
			t.Errorf("%s: gRPC report %+v does not match the engine report %+v", v.Name, got, want)
			continue
		}
		for i, node := range want.Nodes {
			if got.Nodes[i].Address != node.Address || got.Nodes[i].Verdict != verdictToProto(node.Verdict) {
				t.Errorf("%s: node %d: gRPC %+v does not match engine %+v", v.Name, i, got.Nodes[i], node)
			}
		}
		checked++
	}
	if checked == 0 {
		t.Fatal("no vectors were checked; the parity run proved nothing")
	}
	t.Logf("checked %d vectors", checked)
}

// TestVerifyKeepsCannotCheckDistinct proves the schema's honesty boundary:
// a signature that is not the built-in account shape is CANNOT_CHECK, a
// well-formed signature over the wrong bytes is INVALID, and neither reads
// as a boolean false or as each other.
func TestVerifyKeepsCannotCheckDistinct(t *testing.T) {
	kp := keypairForLabel(t, "soroauth-vector-signer-1")
	grpcClient := serve(t, map[string]soroauth.Signer{kp.Address(): soroauth.NewEd25519Signer(kp)})

	var fixture vector
	for _, v := range loadVectors(t) {
		if v.Name == "legacy_single_testnet" {
			fixture = v
		}
	}
	if fixture.Name == "" {
		t.Fatal("legacy_single_testnet vector not found")
	}

	// A custom-account shape: an ScVal the classic decoder cannot read.
	custom, err := decodeEntry(fixture.SignedEntryXDR)
	if err != nil {
		t.Fatalf("decoding the signed entry: %v", err)
	}
	boolean := xdr.ScVal{Type: xdr.ScValTypeScvBool, B: func() *bool { b := true; return &b }()}
	custom.Credentials.Address.Signature = boolean
	customXDR, err := xdr.MarshalBase64(custom)
	if err != nil {
		t.Fatalf("encoding the custom entry: %v", err)
	}
	customResp, err := grpcClient.Verify(context.Background(), &soroauthv1.VerifyRequest{
		Entry:   customXDR,
		Network: fixture.NetworkPassphrase,
	})
	if err != nil {
		t.Fatalf("verifying the custom entry: %v", err)
	}
	if len(customResp.Nodes) != 1 || customResp.Nodes[0].Verdict != soroauthv1.Verdict_CANNOT_CHECK {
		t.Fatalf("custom shape verdicts = %+v, want exactly one CANNOT_CHECK node", customResp.Nodes)
	}
	if customResp.Verified {
		t.Error("custom shape entry reports verified = true; cannot_check must fail closed")
	}

	// A well-formed signature over tampered bytes: moving the expiration
	// the entry carries changes the payload underneath the stored
	// signature.
	tampered, err := decodeEntry(fixture.SignedEntryXDR)
	if err != nil {
		t.Fatalf("decoding the signed entry: %v", err)
	}
	tampered.Credentials.Address.SignatureExpirationLedger = xdr.Uint32(fixture.ValidUntilLedger + 1)
	tamperedXDR, err := xdr.MarshalBase64(tampered)
	if err != nil {
		t.Fatalf("encoding the tampered entry: %v", err)
	}
	tamperedResp, err := grpcClient.Verify(context.Background(), &soroauthv1.VerifyRequest{
		Entry:   tamperedXDR,
		Network: fixture.NetworkPassphrase,
	})
	if err != nil {
		t.Fatalf("verifying the tampered entry: %v", err)
	}
	if len(tamperedResp.Nodes) != 1 || tamperedResp.Nodes[0].Verdict != soroauthv1.Verdict_INVALID {
		t.Fatalf("tampered entry verdicts = %+v, want exactly one INVALID node", tamperedResp.Nodes)
	}
	if tamperedResp.Verified {
		t.Error("tampered entry reports verified = true")
	}
}

// blockingSigner blocks until its context is done, recording whether the
// cancellation reached it.
type blockingSigner struct {
	address string
	reached chan struct{}
}

func (s *blockingSigner) Address() string { return s.address }

func (s *blockingSigner) Sign(ctx context.Context, _ xdr.HashIdPreimage, _ [32]byte) (xdr.ScVal, error) {
	<-ctx.Done()
	close(s.reached)
	return xdr.ScVal{}, ctx.Err()
}

// TestContextDeadlineReachesSigner proves deadlines and cancellation
// propagate to the signer: a call whose deadline expires while the signer
// is blocked fails with DEADLINE_EXCEEDED, and the signer observes the
// cancellation rather than signing afterwards.
func TestContextDeadlineReachesSigner(t *testing.T) {
	kp := keypairForLabel(t, "soroauth-vector-signer-1")
	signer := &blockingSigner{address: kp.Address(), reached: make(chan struct{})}
	grpcClient := serve(t, map[string]soroauth.Signer{kp.Address(): signer})

	var unsigned string
	for _, v := range loadVectors(t) {
		if v.Name == "legacy_single_testnet" {
			unsigned = v.UnsignedEntryXDR
		}
	}
	if unsigned == "" {
		t.Fatal("legacy_single_testnet vector not found")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err := grpcClient.Sign(ctx, &soroauthv1.SignRequest{
		Entry:            unsigned,
		ValidUntilLedger: 1234567,
		Network:          "testnet",
		Address:          kp.Address(),
	})
	if err == nil {
		t.Fatal("blocked sign returned no error; the deadline did not propagate")
	}
	if code := status.Code(err); code != codes.DeadlineExceeded && code != codes.Canceled {
		t.Fatalf("blocked sign status = %v, want DEADLINE_EXCEEDED or CANCELED", code)
	}
	select {
	case <-signer.reached:
	case <-time.After(5 * time.Second):
		t.Fatal("the signer never observed the cancellation")
	}
}

// TestGeneratedCodeMatchesProto is the in-sync check writ small: every
// message, enum and RPC the .proto declares must have its generated
// counterpart in gen/. CI re-runs generate.sh and diffs gen/ as the
// authoritative check; this test fails the build the same way when the two
// were committed out of sync.
func TestGeneratedCodeMatchesProto(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("proto", "soroauth.proto"))
	if err != nil {
		t.Fatalf("reading the schema: %v", err)
	}
	schema := string(raw)

	messageRe := regexp.MustCompile(`(?m)^message (\w+)`)
	enumRe := regexp.MustCompile(`(?m)^enum (\w+)`)
	rpcRe := regexp.MustCompile(`(?m)^\s*rpc (\w+)\(`)

	pb, err := os.ReadFile(filepath.Join("gen", "soroauth.pb.go"))
	if err != nil {
		t.Fatalf("reading the generated messages: %v", err)
	}
	rpc, err := os.ReadFile(filepath.Join("gen", "soroauth_grpc.pb.go"))
	if err != nil {
		t.Fatalf("reading the generated service: %v", err)
	}

	for _, name := range messageRe.FindAllStringSubmatch(schema, -1) {
		if !strings.Contains(string(pb), "type "+name[1]+" struct") {
			t.Errorf("message %s has no generated struct in gen/soroauth.pb.go; run ./generate.sh", name[1])
		}
	}
	for _, name := range enumRe.FindAllStringSubmatch(schema, -1) {
		if !strings.Contains(string(pb), "type "+name[1]+" int32") {
			t.Errorf("enum %s has no generated type in gen/soroauth.pb.go; run ./generate.sh", name[1])
		}
	}
	for _, name := range rpcRe.FindAllStringSubmatch(schema, -1) {
		if !strings.Contains(string(rpc), name[1]+"(context.Context") {
			t.Errorf("rpc %s has no generated method in gen/soroauth_grpc.pb.go; run ./generate.sh", name[1])
		}
	}
	if !bytes.Contains(pb, []byte("DO NOT EDIT")) {
		t.Error("gen/soroauth.pb.go does not look generated; run ./generate.sh and commit its output")
	}
}

// mustMarshalBase64 encodes an entry, failing the test on error.
func mustMarshalBase64(t *testing.T, entry xdr.SorobanAuthorizationEntry) string {
	t.Helper()
	encoded, err := xdr.MarshalBase64(entry)
	if err != nil {
		t.Fatalf("encoding the entry: %v", err)
	}
	return encoded
}
