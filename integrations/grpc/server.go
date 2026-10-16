package grpc

import (
	"context"
	"fmt"

	"github.com/stellar/go-stellar-sdk/network"
	"github.com/stellar/go-stellar-sdk/xdr"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/soroauth/soroauth-go"

	soroauthv1 "github.com/soroauth/soroauth-go/integrations/grpc/gen"
)

// Server implements the SoroauthService over a set of soroauth.Signers.
//
// It speaks the same contract the HTTP surfaces expose: Sign is
// remote/protocol.go's signing protocol (the request carries the address the
// signature belongs to, the response the base64 entry), and Verify answers
// the same question server/main.go's POST /verify answers, in the same
// shape. The proto expresses that contract, not a looser version: in
// particular Verify reports a Verdict per credential node and CANNOT_CHECK
// stays distinct from a boolean false.
//
// Entries are decoded the way the HTTP verification service decodes them,
// with no additional bounds of this package's own, so the two surfaces
// accept and refuse the same inputs.
//
// It is a reference, not a production service: it has no authentication, no
// rate limiting and no TLS of its own. Anyone who can reach it can ask it to
// sign, exactly like remote.Server. Put authentication and transport
// security in front of it before exposing it anywhere; see README.md for
// the bearer-token interceptor pattern this package expects an operator to
// add.
type Server struct {
	soroauthv1.UnimplementedSoroauthServiceServer

	signers map[string]soroauth.Signer
}

// NewServer returns a Server that signs with signers.
//
// A service generally holds more than one key, so Sign answers for the
// address the request names by looking it up in this set. A request for an
// address no signer holds is refused, the same fail-closed reading
// soroauth gives a signature with nowhere to go.
func NewServer(signers ...soroauth.Signer) *Server {
	set := make(map[string]soroauth.Signer, len(signers))
	for _, signer := range signers {
		if signer == nil {
			continue
		}
		set[signer.Address()] = signer
	}
	return &Server{signers: set}
}

// Sign signs one authorization entry.
//
// The caller's context is checked before any work and passed unchanged to
// the signer, so deadlines and cancellation propagate: a cancelled call
// fails with CANCELLED or DEADLINE_EXCEEDED and never produces a signature
// afterwards.
func (s *Server) Sign(ctx context.Context, req *soroauthv1.SignRequest) (*soroauthv1.SignResponse, error) {
	if err := ctx.Err(); err != nil {
		return nil, status.Error(codes.Canceled, err.Error())
	}
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}
	if len(s.signers) == 0 {
		return nil, status.Error(codes.FailedPrecondition, "server has no signer")
	}
	passphrase, err := resolveNetwork(req.Network)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "network: %v", err)
	}

	entry, err := decodeEntry(req.Entry)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "decoding entry: %v", err)
	}

	target := req.Address
	if target == "" {
		if len(s.signers) != 1 {
			return nil, status.Error(codes.InvalidArgument, "address is required: the server holds more than one key")
		}
		for address := range s.signers {
			target = address
		}
	}
	signer, ok := s.signers[target]
	if !ok {
		return nil, status.Errorf(codes.InvalidArgument, "this server holds no key for %q", target)
	}

	signed, err := soroauth.AuthorizeEntry(ctx, entry, signer, req.ValidUntilLedger, passphrase, soroauth.ForAddress(target))
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "signing entry: %v", err)
	}

	encoded, err := xdr.MarshalBase64(signed)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "encoding the signed entry: %v", err)
	}
	return &soroauthv1.SignResponse{SignedEntry: encoded}, nil
}

// Verify checks an entry's signatures without submitting anything.
//
// The payload is rebuilt from the entry as it stands, through
// soroauth.VerifyEntry, so the report says what the entry commits to, not
// what the caller hoped. A completed verification is returned whatever the
// verdicts say — an INVALID node is the answer, not a transport failure —
// and only a request the service cannot verify is an error.
func (s *Server) Verify(ctx context.Context, req *soroauthv1.VerifyRequest) (*soroauthv1.VerifyResponse, error) {
	if err := ctx.Err(); err != nil {
		return nil, status.Error(codes.Canceled, err.Error())
	}
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}
	passphrase, err := resolveNetwork(req.Network)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "network: %v", err)
	}

	entry, err := decodeEntry(req.Entry)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "decoding entry: %v", err)
	}

	report, err := soroauth.VerifyEntryContext(ctx, entry, passphrase)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "verification failed: %v", err)
	}
	if req.ValidUntilLedger != 0 && report.ValidUntilLedger != req.ValidUntilLedger {
		return nil, status.Errorf(codes.InvalidArgument,
			"entry carries expiration %d, but valid_until_ledger says %d",
			report.ValidUntilLedger, req.ValidUntilLedger)
	}

	return reportToProto(report), nil
}

// reportToProto renders a VerificationReport in the proto's shape.
//
// The mapping is total over the four verdicts: VERIFIED, UNSIGNED, INVALID
// and CANNOT_CHECK each have their own enum value, so the honesty boundary
// survives the transport and no caller can read a cannot-check node as a
// boolean false.
func reportToProto(report soroauth.VerificationReport) *soroauthv1.VerifyResponse {
	out := &soroauthv1.VerifyResponse{
		CredentialType:   report.CredentialType,
		AddressBound:     report.AddressBound,
		Address:          report.Address,
		ValidUntilLedger: report.ValidUntilLedger,
		Verified:         report.Verified(),
		Note:             report.Note,
		Nodes:            make([]*soroauthv1.NodeVerdict, 0, len(report.Nodes)),
	}
	for _, node := range report.Nodes {
		out.Nodes = append(out.Nodes, &soroauthv1.NodeVerdict{
			Address: node.Address,
			Verdict: verdictToProto(node.Verdict),
			Reason:  node.Reason,
		})
	}
	return out
}

// verdictToProto maps one VerifyVerdict to its proto enum value.
func verdictToProto(verdict soroauth.VerifyVerdict) soroauthv1.Verdict {
	switch verdict {
	case soroauth.VerdictVerified:
		return soroauthv1.Verdict_VERIFIED
	case soroauth.VerdictUnsigned:
		return soroauthv1.Verdict_UNSIGNED
	case soroauth.VerdictInvalid:
		return soroauthv1.Verdict_INVALID
	case soroauth.VerdictCannotCheck:
		return soroauthv1.Verdict_CANNOT_CHECK
	default:
		return soroauthv1.Verdict_VERDICT_UNSPECIFIED
	}
}

// decodeEntry reads a base64 authorization entry the way the HTTP
// verification service reads one: a plain XDR unmarshal with no bounds of
// this package's own, so the gRPC and HTTP surfaces accept and refuse the
// same inputs. Bounds still apply downstream — soroauth.VerifyEntry and
// soroauth.AuthorizeEntry enforce their own — exactly as they do for HTTP.
func decodeEntry(encoded string) (xdr.SorobanAuthorizationEntry, error) {
	var entry xdr.SorobanAuthorizationEntry
	if err := xdr.SafeUnmarshalBase64(encoded, &entry); err != nil {
		return xdr.SorobanAuthorizationEntry{}, err
	}
	return entry, nil
}

// resolveNetwork turns the network field into a passphrase.
//
// It accepts the same three named shorthands the HTTP verification service
// accepts, and otherwise reads the value as a literal passphrase.
func resolveNetwork(value string) (string, error) {
	switch value {
	case "":
		return "", fmt.Errorf("network is required (testnet, futurenet, public, or a literal passphrase)")
	case "testnet":
		return network.TestNetworkPassphrase, nil
	case "futurenet":
		return network.FutureNetworkPassphrase, nil
	case "public":
		return network.PublicNetworkPassphrase, nil
	default:
		return value, nil
	}
}
