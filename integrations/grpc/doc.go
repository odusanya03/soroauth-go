// Package grpc is a gRPC surface over the operations the HTTP service
// already exposes, with a published protobuf schema.
//
// The schema lives in proto/soroauth.proto and is the machine-readable
// statement of the same contract remote/protocol.go defines for signing and
// server/main.go serves for verification: the .proto expresses that same
// contract, not a looser version. In particular the Verdict enum keeps
// CANNOT_CHECK distinct from a boolean false, so the honesty boundaries of
// verify survive the transport.
//
// This is a separate Go module on purpose: the gRPC runtime is a dependency
// the root module must never carry, so importing soroauth never drags it
// along. Nothing in the root module may depend on this one, and the replace
// in go.mod pins this module to the soroauth in this checkout rather than a
// published version.
//
// A service that signs needs its authentication story stated, not deferred:
// this is a reference with no authentication of its own, the same position
// remote.Server takes. Put bearer-token authentication, rate limiting and
// TLS in front of it before exposing it anywhere; see README.md.
package grpc
