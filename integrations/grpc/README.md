# soroauth gRPC service

A gRPC surface over the operations the HTTP service already exposes, with a
published protobuf schema.

The schema is [`proto/soroauth.proto`](proto/soroauth.proto). It expresses the
same contract [`remote/protocol.go`](../../remote/protocol.go) defines for
signing and `POST /verify` in [`server/main.go`](../../server/main.go) serves
for verification — the same fields, the same refusal behavior, and in particular
the same honesty boundary: verification reports a `Verdict` per credential node,
and `CANNOT_CHECK` is a distinct value, not a `false`.

## Layout

| Path                  | What it is                                                          |
| --------------------- | ------------------------------------------------------------------- |
| `proto/`              | The schema. This is the source of truth.                            |
| `gen/`                | Code generated from the schema. Never edited by hand.               |
| `server.go`           | The service implementation over one or more `soroauth.Signer`s.     |
| `server_test.go`      | Parity with the HTTP surfaces, the honesty boundary, and deadlines. |
| `generate.sh`         | Regenerates `gen/`; CI runs it and fails if the output differs.     |
| `buf.yaml`            | Lint and breaking-change configuration for the schema.              |
| `buf.gen.yaml`        | Local generation config (pinned `protoc-gen-go` plugins).           |
| `buf.gen.remote.yaml` | Remote generation config (same pins, no local toolchain).           |

This is a separate Go module on purpose: the gRPC runtime is a dependency the
root module must never carry. `go.mod` carries a `replace` back to the
repository root, so the service is tested against the soroauth in this checkout
rather than a published version.

## Running it

```sh
cd integrations/grpc
go test ./...   # parity, honesty boundary, deadlines, schema sync
./generate.sh   # regenerate gen/ after editing proto/soroauth.proto
```

## Authentication

A service that signs needs its authentication story stated, not deferred: this
service has none of its own. Like `remote.Server`, it will sign for anyone who
can reach it, so put bearer-token authentication, rate limiting and TLS in front
of it before exposing it anywhere. The expected shape is a unary interceptor
that reads `authorization` metadata and rejects the call before it reaches the
signer:

```go
func bearerAuth(valid string) grpc.UnaryServerInterceptor {
  return func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
    values := metadata.ValueFromIncomingContext(ctx, "authorization")
    if len(values) != 1 || values[0] != "Bearer "+valid {
      return nil, status.Error(codes.Unauthenticated, "missing or invalid bearer token")
    }
    return handler(ctx, req)
  }
}
```

The token's issuance, rotation and storage belong to the operator, and are
tracked with the service-auth work rather than invented here.

## Deadlines

The caller's context is checked before any work and passed unchanged to the
signer, so a deadline or cancellation aborts an in-flight call. A blocked signer
sees `ctx.Done` rather than signing after the caller gave up; the test proves it
with a signer that blocks until its context ends.

## What the tests prove

- `TestSignMatchesHTTPRemote` replays every golden vector's recorded signing
  steps through gRPC and through the HTTP remote surface with the same keys,
  asserting byte-identical signed entries after every step.
- `TestVerifyMatchesEngine` asserts the gRPC report matches
  `soroauth.VerifyEntry` for every signed golden entry.
- `TestVerifyKeepsCannotCheckDistinct` asserts a non-classic signature shape is
  `CANNOT_CHECK` and a tampered entry is `INVALID` — distinct values, both
  failing closed.
- `TestContextDeadlineReachesSigner` asserts a 50 ms deadline on a blocked
  signer ends in `DEADLINE_EXCEEDED`/`CANCELED` and the signer observes the
  cancellation.
- `TestGeneratedCodeMatchesProto` asserts every message, enum and RPC in the
  schema has its generated counterpart.
