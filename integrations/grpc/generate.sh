#!/bin/sh
# Regenerate gen/ from proto/soroauth.proto with the pinned plugins.
# CI re-runs this script and fails if gen/ drifts, so the checked-in code
# is always the schema's code and never a hand edit.
#
# The plugin versions are pinned here and in buf.gen.yaml's remote
# references; install them with:
#   GOBIN="$PWD/.tools" go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.6
#   GOBIN="$PWD/.tools" go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.5.1
# then run with .tools on PATH, or let buf fetch its pinned remote plugins.
set -eu
cd "$(dirname "$0")"
if command -v protoc-gen-go >/dev/null 2>&1 && command -v protoc-gen-go-grpc >/dev/null 2>&1; then
  buf generate --template buf.gen.yaml
else
  buf generate --template buf.gen.remote.yaml
fi
