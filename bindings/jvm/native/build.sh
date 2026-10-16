#!/bin/sh
# Builds the minimal native library the JVM binding loads, for the host
# platform, into the resources tree Maven packages. The libraries are build
# output, not committed files (see .gitignore): CI builds one per runner OS
# before running the suite, so the FFM binding is exercised against a fresh
# binary rather than a checked-in one.
set -eu
cd "$(dirname "$0")"
UNAME="$(uname -s)"
ARCH="$(uname -m)"
case "$UNAME" in
Linux) OS=linux; EXT=so ;;
Darwin) OS=macos; EXT=dylib ;;
*) echo "unsupported OS for the native library: $UNAME" >&2; exit 1 ;;
esac
case "$ARCH" in
x86_64 | amd64) CPU=x86_64 ;;
aarch64 | arm64) CPU=aarch64 ;;
*) echo "unsupported architecture for the native library: $ARCH" >&2; exit 1 ;;
esac
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
DEST="../src/main/resources/native/$OS-$CPU"
mkdir -p "$DEST"
go build -buildmode=c-shared -o "$STAGE/libsoroauth.$EXT" main.go
mv "$STAGE/libsoroauth.$EXT" "$DEST/libsoroauth.$EXT"
echo "wrote $DEST/libsoroauth.$EXT"
