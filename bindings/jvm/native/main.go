//go:build ignore

// The minimal native surface the JVM binding loads: a version symbol and a
// SHA-256 passthrough. It is deliberately not the C ABI issue's stable
// surface (that issue is still open): it is exactly enough to prove the
// bundling, the per-platform selection, and the FFM marshalling work, so
// the fuller surface later has a proven loader to stand on.
//
// It is excluded from the normal build with the ignore tag: c-shared needs
// a C toolchain for its target, which the cross-compile matrix does not
// have. Build it explicitly with build.sh in this directory.
package main

import "C"

import (
	"crypto/sha256"
	"encoding/hex"
	"unsafe"
)

// version is the only source of the string SoroauthVersion reports.
const version = "soroauth-jvm-native-0.1.0"

//export SoroauthVersion
func SoroauthVersion() *C.char {
	return C.CString(version)
}

//export SoroauthSha256Hex
func SoroauthSha256Hex(input *C.char, length C.longlong, outHex *C.char, outLen C.longlong) C.longlong {
	if input == nil || outHex == nil || length < 0 || outLen < 65 {
		return -1
	}
	data := unsafe.Slice((*byte)(unsafe.Pointer(input)), int(length))
	sum := sha256.Sum256(data)
	encoded := hex.EncodeToString(sum[:])
	if len(encoded)+1 > int(outLen) {
		return -1
	}
	out := unsafe.Slice((*byte)(unsafe.Pointer(outHex)), int(outLen))
	copy(out, encoded)
	out[len(encoded)] = 0
	return C.longlong(len(encoded))
}

func main() {}
