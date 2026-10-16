package org.soroauth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

/** The native-library selection mechanism, without any binary present. */
class NativeLoaderTest {
  @org.junit.jupiter.api.Test
  void selectsLinuxAndMacPairs() {
    assertEquals(
        "native/linux-x86_64/libsoroauth.so", NativeLoader.resourcePath("Linux", "amd64"));
    assertEquals(
        "native/linux-aarch64/libsoroauth.so", NativeLoader.resourcePath("Linux", "aarch64"));
    assertEquals(
        "native/macos-x86_64/libsoroauth.dylib", NativeLoader.resourcePath("Mac OS X", "x86_64"));
    assertEquals(
        "native/macos-aarch64/libsoroauth.dylib", NativeLoader.resourcePath("Mac OS X", "aarch64"));
    assertEquals(
        "native/macos-aarch64/libsoroauth.dylib", NativeLoader.resourcePath("Darwin", "arm64"));
  }

  @org.junit.jupiter.api.Test
  void refusesUnknownPlatforms() {
    assertNull(NativeLoader.resourcePath("Windows 11", "amd64"));
    assertNull(NativeLoader.resourcePath("Linux", "riscv64"));
  }
}
