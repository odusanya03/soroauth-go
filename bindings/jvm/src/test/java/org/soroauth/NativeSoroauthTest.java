package org.soroauth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import org.junit.jupiter.api.Test;

/**
 * The FFM binding over the bundled native library. It runs only when the
 * library was built for this platform (see native/build.sh); otherwise the
 * tests skip and the pure-JVM suite below is what proves the bytes. CI
 * builds the library first, so there the binding is exercised, not skipped.
 */
class NativeSoroauthTest {
  private static NativeSoroauth loadOrSkip() {
    NativeSoroauth binding = null;
    try {
      binding = NativeSoroauth.load();
    } catch (SoroauthException e) {
      assumeTrue(false, "native library not built for this run: " + e.getMessage());
    }
    return binding;
  }

  @Test
  void versionMatches() {
    try (NativeSoroauth binding = loadOrSkip()) {
      assertEquals("soroauth-jvm-native-0.1.0", binding.version());
    }
  }

  @Test
  void sha256RoundTripsAcrossTheBoundary() {
    try (NativeSoroauth binding = loadOrSkip()) {
      byte[] input = "soroauth".getBytes(java.nio.charset.StandardCharsets.UTF_8);
      assertEquals(Soroauth.hex(Soroauth.sha256(input)), binding.sha256Hex(input));
    }
  }
}
