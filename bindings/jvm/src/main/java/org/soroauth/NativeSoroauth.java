package org.soroauth;

import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.SymbolLookup;
import java.lang.foreign.ValueLayout;
import java.lang.invoke.MethodHandle;

/**
 * The Foreign Function and Memory API binding over the bundled native
 * library. JNI is deliberately not used: FFM is the maintained foreign
 * interface, and it keeps the binding to a linker call with no generated
 * stubs.
 *
 * <p>Minimum version: JDK 22, the first release with FFM final
 * (JEP 454). The {@code maven.compiler.release} floor states it, and CI
 * runs the suite on 22 to prove the minimum rather than only the newest
 * release.
 *
 * <p>Until the C ABI issue lands, the native surface is exactly two
 * symbols — {@code SoroauthVersion} and {@code SoroauthSha256Hex} — which
 * is what proves the bundling and selection work without pretending a
 * reviewed ABI exists yet.
 */
public final class NativeSoroauth implements AutoCloseable {
  private final Arena arena;
  private final MethodHandle version;
  private final MethodHandle sha256Hex;

  private NativeSoroauth(Arena arena, MethodHandle version, MethodHandle sha256Hex) {
    this.arena = arena;
    this.version = version;
    this.sha256Hex = sha256Hex;
  }

  /**
   * Loads the bundled library for this platform and links its symbols.
   * The caller closes the returned binding to release its arena.
   */
  public static NativeSoroauth load() {
    NativeLoader.loadBundled();
    Arena arena = Arena.ofConfined();
    try {
      SymbolLookup lookup =
          SymbolLookup.loaderLookup().or(Linker.nativeLinker().defaultLookup());
      MemorySegment versionAddress =
          lookup.find("SoroauthVersion").orElseThrow(() -> new SoroauthException.MalformedXdr("native symbol SoroauthVersion not found"));
      MemorySegment sha256Address =
          lookup.find("SoroauthSha256Hex").orElseThrow(() -> new SoroauthException.MalformedXdr("native symbol SoroauthSha256Hex not found"));
      MethodHandle version =
          Linker.nativeLinker()
              .downcallHandle(versionAddress, FunctionDescriptor.of(ValueLayout.ADDRESS));
      // Caller-allocated output: the C side writes 64 hex chars plus NUL
      // into outHex and returns their count, so no per-call allocation
      // crosses the boundary to leak.
      MethodHandle sha256Hex =
          Linker.nativeLinker()
              .downcallHandle(
                  sha256Address,
                  FunctionDescriptor.of(
                      ValueLayout.JAVA_LONG,
                      ValueLayout.ADDRESS,
                      ValueLayout.JAVA_LONG,
                      ValueLayout.ADDRESS,
                      ValueLayout.JAVA_LONG));
      return new NativeSoroauth(arena, version, sha256Hex);
    } catch (Throwable e) {
      arena.close();
      throw new SoroauthException.MalformedXdr("linking the native symbols: " + e.getMessage(), e);
    }
  }

  /** The native library's version string. */
  public String version() {
    try {
      MemorySegment address = (MemorySegment) version.invokeExact();
      return address.reinterpret(Long.MAX_VALUE).getString(0);
    } catch (Throwable e) {
      throw new SoroauthException.MalformedXdr("calling SoroauthVersion: " + e.getMessage(), e);
    }
  }

  /**
   * SHA-256 of the given bytes as lowercase hex, computed across the
   * boundary: the round trip proves argument and output-buffer marshalling
   * work, which is everything the fuller future surface will rely on.
   */
  public String sha256Hex(byte[] data) {
    try (Arena call = Arena.ofConfined()) {
      MemorySegment input = call.allocateFrom(ValueLayout.JAVA_BYTE, data);
      MemorySegment output = call.allocate(65);
      long written =
          (long) sha256Hex.invokeExact(input, (long) data.length, output, 65L);
      if (written != 64) {
        throw new SoroauthException.MalformedXdr("SoroauthSha256Hex wrote " + written + " chars");
      }
      return output.getString(0);
    } catch (Throwable e) {
      throw new SoroauthException.MalformedXdr("calling SoroauthSha256Hex: " + e.getMessage(), e);
    }
  }

  @Override
  public void close() {
    arena.close();
  }
}
