package org.soroauth;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Locale;

/**
 * Selects and loads the bundled native library for this platform.
 *
 * <p>Libraries ship inside the jar under {@code native/<os>-<arch>/}:
 * {@code libsoroauth.so} on Linux, {@code libsoroauth.dylib} on macOS, one
 * directory per supported pair. The selection is a pure function of the OS
 * name and architecture ({@link #resourcePath}), tested without any binary
 * present; loading extracts the resource to a temporary file and loads it
 * from there, because a library cannot be loaded from inside a jar.
 *
 * <p>The native surface is intentionally tiny until the C ABI issue lands
 * (see the README): version and SHA-256 passthrough, enough to prove the
 * bundling and selection work. The published artifact's signing path is
 * pure JVM and needs no native library at all.
 */
public final class NativeLoader {
  private NativeLoader() {}

  /**
   * The classpath resource for an OS/architecture pair, or null when the
   * pair is not supported. Accepts the {@code os.name} and
   * {@code os.arch} spellings callers actually see.
   */
  public static String resourcePath(String osName, String arch) {
    String os = osName.toLowerCase(Locale.ROOT);
    String cpu = arch.toLowerCase(Locale.ROOT);
    String platform;
    if (os.contains("linux")) {
      platform = "linux";
    } else if (os.contains("mac") || os.contains("darwin")) {
      platform = "macos";
    } else {
      return null;
    }
    String instruction;
    if (cpu.equals("amd64") || cpu.equals("x86_64")) {
      instruction = "x86_64";
    } else if (cpu.equals("aarch64") || cpu.equals("arm64")) {
      instruction = "aarch64";
    } else {
      return null;
    }
    String file = platform.equals("linux") ? "libsoroauth.so" : "libsoroauth.dylib";
    return "native/" + platform + "-" + instruction + "/" + file;
  }

  /** The resource for this JVM's own platform, or null when unsupported. */
  public static String currentResourcePath() {
    return resourcePath(System.getProperty("os.name", ""), System.getProperty("os.arch", ""));
  }

  /**
   * Extracts the current platform's library from the jar and loads it.
   * A missing resource or a load failure is a fault, not a refusal.
   */
  public static void loadBundled() {
    String resource = currentResourcePath();
    if (resource == null) {
      throw new SoroauthException.MalformedXdr(
          "unsupported platform: " + System.getProperty("os.name") + "/" + System.getProperty("os.arch"));
    }
    try (InputStream in = NativeLoader.class.getClassLoader().getResourceAsStream(resource)) {
      if (in == null) {
        throw new SoroauthException.MalformedXdr("bundled library missing from the jar: " + resource);
      }
      Path temp = Files.createTempFile("libsoroauth", resource.endsWith(".so") ? ".so" : ".dylib");
      temp.toFile().deleteOnExit();
      Files.copy(in, temp, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
      System.load(temp.toAbsolutePath().toString());
    } catch (IOException | UnsatisfiedLinkError e) {
      throw new SoroauthException.MalformedXdr("loading the bundled library: " + e.getMessage(), e);
    }
  }
}
