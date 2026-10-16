package org.soroauth;

import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Comparator;
import java.util.List;

/**
 * The JVM entry point: preimage, payload, authorization and verification
 * with the same bytes and the same honesty boundaries as the Go library,
 * in pure JVM code that installs without a local Go or Rust toolchain.
 *
 * <p>The signer never signs the entry. It signs {@code SHA-256(XDR(HashIdPreimage))},
 * and which preimage variant applies is decided by the credentials arm
 * (CAP-46-11 for legacy, CAP-71-01 for V2 and delegates). Verification
 * reports a {@link Verdict} per node — verified, unsigned, invalid,
 * cannot_check — and there is no boolean anywhere a {@code cannot_check}
 * could dissolve into.
 */
public final class Soroauth {
  /** The host's cap on classic-account signatures (20). */
  public static final int MAX_ACCOUNT_SIGNATURES = 20;

  private Soroauth() {}

  /**
   * The 32-byte payload a signer signs: the SHA-256 of a preimage's XDR encoding.
   *
   * @param preimageB64 base64 XDR HashIdPreimage
   */
  public static byte[] payload(String preimageB64) {
    return sha256(decodeBase64(preimageB64, "preimage"));
  }

  /** {@link #payload(String)} as lowercase hex. */
  public static String payloadHex(String preimageB64) {
    return hex(payload(preimageB64));
  }

  /**
   * The G... address of a 32-byte ed25519 seed.
   *
   * @param seed 32 raw seed bytes
   */
  public static String addressOfSeed(byte[] seed) {
    requireSeed(seed);
    return Strkey.encode(Strkey.VERSION_ACCOUNT, Ed25519.publicKey(seed));
  }

  /**
   * Signs an entry and returns a signed copy as base64 XDR, leaving the
   * input untouched. Source-account entries are returned unchanged: the
   * transaction envelope's own signature covers that arm.
   *
   * @param entryB64 base64 unsigned entry, as simulation returned it
   * @param seed 32 raw seed bytes of the signing key
   * @param validUntilLedger the absolute expiration ledger, signed over and stored
   * @param networkPassphrase the network to sign for; must not be empty
   * @param target the credential node the signature belongs to; null or empty means the signer's own address
   */
  public static String authorize(
      String entryB64, byte[] seed, long validUntilLedger, String networkPassphrase, String target) {
    requireSeed(seed);
    return authorizeSeeds(
        entryB64, List.of(seed), null, validUntilLedger, networkPassphrase, target, false, null);
  }

  /**
   * {@link #authorize(String, byte[], long, String, String)} with resign
   * control. An empty scope lifts the guard for whatever address the call
   * targets; naming addresses restricts it to those, and a target outside
   * the list still refuses. The delegates-arm expiration guard is never
   * lifted.
   */
  public static String authorizeAllowResign(
      String entryB64,
      byte[] seed,
      long validUntilLedger,
      String networkPassphrase,
      String target,
      List<String> scope) {
    requireSeed(seed);
    return authorizeSeeds(
        entryB64, List.of(seed), null, validUntilLedger, networkPassphrase, target, false, scope);
  }

  /**
   * Signs an entry with a classic-account multisig set: the keys are sorted
   * strictly ascending by raw public key and capped at {@link #MAX_ACCOUNT_SIGNATURES},
   * which is what the host requires.
   *
   * @param entryB64 base64 unsigned entry
   * @param seeds one 32-byte seed per signing key
   * @param account the G... account the signatures belong to
   */
  public static String authorizeMultisig(
      String entryB64,
      List<byte[]> seeds,
      String account,
      long validUntilLedger,
      String networkPassphrase,
      String target) {
    if (seeds == null || seeds.isEmpty()) {
      throw new SoroauthException.MissingSigner(account == null ? "" : account);
    }
    if (seeds.size() > MAX_ACCOUNT_SIGNATURES) {
      throw new SoroauthException.TooManySignatures(seeds.size());
    }
    for (byte[] seed : seeds) {
      requireSeed(seed);
    }
    return authorizeSeeds(
        entryB64, seeds, account, validUntilLedger, networkPassphrase, target, true, null);
  }

  /**
   * Wraps an address or V2 entry's credentials in the delegates arm carrying
   * the given tree. Each delegates array is sorted by the XDR encoding of
   * the address and checked for duplicates within that level, as CAP-71-01
   * requires. An already-signed entry is refused: wrapping changes the
   * payload the old signature was made over.
   */
  public static String withDelegates(String entryB64, long validUntilLedger, List<Delegate> delegates) {
    checkExpiration(validUntilLedger);
    Xdr.Entry entry = Xdr.parseEntry(decodeBase64(entryB64, "entry"));
    if (entry.arm != Xdr.ARM_ADDRESS && entry.arm != Xdr.ARM_ADDRESS_V2) {
      throw new SoroauthException.UnsupportedCredentials();
    }
    Xdr.Node top = entry.nodes.get(0);
    if (Xdr.isSigned(entry.raw, top)) {
      throw new SoroauthException.AlreadySigned();
    }
    List<Xdr.DelegateSpec> specs = toSpecs(delegates, 1);
    java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
    Xdr.putU32(out, Xdr.ARM_WITH_DELEGATES);
    out.write(entry.addressXdr, 0, entry.addressXdr.length);
    Xdr.putI64(out, entry.nonce);
    Xdr.putU32(out, validUntilLedger);
    Xdr.putU32(out, 1); // ScvVoid top-level signature
    writeDelegates(out, specs);
    byte[] invocation = entry.invocationBytes();
    out.write(invocation, 0, invocation.length);
    return Base64.getEncoder().encodeToString(out.toByteArray());
  }

  /**
   * Checks an entry's signatures against the payload the entry itself
   * commits to, without submitting anything. Only classic account
   * signatures can be decided offline; any other shape is
   * {@link Verdict#CANNOT_CHECK}, never verified.
   */
  public static VerificationReport verify(String entryB64, String networkPassphrase) {
    if (networkPassphrase == null || networkPassphrase.isEmpty()) {
      throw new SoroauthException.EmptyPassphrase();
    }
    byte[] raw = decodeBase64(entryB64, "entry");
    Xdr.Entry entry = Xdr.parseEntry(raw);
    if (entry.arm == Xdr.ARM_SOURCE_ACCOUNT) {
      return new VerificationReport(
          "source_account",
          false,
          "",
          0,
          List.of(),
          "source-account credentials carry no signature payload of their own; the transaction envelope's signature covers them, so there is nothing here to verify");
    }
    byte[] networkId = sha256(networkPassphrase.getBytes(java.nio.charset.StandardCharsets.UTF_8));
    byte[] preimage = Xdr.preimageBytes(entry, entry.expiration, networkId);
    byte[] payload = sha256(preimage);
    List<NodeVerdict> nodes = new ArrayList<>();
    for (Xdr.Node node : entry.nodes) {
      nodes.add(verifyNode(raw, node, payload));
    }
    return new VerificationReport(
        credentialType(entry.arm),
        entry.arm != Xdr.ARM_ADDRESS,
        entry.address,
        entry.expiration,
        nodes,
        "");
  }

  // -- internals ----------------------------------------------------------

  private static NodeVerdict verifyNode(byte[] raw, Xdr.Node node, byte[] payload) {
    if (!Xdr.isSigned(raw, node)) {
      return new NodeVerdict(node.address, Verdict.UNSIGNED, "the node carries no signature (Void or an empty vector)");
    }
    boolean account = node.addressXdr.length == 40 && (node.addressXdr[3] & 0xff) == 0;
    if (!account) {
      return new NodeVerdict(
          node.address,
          Verdict.CANNOT_CHECK,
          "the node addresses a C... contract; only the contract's __check_auth defines whether its signature is valid, so this cannot be checked offline");
    }
    Xdr.SigResult sig = Xdr.parseClassicSig(raw, node);
    if (sig.publicKey == null) {
      return new NodeVerdict(
          node.address,
          Verdict.CANNOT_CHECK,
          "the signature is not the built-in {public_key, signature} account shape; only the account's own logic defines its validity, so this cannot be checked offline ("
              + sig.cannotCheckReason
              + ")");
    }
    if (verifyEd25519(sig.publicKey, payload, sig.signature)) {
      return new NodeVerdict(node.address, Verdict.VERIFIED, "");
    }
    return new NodeVerdict(
        node.address, Verdict.INVALID, "the stored signature does not verify over the payload the entry commits to");
  }

  private static String credentialType(int arm) {
    switch (arm) {
      case Xdr.ARM_ADDRESS:
        return "address";
      case Xdr.ARM_ADDRESS_V2:
        return "address_v2";
      case Xdr.ARM_WITH_DELEGATES:
        return "address_with_delegates";
      default:
        return "unknown";
    }
  }

  private static String authorizeSeeds(
      String entryB64,
      List<byte[]> seeds,
      String multisigAccount,
      long validUntilLedger,
      String networkPassphrase,
      String target,
      boolean multisig,
      List<String> resignScope) {
    checkExpiration(validUntilLedger);
    if (networkPassphrase == null || networkPassphrase.isEmpty()) {
      throw new SoroauthException.EmptyPassphrase();
    }
    byte[] raw = decodeBase64(entryB64, "entry");
    Xdr.Entry entry = Xdr.parseEntry(raw);
    if (entry.arm == Xdr.ARM_SOURCE_ACCOUNT) {
      return entryB64;
    }

    String signerAddress =
        multisig ? requireAccount(multisigAccount) : addressOfSeed(seeds.get(0));
    String resolved = (target == null || target.isEmpty()) ? signerAddress : target;
    byte[] targetXdr = Xdr.encodeAddress(resolved);

    List<Xdr.Node> matches = new ArrayList<>();
    for (Xdr.Node node : entry.nodes) {
      if (Arrays.equals(node.addressXdr, targetXdr)) {
        matches.add(node);
      }
    }
    if (matches.isEmpty()) {
      throw new SoroauthException.NoMatchingNode(resolved);
    }

    if (entry.arm == Xdr.ARM_WITH_DELEGATES && entry.expiration != validUntilLedger) {
      for (Xdr.Node node : entry.nodes) {
        if (Xdr.isSigned(raw, node)) {
          throw new SoroauthException.InvalidExpiration(
              "the entry already carries signatures over expiration "
                  + entry.expiration
                  + ", but "
                  + validUntilLedger
                  + " was requested");
        }
      }
    }
    for (Xdr.Node match : matches) {
      if (Xdr.isSigned(raw, match) && !resignAllowed(resolved, resignScope)) {
        throw new SoroauthException.AlreadySigned();
      }
    }

    byte[] networkId = sha256(networkPassphrase.getBytes(java.nio.charset.StandardCharsets.UTF_8));
    byte[] payload = sha256(Xdr.preimageBytes(entry, validUntilLedger, networkId));

    List<byte[]> keys = new ArrayList<>(seeds);
    if (multisig) {
      keys.sort(Comparator.comparing(seed -> Ed25519.publicKey(seed), Xdr::compareUnsigned));
      for (int i = 1; i < keys.size(); i++) {
        if (Arrays.equals(Ed25519.publicKey(keys.get(i - 1)), Ed25519.publicKey(keys.get(i)))) {
          throw new SoroauthException.MissingSigner(signerAddress);
        }
      }
    }
    java.io.ByteArrayOutputStream sigs = new java.io.ByteArrayOutputStream();
    Xdr.putU32(sigs, 16);
    Xdr.putU32(sigs, 1); // present
    Xdr.putU32(sigs, keys.size());
    for (byte[] seed : keys) {
      byte[] publicKey = Ed25519.publicKey(seed);
      byte[] signature = Ed25519.sign(seed, payload);
      if (!verifyEd25519(publicKey, payload, signature)) {
        throw new SoroauthException.SignatureMismatch();
      }
      byte[] encoded = Xdr.encodeAccountMap(publicKey, signature);
      sigs.write(encoded, 0, encoded.length);
    }
    byte[] sigVal = sigs.toByteArray();

    // Splice the signature onto every matching node, offsets descending so
    // earlier offsets stay valid (every splice site is past the expiration
    // field, which keeps its offset throughout).
    matches.sort((a, b) -> Integer.compare(b.sigOffset, a.sigOffset));
    byte[] out = raw;
    for (Xdr.Node match : matches) {
      byte[] next = new byte[out.length - match.sigLength + sigVal.length];
      System.arraycopy(out, 0, next, 0, match.sigOffset);
      System.arraycopy(sigVal, 0, next, match.sigOffset, sigVal.length);
      System.arraycopy(
          out,
          match.sigOffset + match.sigLength,
          next,
          match.sigOffset + sigVal.length,
          out.length - match.sigOffset - match.sigLength);
      out = next;
    }
    int expOffset = entry.expirationOffset;
    out[expOffset] = (byte) ((validUntilLedger >>> 24) & 0xff);
    out[expOffset + 1] = (byte) ((validUntilLedger >>> 16) & 0xff);
    out[expOffset + 2] = (byte) ((validUntilLedger >>> 8) & 0xff);
    out[expOffset + 3] = (byte) (validUntilLedger & 0xff);
    return Base64.getEncoder().encodeToString(out);
  }

  private static boolean resignAllowed(String target, List<String> scope) {
    if (scope == null) {
      return false;
    }
    if (scope.isEmpty()) {
      return true;
    }
    byte[] targetXdr = Xdr.encodeAddress(target);
    for (String allowed : scope) {
      if (Arrays.equals(targetXdr, Xdr.encodeAddress(allowed))) {
        return true;
      }
    }
    return false;
  }

  private static List<Xdr.DelegateSpec> toSpecs(List<Delegate> delegates, int depth) {
    if (depth > Xdr.MAX_DEPTH) {
      throw new SoroauthException.DecodeLimit("delegate nesting past " + Xdr.MAX_DEPTH + " levels");
    }
    List<Xdr.DelegateSpec> specs = new ArrayList<>();
    for (Delegate delegate : delegates) {
      specs.add(
          new Xdr.DelegateSpec(
              delegate.address(), Xdr.encodeAddress(delegate.address()), toSpecs(delegate.nested(), depth + 1)));
    }
    Xdr.sortDelegates(specs);
    return specs;
  }

  private static void writeDelegates(java.io.ByteArrayOutputStream out, List<Xdr.DelegateSpec> specs) {
    Xdr.putU32(out, specs.size());
    for (Xdr.DelegateSpec spec : specs) {
      out.write(spec.addressXdr, 0, spec.addressXdr.length);
      Xdr.putU32(out, 1); // ScvVoid placeholder
      writeDelegates(out, spec.nested);
    }
  }

  private static String requireAccount(String account) {
    if (account == null || account.isEmpty()) {
      throw new SoroauthException.MissingSigner("");
    }
    Xdr.encodeAddress(account);
    return account;
  }

  private static void requireSeed(byte[] seed) {
    if (seed == null || seed.length != 32) {
      throw new SoroauthException.MalformedXdr("seed is not 32 bytes");
    }
  }

  private static void checkExpiration(long validUntilLedger) {
    if (validUntilLedger < 1 || validUntilLedger > 0xffffffffL) {
      throw new SoroauthException.InvalidExpiration("expiration ledger is " + validUntilLedger);
    }
  }

  static byte[] decodeBase64(String text, String what) {
    if (text == null || text.isEmpty()) {
      throw new SoroauthException.MalformedXdr(what + " is empty");
    }
    try {
      return Base64.getDecoder().decode(text);
    } catch (IllegalArgumentException e) {
      throw new SoroauthException.MalformedXdr(what + " is not valid base64", e);
    }
  }

  static byte[] sha256(byte[] data) {
    try {
      return MessageDigest.getInstance("SHA-256").digest(data);
    } catch (NoSuchAlgorithmException e) {
      throw new SoroauthException.MalformedXdr("SHA-256 unavailable", e);
    }
  }

  static String hex(byte[] data) {
    StringBuilder out = new StringBuilder(data.length * 2);
    for (byte b : data) {
      out.append(Character.forDigit((b >>> 4) & 0xf, 16));
      out.append(Character.forDigit(b & 0xf, 16));
    }
    return out.toString();
  }

  private static final byte[] X509_PREFIX = {
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
  };

  /** Verifies an ed25519 signature with the JDK provider. */
  static boolean verifyEd25519(byte[] publicKey, byte[] message, byte[] signature) {
    try {
      byte[] x509 = new byte[X509_PREFIX.length + 32];
      System.arraycopy(X509_PREFIX, 0, x509, 0, X509_PREFIX.length);
      System.arraycopy(publicKey, 0, x509, X509_PREFIX.length, 32);
      PublicKey key =
          KeyFactory.getInstance("EdDSA").generatePublic(new X509EncodedKeySpec(x509));
      Signature verifier = Signature.getInstance("Ed25519");
      verifier.initVerify(key);
      verifier.update(message);
      return verifier.verify(signature);
    } catch (Exception e) {
      return false;
    }
  }
}
