package org.soroauth;

import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

/**
 * Minimal XDR for authorization entries: enough to walk credentials, slice
 * the invocation bytes back out, and splice signatures in. The parser never
 * interprets the invocation tree — its encoded bytes are carried opaquely —
 * which is what keeps this small: only the credential shapes and the
 * signature ScVal subset are decoded.
 */
final class Xdr {
  static final int ARM_SOURCE_ACCOUNT = 0;
  static final int ARM_ADDRESS = 1;
  static final int ARM_ADDRESS_V2 = 2;
  static final int ARM_WITH_DELEGATES = 3;

  static final int MAX_DEPTH = 64;
  static final int MAX_ACCOUNT_SIGNATURES = 20;

  // ScVal discriminants in enum order.
  private static final int SCV_BOOL = 0;
  private static final int SCV_VOID = 1;
  private static final int SCV_U32 = 3;
  private static final int SCV_I32 = 4;
  private static final int SCV_U64 = 5;
  private static final int SCV_I64 = 6;
  private static final int SCV_TIMEPOINT = 7;
  private static final int SCV_DURATION = 8;
  private static final int SCV_U128 = 9;
  private static final int SCV_I128 = 10;
  private static final int SCV_U256 = 11;
  private static final int SCV_I256 = 12;
  private static final int SCV_BYTES = 13;
  private static final int SCV_STRING = 14;
  private static final int SCV_SYMBOL = 15;
  private static final int SCV_VEC = 16;
  private static final int SCV_MAP = 17;
  private static final int SCV_ADDRESS = 18;
  private static final int SCV_LEDGER_KEY_CONTRACT_INSTANCE = 20;
  private static final int SCV_LEDGER_KEY_NONCE = 21;

  private Xdr() {}

  /** One signature-bearing node: its address and where its signature sits. */
  static final class Node {
    final byte[] addressXdr;
    final String address;
    final int sigOffset;
    final int sigLength;

    Node(byte[] addressXdr, String address, int sigOffset, int sigLength) {
      this.addressXdr = addressXdr;
      this.address = address;
      this.sigOffset = sigOffset;
      this.sigLength = sigLength;
    }
  }

  /** A decoded entry: structure plus the offsets needed to re-encode it. */
  static final class Entry {
    final byte[] raw;
    final int arm;
    final byte[] addressXdr;
    final String address;
    final long nonce;
    final long expiration;
    final int expirationOffset;
    final List<Node> nodes;
    final int invocationOffset;

    Entry(
        byte[] raw,
        int arm,
        byte[] addressXdr,
        String address,
        long nonce,
        long expiration,
        int expirationOffset,
        List<Node> nodes,
        int invocationOffset) {
      this.raw = raw;
      this.arm = arm;
      this.addressXdr = addressXdr;
      this.address = address;
      this.nonce = nonce;
      this.expiration = expiration;
      this.expirationOffset = expirationOffset;
      this.nodes = nodes;
      this.invocationOffset = invocationOffset;
    }

    byte[] invocationBytes() {
      byte[] out = new byte[raw.length - invocationOffset];
      System.arraycopy(raw, invocationOffset, out, 0, out.length);
      return out;
    }
  }

  static int u32(byte[] b, int p) {
    if (p < 0 || p + 4 > b.length) {
      throw new SoroauthException.MalformedXdr("truncated u32 at offset " + p);
    }
    return ((b[p] & 0xff) << 24) | ((b[p + 1] & 0xff) << 16) | ((b[p + 2] & 0xff) << 8) | (b[p + 3] & 0xff);
  }

  static long i64(byte[] b, int p) {
    if (p < 0 || p + 8 > b.length) {
      throw new SoroauthException.MalformedXdr("truncated i64 at offset " + p);
    }
    long out = 0;
    for (int i = 0; i < 8; i++) {
      out = (out << 8) | (b[p + i] & 0xff);
    }
    return out;
  }

  static void putU32(ByteArrayOutputStream out, long value) {
    out.write((int) ((value >>> 24) & 0xff));
    out.write((int) ((value >>> 16) & 0xff));
    out.write((int) ((value >>> 8) & 0xff));
    out.write((int) (value & 0xff));
  }

  static void putI64(ByteArrayOutputStream out, long value) {
    for (int i = 7; i >= 0; i--) {
      out.write((int) ((value >>> (8 * i)) & 0xff));
    }
  }

  static void putOpaque(ByteArrayOutputStream out, byte[] data) {
    putU32(out, data.length);
    out.write(data, 0, data.length);
    int pad = (4 - (data.length % 4)) % 4;
    for (int i = 0; i < pad; i++) {
      out.write(0);
    }
  }

  /** Compares byte arrays as unsigned, the way CAP-71-01 orders delegates. */
  static int compareUnsigned(byte[] a, byte[] b) {
    int n = Math.min(a.length, b.length);
    for (int i = 0; i < n; i++) {
      int diff = (a[i] & 0xff) - (b[i] & 0xff);
      if (diff != 0) {
        return diff;
      }
    }
    return a.length - b.length;
  }

  static String decodeAddress(byte[] xdr) {
    // An ScAddress on the wire is two discriminants and a key: the address
    // type, then — for accounts and contracts — the key type and 32 bytes.
    if (xdr.length != 40) {
      throw new SoroauthException.MalformedXdr("address is " + xdr.length + " bytes, want 40");
    }
    int disc = u32(xdr, 0);
    int keyType = u32(xdr, 4);
    if (keyType != 0) {
      throw new SoroauthException.MalformedXdr("unsupported address key type " + keyType);
    }
    byte[] raw = new byte[32];
    System.arraycopy(xdr, 8, raw, 0, 32);
    if (disc == 0) {
      return Strkey.encode(Strkey.VERSION_ACCOUNT, raw);
    }
    if (disc == 1) {
      return Strkey.encode(Strkey.VERSION_CONTRACT, raw);
    }
    throw new SoroauthException.InvalidAddress("<address type " + disc + ">");
  }

  /** Encodes a G... or C... address to its 40-byte XDR form. */
  static byte[] encodeAddress(String address) {
    byte[] raw;
    int disc;
    if (address.startsWith("G")) {
      raw = Strkey.decode(address, Strkey.VERSION_ACCOUNT);
      disc = 0;
    } else if (address.startsWith("C")) {
      raw = Strkey.decode(address, Strkey.VERSION_CONTRACT);
      disc = 1;
    } else {
      throw new SoroauthException.InvalidAddress(address);
    }
    if (raw.length != 32) {
      throw new SoroauthException.InvalidAddress(address);
    }
    byte[] out = new byte[40];
    out[3] = (byte) disc;
    // Key type is zero for both account and contract keys.
    System.arraycopy(raw, 0, out, 8, 32);
    return out;
  }

  /** Decodes one entry, bounding the delegate walk at {@link #MAX_DEPTH}. */
  static Entry parseEntry(byte[] raw) {
    int arm = u32(raw, 0);
    if (arm == ARM_SOURCE_ACCOUNT) {
      return new Entry(raw, arm, null, "", 0, 0, -1, List.of(), 4);
    }
    if (arm != ARM_ADDRESS && arm != ARM_ADDRESS_V2 && arm != ARM_WITH_DELEGATES) {
      throw new SoroauthException.UnsupportedCredentials();
    }
    int p = 4;
    byte[] addressXdr = slice(raw, p, 40);
    String address = decodeAddress(addressXdr);
    p += 40;
    long nonce = i64(raw, p);
    p += 8;
    int expirationOffset = p;
    long expiration = u32(raw, p) & 0xffffffffL;
    p += 4;
    List<Node> nodes = new ArrayList<>();
    int sigEnd = skipScVal(raw, p, 0);
    nodes.add(new Node(addressXdr, address, p, sigEnd - p));
    p = sigEnd;
    if (arm == ARM_WITH_DELEGATES) {
      int count = u32(raw, p);
      p += 4;
      for (int i = 0; i < count; i++) {
        p = parseDelegate(raw, p, nodes, 1);
      }
    }
    return new Entry(raw, arm, addressXdr, address, nonce, expiration, expirationOffset, nodes, p);
  }

  private static int parseDelegate(byte[] raw, int p, List<Node> nodes, int depth) {
    if (depth > MAX_DEPTH) {
      throw new SoroauthException.DecodeLimit("delegate nesting past " + MAX_DEPTH + " levels");
    }
    byte[] addressXdr = slice(raw, p, 40);
    String address = decodeAddress(addressXdr);
    p += 40;
    int sigEnd = skipScVal(raw, p, 0);
    nodes.add(new Node(addressXdr, address, p, sigEnd - p));
    p = sigEnd;
    int count = u32(raw, p);
    p += 4;
    for (int i = 0; i < count; i++) {
      p = parseDelegate(raw, p, nodes, depth + 1);
    }
    return p;
  }

  private static byte[] slice(byte[] raw, int offset, int length) {
    if (offset < 0 || offset + length > raw.length) {
      throw new SoroauthException.MalformedXdr("truncated field at offset " + offset);
    }
    byte[] out = new byte[length];
    System.arraycopy(raw, offset, out, 0, length);
    return out;
  }

  /** The end offset of the ScVal starting at p. */
  static int skipScVal(byte[] raw, int p, int depth) {
    if (depth > MAX_DEPTH) {
      throw new SoroauthException.DecodeLimit("ScVal nesting past " + MAX_DEPTH + " levels");
    }
    int disc = u32(raw, p);
    switch (disc) {
      case SCV_VOID:
        return p + 4;
      case SCV_BOOL:
      case SCV_U32:
      case SCV_I32:
        return p + 8;
      case SCV_U64:
      case SCV_I64:
      case SCV_TIMEPOINT:
      case SCV_DURATION:
        return p + 12;
      case SCV_U128:
      case SCV_I128:
      case SCV_U256:
      case SCV_I256:
        return p + 40;
      case SCV_BYTES:
      case SCV_STRING:
      case SCV_SYMBOL: {
        int length = u32(raw, p + 4);
        if (length < 0 || p + 8 + length > raw.length) {
          throw new SoroauthException.MalformedXdr("truncated variable-length value");
        }
        return p + 8 + length + ((4 - (length % 4)) % 4);
      }
      case SCV_VEC:
      case SCV_MAP: {
        // Vec and Map arms are optional pointers (SCVec *vec), so a
        // 4-byte presence word follows the discriminant: 0 is an absent
        // (null) vector, 1 introduces the length and elements. An empty
        // vector — the "to be filled in" placeholder simulation emits —
        // is 12 bytes, not 8.
        int present = u32(raw, p + 4);
        if (present == 0) {
          return p + 8;
        }
        if (present != 1) {
          throw new SoroauthException.MalformedXdr("bad vector presence word");
        }
        int count = u32(raw, p + 8);
        if (count < 0) {
          throw new SoroauthException.MalformedXdr("negative vector length");
        }
        int q = p + 12;
        int stride = disc == SCV_VEC ? 1 : 2;
        for (int i = 0; i < count * stride; i++) {
          q = skipScVal(raw, q, depth + 1);
        }
        return q;
      }
      case SCV_ADDRESS: {
        int kind = u32(raw, p + 4);
        if ((kind == 0 || kind == 1) && p + 44 <= raw.length) {
          return p + 44;
        }
        throw new SoroauthException.MalformedXdr("unsupported address kind " + kind);
      }
      case SCV_LEDGER_KEY_CONTRACT_INSTANCE:
        return p + 4;
      case SCV_LEDGER_KEY_NONCE:
        return p + 12;
      default:
        throw new SoroauthException.MalformedXdr("unsupported ScVal discriminant " + disc);
    }
  }

  /** Whether a signature field holds a real signature rather than a placeholder. */
  static boolean isSigned(byte[] raw, Node node) {
    int disc = u32(raw, node.sigOffset);
    if (disc == SCV_VOID) {
      return false;
    }
    if (disc == SCV_VEC) {
      if (node.sigLength < 12) {
        return false;
      }
      int present = u32(raw, node.sigOffset + 4);
      if (present == 0) {
        return false;
      }
      return u32(raw, node.sigOffset + 8) > 0;
    }
    return true;
  }

  /** A classic account signature, or the reason it cannot be checked. */
  static final class SigResult {
    final byte[] publicKey;
    final byte[] signature;
    final String cannotCheckReason;

    SigResult(byte[] publicKey, byte[] signature, String cannotCheckReason) {
      this.publicKey = publicKey;
      this.signature = signature;
      this.cannotCheckReason = cannotCheckReason;
    }
  }

  /** Reads back the single {public_key, signature} map the host decodes as one account signature. */
  static SigResult parseClassicSig(byte[] raw, Node node) {
    int p = node.sigOffset;
    if (u32(raw, p) != SCV_VEC || u32(raw, p + 4) != 1) {
      return cannotCheck("signature is not the built-in account vector");
    }
    if (u32(raw, p + 8) != 1) {
      return cannotCheck("signature vector does not hold exactly 1 entry");
    }
    int q = p + 12;
    if (u32(raw, q) != SCV_MAP || u32(raw, q + 4) != 1) {
      return cannotCheck("signature vector does not hold a map");
    }
    if (u32(raw, q + 8) != 2) {
      return cannotCheck("signature map does not hold 2 entries");
    }
    q += 12;
    byte[] publicKey = null;
    byte[] signature = null;
    for (int i = 0; i < 2; i++) {
      if (u32(raw, q) != SCV_SYMBOL) {
        return cannotCheck("signature map key is not a symbol");
      }
      int nameLen = u32(raw, q + 4);
      String name = new String(raw, q + 8, nameLen, java.nio.charset.StandardCharsets.UTF_8);
      q += 8 + nameLen + ((4 - (nameLen % 4)) % 4);
      if (u32(raw, q) != SCV_BYTES) {
        return cannotCheck("signature field \"" + name + "\" is not bytes");
      }
      int valueLen = u32(raw, q + 4);
      byte[] value = slice(raw, q + 8, valueLen);
      q += 8 + valueLen + ((4 - (valueLen % 4)) % 4);
      if (name.equals("public_key")) {
        publicKey = value;
      } else if (name.equals("signature")) {
        signature = value;
      }
    }
    if (publicKey == null || signature == null) {
      return cannotCheck("signature map is missing public_key or signature");
    }
    if (publicKey.length != 32) {
      return cannotCheck("signature public key is " + publicKey.length + " bytes, want 32");
    }
    if (signature.length != 64) {
      return cannotCheck("signature is " + signature.length + " bytes, want 64");
    }
    return new SigResult(publicKey, signature, "");
  }

  private static SigResult cannotCheck(String reason) {
    return new SigResult(null, null, reason);
  }

  /** The single {public_key, signature} map, keys in order as the host requires. */
  static byte[] encodeClassicSig(byte[] publicKey, byte[] signature) {
    byte[] map = encodeAccountMap(publicKey, signature);
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    putU32(out, SCV_VEC);
    putU32(out, 1); // present
    putU32(out, 1); // length
    out.write(map, 0, map.length);
    return out.toByteArray();
  }

  /** One {public_key, signature} map body, without the enclosing vector. */
  static byte[] encodeAccountMap(byte[] publicKey, byte[] signature) {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    putU32(out, SCV_MAP);
    putU32(out, 1); // present
    putU32(out, 2); // length
    putSymbolEntry(out, "public_key", publicKey);
    putSymbolEntry(out, "signature", signature);
    return out.toByteArray();
  }

  private static void putSymbolEntry(ByteArrayOutputStream out, String name, byte[] value) {
    putU32(out, SCV_SYMBOL);
    putOpaque(out, name.getBytes(java.nio.charset.StandardCharsets.UTF_8));
    putU32(out, SCV_BYTES);
    putOpaque(out, value);
  }

  /** The preimage bytes for an entry: discriminant, network id, nonce, expiration, address, invocation. */
  static byte[] preimageBytes(Entry entry, long validUntil, byte[] networkId) {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    if (entry.arm == ARM_ADDRESS) {
      putU32(out, 9);
    } else {
      putU32(out, 10);
    }
    out.write(networkId, 0, networkId.length);
    putI64(out, entry.nonce);
    putU32(out, validUntil);
    if (entry.arm != ARM_ADDRESS) {
      out.write(entry.addressXdr, 0, entry.addressXdr.length);
    }
    byte[] invocation = entry.invocationBytes();
    out.write(invocation, 0, invocation.length);
    return out.toByteArray();
  }

  /** One caller-supplied delegate level, with resolved address bytes for sorting. */
  static final class DelegateSpec {
    final String address;
    final byte[] addressXdr;
    final List<DelegateSpec> nested;

    DelegateSpec(String address, byte[] addressXdr, List<DelegateSpec> nested) {
      this.address = address;
      this.addressXdr = addressXdr;
      this.nested = nested;
    }
  }

  /** Sorts one delegates level by address bytes, refusing duplicates. */
  static void sortDelegates(List<DelegateSpec> level) {
    level.sort(Comparator.comparing(spec -> spec.addressXdr, Xdr::compareUnsigned));
    for (int i = 1; i < level.size(); i++) {
      if (compareUnsigned(level.get(i - 1).addressXdr, level.get(i).addressXdr) == 0) {
        throw new SoroauthException.DuplicateDelegate(level.get(i).address);
      }
    }
  }
}
