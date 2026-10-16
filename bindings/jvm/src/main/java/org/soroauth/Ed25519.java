package org.soroauth;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Ed25519 signing and public-key derivation (RFC 8032), over the JDK's
 * SHA-512. Verification uses the JDK's own Ed25519 provider instead; this
 * class exists because the JDK offers no seed-to-public-key derivation,
 * and the golden vectors prove every byte it emits.
 */
final class Ed25519 {
  private static final BigInteger Q = BigInteger.valueOf(2).pow(255).subtract(BigInteger.valueOf(19));
  private static final BigInteger L =
      BigInteger.valueOf(2).pow(252).add(new BigInteger("27742317777372353535851937790883648493"));
  private static final BigInteger D =
      BigInteger.valueOf(-121665)
          .multiply(BigInteger.valueOf(121666).modInverse(Q))
          .mod(Q);
  private static final BigInteger D2 = D.multiply(BigInteger.valueOf(2)).mod(Q);
  private static final BigInteger SQRT_M1 =
      BigInteger.valueOf(2).modPow(Q.subtract(BigInteger.ONE).divide(BigInteger.valueOf(4)), Q);

  private Ed25519() {}

  private static final class Point {
    final BigInteger x;
    final BigInteger y;

    Point(BigInteger x, BigInteger y) {
      this.x = x;
      this.y = y;
    }
  }

  private static final Point BASE = decodePoint(hexToBytes("5866666666666666666666666666666666666666666666666666666666666666"));

  private static byte[] hexToBytes(String hex) {
    byte[] out = new byte[hex.length() / 2];
    for (int i = 0; i < out.length; i++) {
      out[i] = (byte) Integer.parseInt(hex.substring(2 * i, 2 * i + 2), 16);
    }
    return out;
  }

  static byte[] sha512(byte[]... parts) {
    try {
      MessageDigest digest = MessageDigest.getInstance("SHA-512");
      for (byte[] part : parts) {
        digest.update(part);
      }
      return digest.digest();
    } catch (NoSuchAlgorithmException e) {
      throw new SoroauthException.MalformedXdr("SHA-512 unavailable", e);
    }
  }

  private static BigInteger leToInt(byte[] data, int offset, int length) {
    byte[] reversed = new byte[length];
    for (int i = 0; i < length; i++) {
      reversed[i] = data[offset + length - 1 - i];
    }
    return new BigInteger(1, reversed);
  }

  private static byte[] intToLe(BigInteger value, int length) {
    byte[] big = value.toByteArray();
    byte[] out = new byte[length];
    for (int i = 0; i < length && i < big.length; i++) {
      out[i] = big[big.length - 1 - i];
    }
    return out;
  }

  /** Recovers x from y for a point on the curve. */
  private static BigInteger recoverX(BigInteger y) {
    BigInteger y2 = y.multiply(y).mod(Q);
    BigInteger x = y2.subtract(BigInteger.ONE)
        .multiply(D.multiply(y2).add(BigInteger.ONE).modInverse(Q))
        .mod(Q);
    x = x.modPow(Q.add(BigInteger.valueOf(3)).divide(BigInteger.valueOf(8)), Q);
    if (!x.multiply(x).subtract(y2.subtract(BigInteger.ONE)
            .multiply(D.multiply(y2).add(BigInteger.ONE).modInverse(Q))
            .mod(Q)).mod(Q).equals(BigInteger.ZERO)) {
      x = x.multiply(SQRT_M1).mod(Q);
    }
    return x;
  }

  private static Point decodePoint(byte[] encoded) {
    if (encoded.length != 32) {
      throw new SoroauthException.MalformedXdr("compressed point is not 32 bytes");
    }
    int parity = (encoded[31] & 0x80) >>> 7;
    byte[] raw = encoded.clone();
    raw[31] &= 0x7f;
    BigInteger y = leToInt(raw, 0, 32);
    BigInteger x = recoverX(y);
    if (x.testBit(0) != (parity == 1)) {
      x = Q.subtract(x);
    }
    return new Point(x, y);
  }

  private static byte[] encodePoint(Point p) {
    byte[] out = intToLe(p.y, 32);
    if (p.x.testBit(0)) {
      out[31] |= 0x80;
    }
    return out;
  }

  private static Point add(Point p, Point q) {
    // Twisted Edwards addition for a = -1: y3 carries + x1*x2, since the
    // generic term is y1*y2 - a*x1*x2.
    BigInteger x1 = p.x;
    BigInteger y1 = p.y;
    BigInteger x2 = q.x;
    BigInteger y2 = q.y;
    BigInteger e = D.multiply(x1).multiply(x2).multiply(y1).multiply(y2).mod(Q);
    BigInteger x3 = x1.multiply(y2).add(x2.multiply(y1)).multiply(BigInteger.ONE.add(e).modInverse(Q)).mod(Q);
    BigInteger y3 = y1.multiply(y2).add(x1.multiply(x2)).multiply(BigInteger.ONE.subtract(e).modInverse(Q)).mod(Q);
    return new Point(x3, y3);
  }

  private static Point multiply(Point p, BigInteger scalar) {
    Point result = new Point(BigInteger.ZERO, BigInteger.ONE);
    Point addend = p;
    for (int i = 0; i < scalar.bitLength(); i++) {
      if (scalar.testBit(i)) {
        result = add(result, addend);
      }
      addend = add(addend, addend);
    }
    return result;
  }

  private static byte[] clamp(byte[] digest) {
    byte[] a = new byte[32];
    System.arraycopy(digest, 0, a, 0, 32);
    a[0] &= 0xf8;
    a[31] &= 0x3f;
    a[31] |= 0x40;
    return a;
  }

  /** The public key for a 32-byte seed. */
  static byte[] publicKey(byte[] seed) {
    if (seed.length != 32) {
      throw new SoroauthException.MalformedXdr("seed is not 32 bytes");
    }
    byte[] h = sha512(seed);
    BigInteger a = leToInt(clamp(h), 0, 32);
    return encodePoint(multiply(BASE, a));
  }

  /** RFC 8032 deterministic signature over a message. */
  static byte[] sign(byte[] seed, byte[] message) {
    if (seed.length != 32) {
      throw new SoroauthException.MalformedXdr("seed is not 32 bytes");
    }
    byte[] h = sha512(seed);
    BigInteger a = leToInt(clamp(h), 0, 32);
    byte[] prefix = new byte[32];
    System.arraycopy(h, 32, prefix, 0, 32);
    byte[] publicKey = encodePoint(multiply(BASE, a));
    BigInteger r = leToInt(sha512(prefix, message), 0, 64).mod(L);
    byte[] rEncoded = encodePoint(multiply(BASE, r));
    BigInteger k = leToInt(sha512(rEncoded, publicKey, message), 0, 64).mod(L);
    BigInteger s = r.add(k.multiply(a)).mod(L);
    byte[] signature = new byte[64];
    System.arraycopy(rEncoded, 0, signature, 0, 32);
    System.arraycopy(intToLe(s, 32), 0, signature, 32, 32);
    return signature;
  }
}
