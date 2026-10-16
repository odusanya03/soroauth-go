package org.soroauth;

/** Stellar strkey encoding: version byte, payload, little-endian CRC16-XModem, base32 without padding. */
final class Strkey {
  static final int VERSION_ACCOUNT = 6 << 3; // G...
  static final int VERSION_CONTRACT = 2 << 3; // C...

  private static final char[] ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".toCharArray();

  private Strkey() {}

  /** Encodes a raw payload with the given version byte. */
  static String encode(int version, byte[] payload) {
    byte[] raw = new byte[1 + payload.length + 2];
    raw[0] = (byte) version;
    System.arraycopy(payload, 0, raw, 1, payload.length);
    int crc = crc16(raw, 0, 1 + payload.length);
    raw[1 + payload.length] = (byte) (crc & 0xff);
    raw[1 + payload.length + 1] = (byte) ((crc >>> 8) & 0xff);
    return base32Encode(raw);
  }

  /** Decodes a strkey, checking the version byte. */
  static byte[] decode(String text, int expectedVersion) {
    byte[] raw;
    try {
      raw = base32Decode(text);
    } catch (IllegalArgumentException e) {
      throw new SoroauthException.InvalidAddress(text);
    }
    if (raw.length < 3 || (raw[0] & 0xff) != expectedVersion) {
      throw new SoroauthException.InvalidAddress(text);
    }
    int crc = crc16(raw, 0, raw.length - 2);
    int want = (raw[raw.length - 2] & 0xff) | ((raw[raw.length - 1] & 0xff) << 8);
    if (crc != want) {
      throw new SoroauthException.InvalidAddress(text);
    }
    byte[] payload = new byte[raw.length - 3];
    System.arraycopy(raw, 1, payload, 0, payload.length);
    return payload;
  }

  /** CRC16-XModem: polynomial 0x1021, initial 0x0000. */
  static int crc16(byte[] data, int offset, int length) {
    int crc = 0x0000;
    for (int i = 0; i < length; i++) {
      crc ^= (data[offset + i] & 0xff) << 8;
      for (int bit = 0; bit < 8; bit++) {
        crc = (crc & 0x8000) != 0 ? ((crc << 1) ^ 0x1021) & 0xffff : (crc << 1) & 0xffff;
      }
    }
    return crc & 0xffff;
  }

  static String base32Encode(byte[] data) {
    StringBuilder out = new StringBuilder((data.length * 8 + 4) / 5);
    int buffer = 0;
    int bits = 0;
    for (byte b : data) {
      buffer = (buffer << 8) | (b & 0xff);
      bits += 8;
      while (bits >= 5) {
        bits -= 5;
        out.append(ALPHABET[(buffer >>> bits) & 0x1f]);
      }
    }
    if (bits > 0) {
      out.append(ALPHABET[(buffer << (5 - bits)) & 0x1f]);
    }
    return out.toString();
  }

  static byte[] base32Decode(String text) {
    int[] values = new int[128];
    java.util.Arrays.fill(values, -1);
    for (int i = 0; i < ALPHABET.length; i++) {
      values[ALPHABET[i]] = i;
    }
    int totalBits = text.length() * 5;
    int outLen = totalBits / 8;
    byte[] out = new byte[outLen];
    int buffer = 0;
    int bits = 0;
    int pos = 0;
    for (int i = 0; i < text.length(); i++) {
      char c = text.charAt(i);
      if (c >= values.length || values[c] < 0) {
        throw new IllegalArgumentException("bad base32 character: " + c);
      }
      buffer = (buffer << 5) | values[c];
      bits += 5;
      if (bits >= 8) {
        bits -= 8;
        if (pos < outLen) {
          out[pos++] = (byte) ((buffer >>> bits) & 0xff);
        }
      }
    }
    return out;
  }
}
