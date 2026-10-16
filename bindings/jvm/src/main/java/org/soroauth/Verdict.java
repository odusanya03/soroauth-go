package org.soroauth;

/** One credential node's offline verification outcome. Four values, never a boolean. */
public enum Verdict {
  /** The node carries a classic account signature that verifies over the payload the entry commits to. */
  VERIFIED,
  /** The node carries no signature. Under CAP-71-01 a delegates entry may legitimately leave its top-level node void. */
  UNSIGNED,
  /** The node carries a classic account signature that does not verify. */
  INVALID,
  /** The node's signature is not the built-in account shape, so offline code cannot decide it. Never verified. */
  CANNOT_CHECK;

  /** The stable string the Go library and the HTTP surfaces report. */
  public String wireName() {
    switch (this) {
      case VERIFIED:
        return "verified";
      case UNSIGNED:
        return "unsigned";
      case INVALID:
        return "invalid";
      case CANNOT_CHECK:
        return "cannot_check";
      default:
        throw new IllegalStateException(name());
    }
  }
}
