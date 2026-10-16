package org.soroauth;

import java.util.List;

/** The result of {@link Soroauth#verify}. */
public final class VerificationReport {
  private final String credentialType;
  private final boolean addressBound;
  private final String address;
  private final long validUntilLedger;
  private final List<NodeVerdict> nodes;
  private final String note;

  public VerificationReport(
      String credentialType,
      boolean addressBound,
      String address,
      long validUntilLedger,
      List<NodeVerdict> nodes,
      String note) {
    this.credentialType = credentialType;
    this.addressBound = addressBound;
    this.address = address;
    this.validUntilLedger = validUntilLedger;
    this.nodes = List.copyOf(nodes);
    this.note = note == null ? "" : note;
  }

  /** The stable credential-type string: source_account, address, address_v2 or address_with_delegates. */
  public String credentialType() {
    return credentialType;
  }

  /** Whether the arm's payload binds the address into the signed bytes (CAP-71-01). */
  public boolean addressBound() {
    return addressBound;
  }

  /** The entry's address, for the three address arms. */
  public String address() {
    return address;
  }

  /** The expiration the payload was rebuilt with: the value stored on the entry. */
  public long validUntilLedger() {
    return validUntilLedger;
  }

  /** One verdict per credential node, top-level first, then the delegate tree depth-first. */
  public List<NodeVerdict> nodes() {
    return nodes;
  }

  /** A caveat about the whole report, such as the source-account arm carrying nothing to check. */
  public String note() {
    return note;
  }

  /**
   * Whether every credential node verified. True vacuously when there are
   * no nodes; unsigned, invalid and cannot-check nodes all make it false.
   * Verification fails closed — and the per-node verdicts above are what a
   * caller reads when it needs more than this bit.
   */
  public boolean verified() {
    for (NodeVerdict node : nodes) {
      if (node.verdict() != Verdict.VERIFIED) {
        return false;
      }
    }
    return true;
  }
}
