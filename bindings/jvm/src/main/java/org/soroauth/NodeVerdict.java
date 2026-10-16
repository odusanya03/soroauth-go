package org.soroauth;

/** The verification outcome for one credential node. */
public final class NodeVerdict {
  private final String address;
  private final Verdict verdict;
  private final String reason;

  public NodeVerdict(String address, Verdict verdict, String reason) {
    this.address = address;
    this.verdict = verdict;
    this.reason = reason == null ? "" : reason;
  }

  /** The G... or C... address of the node. */
  public String address() {
    return address;
  }

  /** The outcome. */
  public Verdict verdict() {
    return verdict;
  }

  /** Why, in plain language, when the verdict is not {@link Verdict#VERIFIED}. */
  public String reason() {
    return reason;
  }
}
