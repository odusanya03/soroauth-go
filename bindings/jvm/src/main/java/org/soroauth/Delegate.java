package org.soroauth;

import java.util.List;

/**
 * One delegate of the tree {@link Soroauth#withDelegates} wraps an entry
 * with, in the order the caller passes them: sorting is proven, not
 * assumed. The same address at two different nesting levels is allowed; a
 * repeat within one level is refused.
 */
public final class Delegate {
  private final String address;
  private final List<Delegate> nested;

  public Delegate(String address, List<Delegate> nested) {
    if (address == null || nested == null) {
      throw new IllegalArgumentException("address and nested are required");
    }
    this.address = address;
    this.nested = List.copyOf(nested);
  }

  /** The delegate's G... or C... address. */
  public String address() {
    return address;
  }

  /** Delegates nested under this one. */
  public List<Delegate> nested() {
    return nested;
  }
}
