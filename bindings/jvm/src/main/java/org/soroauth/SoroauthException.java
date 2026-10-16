package org.soroauth;

/**
 * The base failure of this library. Every failure is either a refusal or a
 * fault, and {@link #kind()} says which, so a caller can tell the two apart
 * without parsing messages — the same role {@code errors.Is} plays in Go.
 *
 * <p>A {@link Kind#REFUSAL} is the library declining: the protocol or the
 * caller's intent was ambiguous and the fail-closed answer is no. It mirrors
 * a Go sentinel. A {@link Kind#FAULT} is something breaking on the way
 * there: undecodable input, a missing crypto provider, a native library
 * that would not load. Refusals name what was refused; faults name what
 * broke.
 *
 * <p>Each distinction is its own nested class so callers catch it by type:
 * {@code catch (SoroauthException.NoMatchingNode e)}.
 */
public class SoroauthException extends RuntimeException {
  /** Whether the failure is a refusal or a fault. */
  public enum Kind {
    /** The library declined: fail-closed, mirrors a Go sentinel. */
    REFUSAL,
    /** Something broke: input, provider, or native load. */
    FAULT,
  }

  private final Kind kind;

  public SoroauthException(String message, Kind kind) {
    super(message);
    this.kind = kind;
  }

  public SoroauthException(String message, Kind kind, Throwable cause) {
    super(message, cause);
    this.kind = kind;
  }

  /** Whether this failure is a refusal or a fault. */
  public Kind kind() {
    return kind;
  }

  /** Whether this failure is a fail-closed refusal. */
  public boolean isRefusal() {
    return kind == Kind.REFUSAL;
  }

  /** A signing payload was requested for a source-account entry, which carries none. Mirrors {@code ErrSourceAccountCredentials}. */
  public static final class SourceAccount extends SoroauthException {
    public SourceAccount() {
      super("credentials are source-account, which carry no signature payload", Kind.REFUSAL);
    }
  }

  /** The credentials arm is outside the four defined ones. Mirrors {@code ErrUnsupportedCredentials}. */
  public static final class UnsupportedCredentials extends SoroauthException {
    public UnsupportedCredentials() {
      super("unsupported credentials type", Kind.REFUSAL);
    }
  }

  /** No credential node carries the target address. Mirrors {@code ErrNoMatchingCredentialNode}. */
  public static final class NoMatchingNode extends SoroauthException {
    private final String address;

    public NoMatchingNode(String address) {
      super("no credential node matches the target address " + address, Kind.REFUSAL);
      this.address = address;
    }

    /** The target address that matched no node. */
    public String address() {
      return address;
    }
  }

  /** One address appears twice within a single delegates array (CAP-71-01). Mirrors {@code ErrDuplicateDelegate}. */
  public static final class DuplicateDelegate extends SoroauthException {
    private final String address;

    public DuplicateDelegate(String address) {
      super("duplicate delegate address at the same level: " + address, Kind.REFUSAL);
      this.address = address;
    }

    /** The offending address. */
    public String address() {
      return address;
    }
  }

  /** A produced signature does not verify against its payload. Mirrors {@code ErrSignatureMismatch}. */
  public static final class SignatureMismatch extends SoroauthException {
    public SignatureMismatch() {
      super("signature does not verify against the payload", Kind.REFUSAL);
    }
  }

  /** No signer for an address that needs one. Mirrors {@code ErrMissingSigner}. */
  public static final class MissingSigner extends SoroauthException {
    public MissingSigner(String address) {
      super("no signer for address " + address, Kind.REFUSAL);
    }
  }

  /** Signing would overwrite a signature already present. Mirrors {@code ErrAlreadySigned}. */
  public static final class AlreadySigned extends SoroauthException {
    public AlreadySigned() {
      super("credential node is already signed", Kind.REFUSAL);
    }
  }

  /** The expiration is zero or disagrees with signatures already on the entry. Mirrors {@code ErrInvalidExpiration}. */
  public static final class InvalidExpiration extends SoroauthException {
    public InvalidExpiration(String detail) {
      super("invalid signature expiration ledger: " + detail, Kind.REFUSAL);
    }
  }

  /** More signing keys than the host accepts (20). Mirrors {@code ErrTooManySignatures}. */
  public static final class TooManySignatures extends SoroauthException {
    public TooManySignatures(int keys) {
      super(
          "too many signatures for a classic account: " + keys + ", the host accepts at most 20",
          Kind.REFUSAL);
    }
  }

  /** Untrusted input exceeds a decode bound. Mirrors {@code ErrDecodeLimit}. */
  public static final class DecodeLimit extends SoroauthException {
    public DecodeLimit(String detail) {
      super("untrusted input exceeds a decode limit: " + detail, Kind.REFUSAL);
    }
  }

  /** The network passphrase is empty. An empty passphrase hashes to a network that does not exist. */
  public static final class EmptyPassphrase extends SoroauthException {
    public EmptyPassphrase() {
      super("network passphrase is empty", Kind.REFUSAL);
    }
  }

  /** An address is not a G... account or C... contract strkey. Fault: the input was malformed. */
  public static final class InvalidAddress extends SoroauthException {
    public InvalidAddress(String address) {
      super(address + " is not a G... or C... address", Kind.FAULT);
    }
  }

  /** XDR decoding failed for a reason outside the bounded checks. Fault: the input was malformed. */
  public static final class MalformedXdr extends SoroauthException {
    public MalformedXdr(String detail) {
      super("malformed XDR: " + detail, Kind.FAULT);
    }

    public MalformedXdr(String detail, Throwable cause) {
      super("malformed XDR: " + detail, Kind.FAULT, cause);
    }
  }
}
