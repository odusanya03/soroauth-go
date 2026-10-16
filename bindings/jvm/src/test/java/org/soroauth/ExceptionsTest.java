package org.soroauth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** Each refusal has its own exception with its own kind, and faults are not refusals. */
class ExceptionsTest {
  @Test
  void refusalsCarryTheirOwnTypes() {
    assertTrue(new SoroauthException.SourceAccount().isRefusal());
    assertTrue(new SoroauthException.UnsupportedCredentials().isRefusal());
    assertTrue(new SoroauthException.SignatureMismatch().isRefusal());
    assertTrue(new SoroauthException.AlreadySigned().isRefusal());
    assertTrue(new SoroauthException.EmptyPassphrase().isRefusal());
    assertEquals(
        "GABC", new SoroauthException.NoMatchingNode("GABC").address());
    assertEquals(
        "GABC", new SoroauthException.DuplicateDelegate("GABC").address());
  }

  @Test
  void faultsAreNotRefusals() {
    assertFalse(new SoroauthException.InvalidAddress("!!!").isRefusal());
    assertFalse(new SoroauthException.MalformedXdr("truncated").isRefusal());
  }

  @Test
  void emptyPassphraseIsARefusal() {
    SoroauthException e =
        assertThrows(
            SoroauthException.EmptyPassphrase.class,
            () -> Soroauth.verify("AAAA", ""));
    assertTrue(e.isRefusal());
  }

  @Test
  void malformedInputIsAFault() {
    SoroauthException e =
        assertThrows(
            SoroauthException.MalformedXdr.class,
            () -> Soroauth.verify("!!!not-base64!!!", "Test SDF Network ; September 2015"));
    assertFalse(e.isRefusal());
  }

  @Test
  void zeroExpirationIsRefused() {
    SoroauthException e =
        assertThrows(
            SoroauthException.InvalidExpiration.class,
            () ->
                Soroauth.authorize(
                    "AAAA", new byte[32], 0, "Test SDF Network ; September 2015", null));
    assertTrue(e.isRefusal());
  }

  @Test
  void tooManyKeysAreRefused() {
    byte[][] seeds = new byte[21][32];
    SoroauthException e =
        assertThrows(
            SoroauthException.TooManySignatures.class,
            () ->
                Soroauth.authorizeMultisig(
                    "AAAA",
                    java.util.Arrays.asList(seeds),
                    "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF",
                    1234567,
                    "Test SDF Network ; September 2015",
                    null));
    assertTrue(e.isRefusal());
  }

  @Test
  void verdictsKeepTheirNames() {
    assertEquals("verified", Verdict.VERIFIED.wireName());
    assertEquals("unsigned", Verdict.UNSIGNED.wireName());
    assertEquals("invalid", Verdict.INVALID.wireName());
    assertEquals("cannot_check", Verdict.CANNOT_CHECK.wireName());
  }

  @Test
  void unsignedEntryIsReportedNotFailed() throws Exception {
    // An unsigned entry's node is reported unsigned instead of throwing.
    Path vector = Path.of("../../testdata/vectors/legacy_single_testnet.json");
    Map<String, Object> parsed = Json.object(Json.parse(java.nio.file.Files.readString(vector)));
    String unsigned = Json.string(parsed.get("unsigned_entry_xdr"));
    VerificationReport report =
        Soroauth.verify(unsigned, "Test SDF Network ; September 2015");
    assertFalse(report.verified());
    assertEquals(1, report.nodes().size());
    assertEquals(Verdict.UNSIGNED, report.nodes().get(0).verdict());
  }
}
