package org.soroauth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;

/**
 * The correctness gate: every golden vector replayed through the JVM API
 * with byte equality asserted. For each case the preimage hash, the
 * payload, and — after replaying every recorded signing step — the final
 * signed entry must be byte-identical to the reference. A run that checks
 * nothing fails.
 */
class GoldenVectorsTest {
  private static final Path VECTORS = Path.of("../../testdata/vectors");

  static byte[] seedForLabel(String label) throws Exception {
    return MessageDigest.getInstance("SHA-256").digest(label.getBytes(StandardCharsets.UTF_8));
  }

  static List<Path> vectorFiles() throws Exception {
    try (Stream<Path> files = Files.list(VECTORS)) {
      List<Path> paths =
          files.filter(p -> p.toString().endsWith(".json")).sorted().toList();
      assertTrue(!paths.isEmpty(), "no golden vectors found; the gate proved nothing");
      return paths;
    }
  }

  @Test
  void replaysEveryVectorWithByteEquality() throws Exception {
    int checked = 0;
    for (Path path : vectorFiles()) {
      Map<String, Object> vector = Json.object(Json.parse(Files.readString(path)));
      String name = Json.string(vector.get("name"));
      long validUntil = Json.integer(vector.get("valid_until_ledger"));
      String passphrase = Json.string(vector.get("network_passphrase"));
      String unsignedXdr = Json.string(vector.get("unsigned_entry_xdr"));

      byte[] entryBytes = Base64.getDecoder().decode(unsignedXdr);
      Xdr.Entry entry = Xdr.parseEntry(entryBytes);

      if (entry.arm == Xdr.ARM_SOURCE_ACCOUNT) {
        // Passes through untouched.
        String passed =
            Soroauth.authorize(
                unsignedXdr, seedForLabel("soroauth-vector-signer-1"), validUntil, passphrase, null);
        assertEquals(unsignedXdr, passed, name + ": source-account entry was mutated");
        checked++;
        continue;
      }

      // The wrap itself, for vectors that record a pre-wrap entry.
      Object preWrap = vector.get("pre_wrap_entry_xdr");
      if (preWrap instanceof String && !((String) preWrap).isEmpty()) {
        List<Delegate> delegates = toDelegates(Json.array(vector.get("delegates")));
        String wrapped = Soroauth.withDelegates((String) preWrap, validUntil, delegates);
        assertEquals(unsignedXdr, wrapped, name + ": rebuilt delegates differ");
      }

      // The payload hash.
      String wantPayload = Json.string(vector.get("payload_hex"));
      String wantPreimage = Json.string(vector.get("preimage_xdr"));
      assertEquals(
          wantPayload, Soroauth.payloadHex(wantPreimage), name + ": payload differs");
      // And the preimage the JVM rebuilds hashes to the same payload.
      byte[] networkId =
          MessageDigest.getInstance("SHA-256").digest(passphrase.getBytes(StandardCharsets.UTF_8));
      byte[] rebuilt = Xdr.preimageBytes(entry, validUntil, networkId);
      assertEquals(
          wantPayload,
          Soroauth.hex(Soroauth.sha256(rebuilt)),
          name + ": rebuilt preimage hashes differently");

      // The signed entry, after replaying every recorded step.
      String signed = unsignedXdr;
      for (Object stepObject : Json.array(vector.get("steps"))) {
        Map<String, Object> step = Json.object(stepObject);
        String label = Json.string(step.get("signer_label"));
        Object forAddress = step.get("for_address");
        Object multisig = step.get("multisig");
        if (multisig instanceof Map) {
          List<Object> labels = Json.array(Json.object(multisig).get("signer_labels"));
          List<byte[]> seeds = new ArrayList<>();
          for (Object signerLabel : labels) {
            seeds.add(seedForLabel(Json.string(signerLabel)));
          }
          byte[] accountSeed = seedForLabel(label);
          String account = Soroauth.addressOfSeed(accountSeed);
          signed =
              Soroauth.authorizeMultisig(
                  signed,
                  seeds,
                  account,
                  validUntil,
                  passphrase,
                  forAddress instanceof String ? (String) forAddress : null);
        } else {
          signed =
              Soroauth.authorize(
                  signed,
                  seedForLabel(label),
                  validUntil,
                  passphrase,
                  forAddress instanceof String ? (String) forAddress : null);
        }
        // Each step fills its own target: verify it now.
        VerificationReport stepReport = Soroauth.verify(signed, passphrase);
        String target =
            forAddress instanceof String
                ? (String) forAddress
                : Soroauth.addressOfSeed(seedForLabel(label));
        boolean filled = false;
        for (NodeVerdict node : stepReport.nodes()) {
          if (node.address().equals(target)) {
            Verdict want =
                multisig instanceof Map ? Verdict.CANNOT_CHECK : Verdict.VERIFIED;
            assertEquals(want, node.verdict(), name + ": target node " + target + " is " + node.verdict());
            filled = true;
          } else if (node.verdict() == Verdict.INVALID || node.verdict() == Verdict.CANNOT_CHECK) {
            fail(name + ": node " + node.address() + " is " + node.verdict() + " after signing");
          }
        }
        assertTrue(filled, name + ": step target " + target + " names no node");
      }
      assertEquals(Json.string(vector.get("signed_entry_xdr")), signed, name + ": signed entry differs");
      checked++;
    }
    assertTrue(checked > 0, "no vectors were checked; the gate proved nothing");
  }

  private static List<Delegate> toDelegates(List<Object> recorded) {
    List<Delegate> out = new ArrayList<>();
    for (Object node : recorded) {
      Map<String, Object> map = Json.object(node);
      Object nested = map.get("nested");
      out.add(
          new Delegate(
              Json.string(map.get("address")),
              nested instanceof List ? toDelegates(Json.array(nested)) : List.of()));
    }
    return out;
  }

  @Test
  void strkeyRoundTrips() {
    // A vector address, decoded and re-encoded: the bytes name the key.
    String address = "GCZCHOZ7YRWJSP7HKKHF3UBPDQTRDTSNSX2VSLNXIQYTBRDIPW52TOBG";
    byte[] xdr = Xdr.encodeAddress(address);
    assertEquals(40, xdr.length);
    assertEquals(address, Xdr.decodeAddress(xdr));
  }
}
