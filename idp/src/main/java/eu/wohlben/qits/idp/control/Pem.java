package eu.wohlben.qits.idp.control;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * PEM wrapping, the only encoding decision in the key store: DER bytes go into the database as
 * text, so a row can be read and moved by hand.
 */
final class Pem {

  private static final int LINE_LENGTH = 64;

  private Pem() {}

  /** {@code type} is the label between the dashes — {@code PRIVATE KEY}, {@code PUBLIC KEY}. */
  static String wrap(String type, byte[] der) {
    String body = Base64.getEncoder().encodeToString(der);
    StringBuilder pem = new StringBuilder("-----BEGIN ").append(type).append("-----\n");
    for (int start = 0; start < body.length(); start += LINE_LENGTH) {
      pem.append(body, start, Math.min(start + LINE_LENGTH, body.length())).append('\n');
    }
    return pem.append("-----END ").append(type).append("-----\n").toString();
  }

  /** The inverse: everything that is not base64 payload is dropped, header line included. */
  static byte[] unwrap(String pem) {
    StringBuilder body = new StringBuilder();
    for (String line : pem.split("\\R")) {
      String trimmed = line.trim();
      if (!trimmed.isEmpty() && !trimmed.startsWith("-----")) {
        body.append(trimmed);
      }
    }
    return Base64.getDecoder().decode(body.toString().getBytes(StandardCharsets.US_ASCII));
  }
}
