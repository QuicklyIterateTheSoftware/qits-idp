package eu.wohlben.qits.idp.control;

import eu.wohlben.qits.idp.control.SigningKeys.SigningKey;
import java.math.BigInteger;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The JWKS document: every published key as a public RSA JWK.
 *
 * <p>A consumer picks a key by {@code kid}, which is why every token carries one and why retired
 * keys stay in the set until the tokens they signed have expired.
 */
public final class Jwks {

  private Jwks() {}

  /** The {@code {"keys": [...]}} document, signer first. */
  public static Map<String, Object> document(List<SigningKey> keys) {
    return Map.of("keys", keys.stream().map(Jwks::jwk).toList());
  }

  private static Map<String, Object> jwk(SigningKey key) {
    // LinkedHashMap, not Map.of: a JWKS is read by people as often as by machines, and the member
    // order is the only thing that makes it scannable.
    Map<String, Object> jwk = new LinkedHashMap<>();
    jwk.put("kty", "RSA");
    jwk.put("use", "sig");
    jwk.put("alg", key.algorithm());
    jwk.put("kid", key.kid());
    jwk.put("n", base64Url(key.publicKey().getModulus()));
    jwk.put("e", base64Url(key.publicKey().getPublicExponent()));
    return jwk;
  }

  /**
   * Base64url of the unsigned big-endian value. {@link BigInteger#toByteArray()} prefixes a zero
   * byte whenever the top bit is set — leave it in and every consumer computes a different modulus
   * than the one that signed.
   */
  private static String base64Url(BigInteger value) {
    byte[] bytes = value.toByteArray();
    int start = 0;
    while (start < bytes.length - 1 && bytes[start] == 0) {
      start++;
    }
    byte[] unsigned = new byte[bytes.length - start];
    System.arraycopy(bytes, start, unsigned, 0, unsigned.length);
    return Base64.getUrlEncoder().withoutPadding().encodeToString(unsigned);
  }
}
