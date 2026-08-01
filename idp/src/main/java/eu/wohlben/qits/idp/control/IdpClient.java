package eu.wohlben.qits.idp.control;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.List;
import java.util.Map;

/**
 * One client the idp will issue for: its id, its shared secret, the audiences it may ask for, and
 * the structured claims its tokens carry.
 *
 * <p>Phase 1 builds these from config only ({@link IdpClients}). Phase 2's dynamic agent clients
 * become rows in {@code idp_client} and arrive here through the same record.
 *
 * @param secret the configured secret, or {@code null}/blank when none is configured — see {@link
 *     #usable()}
 * @param audiences the {@code aud} values this client may request; a request naming none gets all
 *     of them
 * @param claims granted claims, copied into the token verbatim
 */
public record IdpClient(
    String clientId, String secret, List<String> audiences, Map<String, String> claims) {

  /**
   * Whether this client can authenticate at all.
   *
   * <p><b>A blank secret is unusable, never open.</b> That is the one decision this record makes:
   * a client seeded without a secret — which is how every service client ships — is refused exactly
   * like a wrong secret, so an unconfigured deployment issues nothing rather than issuing to
   * anyone. It is the opposite reading from {@code qits.artifacts.token}, where a blank value means
   * "no guard"; the difference is that a guard with no secret protects a network already trusted,
   * while an issuer with no secret mints identity for whoever asks.
   */
  public boolean usable() {
    return secret != null && !secret.isBlank();
  }

  /**
   * Whether {@code candidate} is this client's secret. False when the client is unusable, so this
   * is never on its own a reason to issue a token.
   *
   * <p>Constant-time, via {@link MessageDigest#isEqual}: the comparison is against a shared secret
   * a caller may retry freely, which is the case byte-by-byte {@code String.equals} leaks.
   */
  public boolean secretMatches(String candidate) {
    if (!usable() || candidate == null) {
      return false;
    }
    return MessageDigest.isEqual(
        secret.getBytes(StandardCharsets.UTF_8), candidate.getBytes(StandardCharsets.UTF_8));
  }
}
