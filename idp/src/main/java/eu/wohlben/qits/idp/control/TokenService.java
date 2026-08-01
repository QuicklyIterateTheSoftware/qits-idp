package eu.wohlben.qits.idp.control;

import eu.wohlben.qits.idp.control.SigningKeys.SigningKey;
import eu.wohlben.qits.idp.error.OAuthException;
import io.smallrye.jwt.build.Jwt;
import io.smallrye.jwt.build.JwtClaimsBuilder;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.time.Instant;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.jboss.logging.Logger;

/**
 * The {@code client_credentials} grant: authenticate a client, resolve the audiences it may have,
 * and mint an RS256 JWT.
 *
 * <p>The token says who the caller is and what it may be used against. It says nothing about what
 * the caller may do — that decision belongs to the resource service, helped by the shared
 * enforcement library.
 */
@ApplicationScoped
public class TokenService {

  private static final Logger LOG = Logger.getLogger(TokenService.class);

  /** What a caller gets back, before it is dressed as an RFC 6749 token response. */
  public record IssuedToken(String accessToken, long expiresInSeconds, List<String> audiences) {}

  /** Client ids that may go into a log line verbatim. Anything else is an attacker's string. */
  private static final Pattern LOGGABLE_ID = Pattern.compile("[A-Za-z0-9._-]{1,128}");

  @Inject Issuer issuer;

  @ConfigProperty(name = "qits.idp.token-ttl-seconds")
  long tokenTtlSeconds;

  @Inject SigningKeys signingKeys;

  @Inject IdpClients clients;

  /**
   * Authenticate and mint.
   *
   * @param requestedAudiences the {@code audience} values the request asked for; empty means "all
   *     of the client's own"
   * @throws OAuthException {@code invalid_client} (401) when authentication fails, {@code
   *     invalid_target} (400) when an audience is not this client's to ask for
   */
  public IssuedToken clientCredentials(
      String clientId, String secret, List<String> requestedAudiences) {
    IdpClient client = clients.find(clientId).orElse(null);
    // One refusal for three causes — unknown id, no secret configured, wrong secret. The caller
    // learns only that it did not authenticate; the log line below is where the difference lives.
    if (client == null || !client.secretMatches(secret)) {
      LOG.warnf(
          "token request refused for client %s: %s",
          loggable(clientId),
          client == null
              ? "unknown client"
              : (client.usable() ? "wrong secret" : "no secret configured"));
      throw OAuthException.invalidClient("client authentication failed");
    }

    List<String> audiences = resolveAudiences(client, requestedAudiences);
    Instant now = Instant.now();
    SigningKey key = signingKeys.signing();

    JwtClaimsBuilder token =
        Jwt.claims()
            .issuer(issuer.url())
            .subject(client.clientId())
            // A Set, so `aud` is always a JSON array — one shape for consumers to read whether the
            // token names one audience or four.
            .audience(new LinkedHashSet<>(audiences))
            .issuedAt(now)
            .expiresAt(now.plusSeconds(tokenTtlSeconds));
    // The granted claims, verbatim. The idp does not interpret these values.
    client.claims().forEach(token::claim);

    String jwt = token.jws().keyId(key.kid()).sign(key.privateKey());
    return new IssuedToken(jwt, tokenTtlSeconds, audiences);
  }

  /**
   * The {@code aud} of the token: what was asked for, or the client's whole allowed list when
   * nothing was asked for.
   */
  private List<String> resolveAudiences(IdpClient client, List<String> requested) {
    List<String> allowed = client.audiences();
    if (allowed.isEmpty()) {
      LOG.warnf("token request refused for client %s: no audiences configured", loggable(client.clientId()));
      throw OAuthException.invalidTarget("this client may request no audience");
    }
    if (requested.isEmpty()) {
      return allowed;
    }
    Set<String> resolved = new LinkedHashSet<>();
    for (String audience : requested) {
      if (!allowed.contains(audience)) {
        LOG.warnf(
            "token request refused for client %s: audience not allowed", loggable(client.clientId()));
        throw OAuthException.invalidTarget("audience is not allowed for this client");
      }
      resolved.add(audience);
    }
    return List.copyOf(resolved);
  }

  private static String loggable(String clientId) {
    return clientId != null && LOGGABLE_ID.matcher(clientId).matches() ? clientId : "<malformed>";
  }
}
