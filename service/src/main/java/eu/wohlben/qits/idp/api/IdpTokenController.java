package eu.wohlben.qits.idp.api;

import eu.wohlben.qits.idp.control.TokenService;
import eu.wohlben.qits.idp.control.TokenService.IssuedToken;
import eu.wohlben.qits.idp.error.OAuthException;
import jakarta.inject.Inject;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.FormParam;
import jakarta.ws.rs.HeaderParam;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * The token endpoint: {@code POST /idp/token}, {@code application/x-www-form-urlencoded}, RFC 6749
 * {@code client_credentials}.
 *
 * <p>This class does the wire work only — pulling the client's credentials out of whichever of the
 * two supported places they arrived in, and dressing the result as a token response. Who the client
 * is and what it may have is {@link TokenService}'s.
 *
 * <p>The path is relative to {@code quarkus.rest.path=/idp}. It is a cross-repo contract: every
 * consumer reaches it through the {@code token_endpoint} of the discovery document, which is
 * derived from the same issuer string, so the three cannot drift apart.
 */
@Path("/token")
public class IdpTokenController {

  private static final String GRANT_CLIENT_CREDENTIALS = "client_credentials";
  private static final String BASIC_PREFIX = "basic ";

  @Inject TokenService tokenService;

  /**
   * Client authentication is {@code client_secret_basic} or {@code client_secret_post}, never both
   * in one request — RFC 6749 §2.3 forbids it, and accepting both would make which one was checked
   * a question.
   *
   * @param audienceParams zero or more {@code audience} values. Repeated parameters and one
   *     whitespace-separated value both work; naming none asks for the client's whole allowed list.
   */
  @POST
  @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
  @Produces(MediaType.APPLICATION_JSON)
  public Response token(
      @HeaderParam(HttpHeaders.AUTHORIZATION) String authorization,
      @FormParam("grant_type") String grantType,
      @FormParam("client_id") String clientIdParam,
      @FormParam("client_secret") String clientSecretParam,
      @FormParam("audience") List<String> audienceParams) {

    if (grantType == null || grantType.isBlank()) {
      throw OAuthException.invalidRequest("grant_type is required");
    }
    if (!GRANT_CLIENT_CREDENTIALS.equals(grantType)) {
      throw OAuthException.unsupportedGrantType("only client_credentials is supported");
    }

    Credentials credentials = credentials(authorization, clientIdParam, clientSecretParam);
    IssuedToken issued =
        tokenService.clientCredentials(
            credentials.clientId(), credentials.secret(), audiences(audienceParams));

    // LinkedHashMap so the response reads in the order RFC 6749 §5.1 lists the members.
    Map<String, Object> body = new LinkedHashMap<>();
    body.put("access_token", issued.accessToken());
    body.put("token_type", "Bearer");
    body.put("expires_in", issued.expiresInSeconds());
    return Response.ok(body)
        // RFC 6749 §5.1: a token response is never cached, anywhere.
        .header(HttpHeaders.CACHE_CONTROL, "no-store")
        .header("Pragma", "no-cache")
        .build();
  }

  private record Credentials(String clientId, String secret) {}

  /**
   * The client's credentials, from the Authorization header or the form — not both, and at least
   * one.
   */
  private static Credentials credentials(
      String authorization, String clientIdParam, String clientSecretParam) {
    Credentials basic = basic(authorization);
    boolean postPresent = clientIdParam != null && !clientIdParam.isBlank();
    if (basic != null && postPresent) {
      throw OAuthException.invalidRequest(
          "client credentials must be presented once, not both in the header and in the form");
    }
    if (basic != null) {
      return basic;
    }
    if (!postPresent) {
      throw OAuthException.invalidClient("client authentication is required");
    }
    return new Credentials(clientIdParam, clientSecretParam);
  }

  /**
   * {@code client_secret_basic}: base64 of {@code id:secret}, both form-urlencoded first (RFC 6749
   * §2.3.1). Decoding them back is what makes a secret with a {@code :} or a {@code +} in it work;
   * a client that did not encode is unaffected, because our ids and generated secrets contain
   * nothing that encodes.
   *
   * <p>Returns null when the header is absent or is not Basic — a malformed Basic header is a
   * refusal, not a fall-through to the form, or a caller could hide a bad header behind good form
   * fields.
   */
  private static Credentials basic(String authorization) {
    if (authorization == null
        || !authorization.toLowerCase(Locale.ROOT).startsWith(BASIC_PREFIX)) {
      return null;
    }
    String decoded;
    try {
      decoded =
          new String(
              Base64.getDecoder().decode(authorization.substring(BASIC_PREFIX.length()).trim()),
              StandardCharsets.UTF_8);
    } catch (IllegalArgumentException e) {
      throw OAuthException.invalidClient("malformed Basic credentials");
    }
    int separator = decoded.indexOf(':');
    if (separator < 0) {
      throw OAuthException.invalidClient("malformed Basic credentials");
    }
    return new Credentials(
        formDecode(decoded.substring(0, separator)), formDecode(decoded.substring(separator + 1)));
  }

  private static String formDecode(String value) {
    try {
      return URLDecoder.decode(value, StandardCharsets.UTF_8.name());
    } catch (UnsupportedEncodingException | IllegalArgumentException e) {
      // A value that is not valid percent-encoding is taken as-is: it is then simply not the
      // configured secret, and the request fails as an authentication failure rather than a 500.
      return value;
    }
  }

  /** Repeated {@code audience} parameters and whitespace-separated values both flatten to here. */
  private static List<String> audiences(List<String> params) {
    if (params == null || params.isEmpty()) {
      return List.of();
    }
    List<String> audiences = new ArrayList<>();
    for (String param : params) {
      if (param == null) {
        continue;
      }
      for (String audience : param.trim().split("\\s+")) {
        if (!audience.isEmpty()) {
          audiences.add(audience);
        }
      }
    }
    return List.copyOf(audiences);
  }
}
