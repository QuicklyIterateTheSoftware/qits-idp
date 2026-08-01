package eu.wohlben.qits.idp.api;

import eu.wohlben.qits.idp.error.OAuthException;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.ExceptionMapper;
import jakarta.ws.rs.ext.Provider;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Maps the domain's framework-free {@link OAuthException}s to the error response RFC 6749 §5.2
 * specifies — kept here in {@code service} because the idp module carries no JAX-RS.
 */
@Provider
public class OAuthExceptionMapper implements ExceptionMapper<OAuthException> {

  @Override
  public Response toResponse(OAuthException exception) {
    Map<String, Object> body = new LinkedHashMap<>();
    body.put("error", exception.error());
    body.put("error_description", exception.getMessage());

    Response.ResponseBuilder response =
        Response.status(exception.statusCode())
            .entity(body)
            .type(MediaType.APPLICATION_JSON)
            .header(HttpHeaders.CACHE_CONTROL, "no-store")
            .header("Pragma", "no-cache");
    if (exception.statusCode() == Response.Status.UNAUTHORIZED.getStatusCode()) {
      // RFC 6749 §5.2 requires the challenge whenever the client tried the Authorization header.
      // It is sent on every 401 rather than only then: the header costs nothing, and deciding
      // per-request would mean the mapper had to know how the credentials arrived.
      response.header(HttpHeaders.WWW_AUTHENTICATE, "Basic realm=\"qits-idp\"");
    }
    return response.build();
  }
}
