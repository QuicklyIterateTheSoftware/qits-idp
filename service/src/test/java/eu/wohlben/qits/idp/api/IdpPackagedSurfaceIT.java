package eu.wohlben.qits.idp.api;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.quarkus.test.junit.QuarkusIntegrationTest;
import io.quarkus.test.junit.QuarkusTestProfile;
import io.quarkus.test.junit.TestProfile;
import io.restassured.http.ContentType;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * The whole service as it is <b>packaged</b> — the fast-jar under {@code mvn verify
 * -DskipITs=false}, the GraalVM binary under {@code mvn verify -Dnative}. The assertions are chosen
 * for what a native build can silently lose rather than for API coverage (that is the
 * {@code @QuarkusTest} suite's job):
 *
 * <ul>
 *   <li>the routes are where the config says — {@code quarkus.rest.path} and {@code
 *       quarkus.http.non-application-root-path} are build-time settings baked into the artifact,
 *       and an OIDC consumer derives the discovery URL from the first of them;
 *   <li>the shipped datasource default connects and {@code db/idp/migration/} survived as a
 *       resource — migrations are loaded by scanning a classpath location, exactly the shape
 *       native-image drops;
 *   <li><b>RSA key generation works in the packaged process.</b> Key generation, PKCS#8 encoding
 *       and RS256 signing all go through JCA providers, which is the other thing a native image
 *       can lose. A service that boots and then cannot mint is the failure this catches.
 * </ul>
 */
@QuarkusIntegrationTest
@TestProfile(IdpPackagedSurfaceIT.PackagedUnderTarget.class)
public class IdpPackagedSurfaceIT {

  private static final String SECRET = "packaged-it-secret";

  /**
   * Relocates the launched artifact's state under {@code target/} by moving {@code user.home}, not
   * by restating the settings — the idp jar's datasource default is {@code ${user.home}}-rooted, so
   * overriding {@code user.home} leaves the <b>shipped</b> JDBC URL itself under test.
   *
   * <p>The secret is an override for the same reason the shipped config has none: a client with no
   * secret is unusable, so the packaged process can only be asked to mint once a deployment (here,
   * this profile) gives it one.
   */
  public static class PackagedUnderTarget implements QuarkusTestProfile {
    static final Path HOME = Path.of("target", "idp-packaged-it-home").toAbsolutePath();

    @Override
    public Map<String, String> getConfigOverrides() {
      deleteRecursively(HOME);
      return Map.of(
          "user.home", HOME.toString(),
          "qits.idp.client.prod-qits-workspaces.secret", SECRET);
    }
  }

  @Test
  public void theDiscoveryDocumentIsWhereAnOidcConsumerLooksForIt() {
    // auth-server-url http://qits-platform-idp:8080/idp + OIDC's own derivation = this path. It
    // is a build-time route prefix, so the artifact is the only place it can be proven.
    given()
        .when()
        .get("/idp/.well-known/openid-configuration")
        .then()
        .statusCode(200)
        .body("issuer", equalTo("http://qits-platform-idp:8080/idp"))
        .body("jwks_uri", equalTo("http://qits-platform-idp:8080/idp/jwks"));

    // prod-qits-gateway routes verbatim by prefix, so there is no unprefixed form to fall back to.
    given().when().get("/.well-known/openid-configuration").then().statusCode(404);
  }

  @Test
  public void theReadinessEndpointIsWhereTheDeploymentLooksForIt() {
    given()
        .when()
        .get("/idp/q/health/ready")
        .then()
        .statusCode(200)
        .body("status", equalTo("UP"));
  }

  @Test
  public void thePackagedProcessGeneratesAKeyIntoTheShippedDatabaseAndSignsWithIt()
      throws Exception {
    String token =
        given()
            .contentType(ContentType.URLENC)
            .body(
                "grant_type=client_credentials&client_id=prod-qits-workspaces&client_secret="
                    + SECRET
                    + "&audience=qits-platform-artifacts")
            .when()
            .post("/idp/token")
            .then()
            .statusCode(200)
            .extract()
            .path("access_token");

    assertNotNull(PublishedJwks.kidOf(token), "the kid header must survive the packaging");
    assertEquals(
        "prod-qits-workspaces",
        PublishedJwks.verify(token, "qits-platform-artifacts").getSubject());

    // The round trip above would look identical against an in-memory database, so pin that the
    // process really opened the ${user.home}-rooted file H2 the idp jar ships — the file the
    // signing key has to outlive a restart in.
    assertTrue(
        Files.isDirectory(PackagedUnderTarget.HOME.resolve(".qits/data/idp/h2")),
        "the shipped file-H2 default must be what the packaged process opened");
  }

  @Test
  public void anUnconfiguredClientStillCannotAuthenticate() {
    // Only prod-qits-workspaces was given a secret above. The other three ship without one and
    // must stay unusable in the packaged artifact too.
    given()
        .contentType(ContentType.URLENC)
        .body("grant_type=client_credentials&client_id=prod-qits-ci&client_secret=" + SECRET)
        .when()
        .post("/idp/token")
        .then()
        .statusCode(401)
        .body("error", equalTo("invalid_client"));
  }

  private static void deleteRecursively(Path root) {
    if (!Files.exists(root)) {
      return;
    }
    try (var walk = Files.walk(root)) {
      walk.sorted(Comparator.reverseOrder()).forEach(p -> p.toFile().delete());
    } catch (Exception e) {
      throw new IllegalStateException("could not clear " + root, e);
    }
  }
}
