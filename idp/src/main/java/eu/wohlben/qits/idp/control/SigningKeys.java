package eu.wohlben.qits.idp.control;

import eu.wohlben.qits.idp.entity.IdpSigningKey;
import eu.wohlben.qits.idp.entity.IdpSigningKeyStatus;
import eu.wohlben.qits.idp.persistence.IdpSigningKeyRepository;
import io.quarkus.narayana.jta.QuarkusTransaction;
import io.quarkus.runtime.StartupEvent;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;
import jakarta.inject.Inject;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.jboss.logging.Logger;

/**
 * The signing keys, generated once and read from the database ever after.
 *
 * <p>This is the whole of "validation survives a restart": the first start that finds no {@code
 * ACTIVE} row generates a keypair and persists it; every start after that loads the same one, so
 * the {@code kid} in a token issued yesterday still resolves against today's JWKS.
 *
 * <p>Rotation needs no code here. Insert a second {@code ACTIVE} row and retire the first, and
 * {@link #reload()} picks the new signer up while the old key keeps being published — which is why
 * the reload is public API rather than a test hook.
 */
@ApplicationScoped
public class SigningKeys {

  private static final Logger LOG = Logger.getLogger(SigningKeys.class);

  /** The only JWS algorithm this service signs with, and the {@code alg} of every published JWK. */
  public static final String ALGORITHM = "RS256";

  /**
   * One usable key: the {@code kid} its tokens carry, the private half that signs, and the public
   * half the JWKS publishes.
   */
  public record SigningKey(
      String kid,
      String algorithm,
      RSAPrivateKey privateKey,
      RSAPublicKey publicKey,
      boolean active) {}

  /** What one load produced: the signer, and everything to publish (the signer included). */
  public record KeySet(SigningKey signing, List<SigningKey> published) {}

  @Inject IdpSigningKeyRepository repository;

  @ConfigProperty(name = "qits.idp.signing-key-bits")
  int keyBits;

  private volatile KeySet cached;

  /**
   * Generate-or-load at boot, so a first start fails loudly on an unwritable database rather than
   * on the first token request.
   */
  void onStart(@Observes StartupEvent event) {
    KeySet keys = reload();
    LOG.infof(
        "idp signing key %s active, %d key(s) published", keys.signing().kid(), keys.published().size());
  }

  /** The key new tokens are signed with. */
  public SigningKey signing() {
    return keys().signing();
  }

  /** Every key the JWKS publishes — the signer plus any retired key whose tokens may still live. */
  public List<SigningKey> published() {
    return keys().published();
  }

  /**
   * Re-read the keys from the database, generating one only if there is no active key at all.
   * Synchronized so two callers on a cold cache cannot both generate.
   */
  public synchronized KeySet reload() {
    KeySet next = QuarkusTransaction.requiringNew().call(this::loadOrCreate);
    cached = next;
    return next;
  }

  private KeySet keys() {
    KeySet local = cached;
    return local != null ? local : reload();
  }

  /** Runs inside the transaction: the rows are turned into keys before the session closes. */
  private KeySet loadOrCreate() {
    List<IdpSigningKey> rows = repository.listNewestFirst();
    if (rows.stream().noneMatch(row -> row.status == IdpSigningKeyStatus.ACTIVE)) {
      repository.persist(generate());
      repository.flush();
      rows = repository.listNewestFirst();
    }
    List<SigningKey> published = rows.stream().map(SigningKeys::toKey).toList();
    SigningKey signing =
        published.stream()
            .filter(SigningKey::active)
            .findFirst()
            .orElseThrow(() -> new IllegalStateException("no active signing key after load"));
    return new KeySet(signing, published);
  }

  private IdpSigningKey generate() {
    KeyPair pair;
    try {
      KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
      generator.initialize(keyBits);
      pair = generator.generateKeyPair();
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException("cannot generate an RSA signing key", e);
    }
    IdpSigningKey row = new IdpSigningKey();
    row.kid = randomKid();
    row.algorithm = ALGORITHM;
    row.status = IdpSigningKeyStatus.ACTIVE;
    row.privateKeyPem = Pem.wrap("PRIVATE KEY", pair.getPrivate().getEncoded());
    row.publicKeyPem = Pem.wrap("PUBLIC KEY", pair.getPublic().getEncoded());
    row.createdAt = Instant.now();
    return row;
  }

  private static SigningKey toKey(IdpSigningKey row) {
    try {
      KeyFactory factory = KeyFactory.getInstance("RSA");
      RSAPrivateKey privateKey =
          (RSAPrivateKey)
              factory.generatePrivate(new PKCS8EncodedKeySpec(Pem.unwrap(row.privateKeyPem)));
      RSAPublicKey publicKey =
          (RSAPublicKey) factory.generatePublic(new X509EncodedKeySpec(Pem.unwrap(row.publicKeyPem)));
      return new SigningKey(
          row.kid,
          row.algorithm,
          privateKey,
          publicKey,
          row.status == IdpSigningKeyStatus.ACTIVE);
    } catch (GeneralSecurityException | IllegalArgumentException e) {
      throw new IllegalStateException("stored signing key " + row.kid + " is unreadable", e);
    }
  }

  /** 128 random bits, base64url. Opaque on purpose: a kid names a key and says nothing else. */
  private static String randomKid() {
    byte[] bytes = new byte[16];
    new SecureRandom().nextBytes(bytes);
    return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
  }
}
