package eu.wohlben.qits.idp.entity;

import io.quarkus.hibernate.orm.panache.PanacheEntityBase;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;

/**
 * One RSA signing keypair, keyed by the {@code kid} its tokens carry.
 *
 * <p>This row is the reason a restart does not invalidate anything: the keypair is generated once,
 * on the first start that finds no {@code ACTIVE} row, and read back from here on every start
 * after that. Losing this table (or pointing the idp at a fresh database) rotates the key by
 * accident, and every token in flight stops verifying.
 *
 * <p>Many rows may exist. The newest {@code ACTIVE} one signs; every row is published in the JWKS.
 */
@Entity
@Table(name = "idp_signing_key")
public class IdpSigningKey extends PanacheEntityBase {

  /** The {@code kid} JWS header of every token this key signs — random, and the row's identity. */
  @Id
  @Column(name = "kid", length = 64)
  public String kid;

  /** The JWS algorithm this key signs with. {@code RS256} is the only value phase 1 writes. */
  @Column(nullable = false, length = 16)
  public String algorithm;

  @Enumerated(EnumType.STRING)
  @Column(nullable = false, length = 16)
  public IdpSigningKeyStatus status;

  /** PKCS#8, PEM-wrapped. Never leaves this process. */
  @Column(name = "private_key_pem", nullable = false)
  public String privateKeyPem;

  /**
   * X.509 SubjectPublicKeyInfo, PEM-wrapped. Stored rather than derived from the private half so
   * building the JWKS never has to unwrap a private key.
   */
  @Column(name = "public_key_pem", nullable = false)
  public String publicKeyPem;

  @Column(name = "created_at", nullable = false)
  public Instant createdAt;

  /** Set when the key stops signing. Null while {@link IdpSigningKeyStatus#ACTIVE}. */
  @Column(name = "retired_at")
  public Instant retiredAt;
}
