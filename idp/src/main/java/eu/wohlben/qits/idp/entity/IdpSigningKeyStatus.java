package eu.wohlben.qits.idp.entity;

/**
 * Whether a stored key still signs.
 *
 * <p>The two states are what makes rotation a data change: an {@code ACTIVE} key signs new tokens,
 * a {@code RETIRED} one only still verifies old ones. Both are published in the JWKS, because a
 * token minted a second before a rotation must stay valid until it expires.
 */
public enum IdpSigningKeyStatus {
  ACTIVE,
  RETIRED
}
