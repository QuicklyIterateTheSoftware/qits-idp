package eu.wohlben.qits.idp.persistence;

import eu.wohlben.qits.idp.entity.IdpSigningKey;
import io.quarkus.hibernate.orm.panache.PanacheRepositoryBase;
import jakarta.enterprise.context.ApplicationScoped;
import java.util.List;

/** Panache DAO for {@link IdpSigningKey} (keyed by its {@code kid}). */
@ApplicationScoped
public class IdpSigningKeyRepository implements PanacheRepositoryBase<IdpSigningKey, String> {

  /**
   * Every stored key, newest first. The signer is the first {@code ACTIVE} entry; the whole list is
   * what the JWKS publishes.
   */
  public List<IdpSigningKey> listNewestFirst() {
    return list("order by createdAt desc, kid desc");
  }
}
