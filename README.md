# qits-idp

The platform's own identity provider. Phase 1 — this tree — is **machine identity only**: an RS256
signing key that survives restarts, a JWKS, an OIDC discovery document, and a `client_credentials`
token endpoint the platform's services authenticate to each other with.

There is no user, no login and no session here. Browser sessions stay at qits-gateway, which keeps
forwarding `X-Qits-User`; this service becomes the auth server that gateway points at in phase 3.

## The surface

Everything is served under `/idp`, the segment qits-gateway routes verbatim.

| path | what it is |
|---|---|
| `GET /idp/.well-known/openid-configuration` | discovery. An OIDC consumer configured with auth-server-url `http://qits-idp:8080/idp` derives this URL itself. |
| `GET /idp/jwks` | the public signing keys, each with its `kid`. |
| `POST /idp/token` | `application/x-www-form-urlencoded`, `grant_type=client_credentials`. |
| `GET /idp/q/health/ready` | readiness, where the deployment convention expects it. |

A token request authenticates with `client_secret_basic` **or** `client_secret_post`, never both,
and may name an `audience` (repeated or whitespace-separated). Naming none asks for every audience
the client is allowed.

    curl -s -X POST http://qits-idp:8080/idp/token \
      -d grant_type=client_credentials \
      -d client_id=qits-ci -d client_secret=... \
      -d audience=qits-cd

The token is RS256, carries a `kid`, and says:

| claim | value |
|---|---|
| `iss` | `qits.idp.issuer` |
| `sub` | the client id |
| `aud` | the resolved audiences, always a JSON array |
| `iat`, `exp`, `jti` | issued now, valid for `qits.idp.token-ttl-seconds` (300 by default) |
| `project`, `workspace`, `branch` | only when granted to the client, copied verbatim |

**Claims, not scopes.** `aud` names the service a token may be used at; the structured claims name
what it may be used for *within* that service. The idp states them and interprets nothing — a
resource service decides what a value permits, including whether `*` means "any".

Refusals are RFC 6749 §5.2: `invalid_client` (401, with a `WWW-Authenticate` challenge),
`invalid_request` / `unsupported_grant_type` / `invalid_target` (400).

## Clients

Phase 1 clients are config, not rows. `qits.idp.clients` lists the ids that exist; each one has
`qits.idp.client.<id>.secret`, `.audiences`, and `.claims.<name>`. The shipped list is the platform's
service names — `qits-ci`, `qits-cd`, `qits-artifacts`, `qits-workspaces`, `qits-gateway` — and the
full key reference is in `idp/src/main/resources/META-INF/microprofile-config.properties`.

**No secret ships with any of them, and a client with a blank secret is unusable rather than open.**
An unconfigured deployment therefore issues nothing; `QITS_IDP_CLIENT_QITS_CI_SECRET=…` is what
turns a client on. This is the opposite reading from `qits.artifacts.token`, where a blank value
means "no guard" — the difference is that a guard with no secret protects a network that is already
trusted, while an issuer with no secret would mint identity for whoever asks.

## The signing key

Generated on the first start that finds no active key, and stored in the `idp` datasource as PKCS#8
PEM with a random `kid`. Every start after that reads it back. **That row is the only reason a token
issued before a restart still verifies after one** — an idp pointed at a fresh or ephemeral database
rotates its key by accident and invalidates everything in flight.

The table holds many keys with one active, so rotation is a data change: insert a new `ACTIVE` row,
retire the old one, and both keep being published until the old one's tokens have expired.
`SigningKeys.reload()` is what picks the change up.

## Building and running

`./mvnw verify` on a clone is the gate — no monorepo, no docker, no prior install, no node. The
suite takes a free port (`service/src/test/resources/application.properties` sets
`quarkus.http.test-port=0`), because on the deployment host 8081 is the platform's npm registry.

    ./mvnw verify                    # the @QuarkusTest suite
    ./mvnw verify -DskipITs=false    # plus IdpPackagedSurfaceIT, against the fast-jar
    ./mvnw verify -Dnative           # plus the same IT, against the GraalVM binary

`docker/Dockerfile` ships the native binary. Read its header before deploying: the container refuses
to boot without `QUARKUS_DATASOURCE_IDP_JDBC_URL` pointing at a mounted volume, and that is
deliberate.

## What is not here yet

Phase 2 adds dynamic clients for agents — `POST/DELETE /idp/api/clients`, a lease TTL, and a
granting template on the registrar's record. The `idp_client` table already exists for it and is
empty. Phase 3 adds users, invites, and the authorization-code flow. See `qits-idp-plan.md` in the
qits superproject.
