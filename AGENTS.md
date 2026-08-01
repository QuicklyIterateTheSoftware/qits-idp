# qits-idp — working notes

Read `README.md` first: it defines the surface, the token's shape, and where clients and keys come
from. This file is the working conventions on top of it.

## The rules that shape everything

**A clone of this repo alone builds and tests green** — no monorepo, no docker, no prior
`mvn install` elsewhere, no credentials, and (unlike every sibling) no node either: this service
serves no client in phase 1, so there is no Quinoa and no webui submodule. `./mvnw verify` is the
gate, and it needs no port argument — `service/src/test/resources/application.properties` sets
`quarkus.http.test-port=0`.

**`service/` compiles to a GraalVM native image.** `.sdkmanrc` names `25.0.2-graalce`. The
consequence to keep in your head here is narrower than in the siblings and more dangerous: this
service's whole job goes through JCA — `KeyPairGenerator`, `KeyFactory`, RS256 signing — and a
native image that lost a provider boots fine and cannot mint. `IdpPackagedSurfaceIT` mints a token
in the packaged process for exactly that reason; run it (`-DskipITs=false`, or `-Dnative`) after
touching anything about keys.

**Never make the safe direction configurable.** A client with a blank secret is unusable. There is
no flag that turns that into "open", and adding one would make an unconfigured deployment issue
identity to whoever asks. `IdpTokenTest.aClientWithNoSecretIsUnusableRatherThanOpen` runs against
`qits-gateway` — a *shipped* client with no secret — rather than a fixture, so the test pins the
real default.

## Package and module conventions

`eu.wohlben.qits.idp.*`, split across maven modules with disjoint sub-packages so there is no split
package:

- `idp/` — `entity`, `persistence`, `control`, `error`. Framework-free in the sense that matters:
  no JAX-RS, no web stack. `control` owns the keys (`SigningKeys`), the JWKS document (`Jwks`), the
  client registry (`IdpClients`), the issuer string (`Issuer`) and the grant (`TokenService`).
- `service/` — `api` only: the two metadata routes, the token endpoint, and the RFC 6749 error
  mapper.

The directories are `idp/` and `service/`; the artifactIds are `qits-idp-domain` and
`qits-idp-service` — generic coordinates would collide in a shared `~/.m2`.

## Addressing

`quarkus.rest.path=/idp`, **not** `/idp/api`. That is the one place this repo departs from the
sibling services, and it is not cosmetic: an OIDC consumer configured with auth-server-url
`http://qits-idp:8080/idp` fetches `/idp/.well-known/openid-configuration` by its own derivation and
follows the document from there. An `/api` segment would move the discovery document off the path
every OIDC client computes. Phase 2's registration API takes `@Path("/api/clients")` relative to
this, which keeps the machine-admin surface separate without moving the protocol.

The issuer string is spelled **once**, in `qits.idp.issuer`, and `Issuer` normalises it. The
discovery document's `token_endpoint` and `jwks_uri` are derived from it, and so is every token's
`iss`. Never configure an endpoint separately: a consumer rejects a token whose `iss` differs from
the discovery document's `issuer` by one character, and two config keys is how that character
appears.

## Untrusted input

`client_id` arrives on an unauthenticated request and is concatenated into a config key.
`IdpClients.find` checks membership in `qits.idp.clients` **before** it builds any key, which is
what keeps a caller from probing the config namespace. Keep that order.

Secrets are compared with `MessageDigest.isEqual`, never `String.equals` — the comparison is against
a value a caller may retry freely.

Client ids reach the log on a refusal, so `TokenService.loggable` bounds what can be written there.

## Schema changes

`idp/src/main/resources/db/idp/migration/`, hand-written, its own lineage on its own datasource —
keep appending, never edit an applied migration.

Two things about the shipped V1:

- `idp_signing_key` is shaped so **rotation is a data change**. Many rows, one `ACTIVE`, all
  published. Do not add a "one active key" constraint; H2 has no partial unique index and the reader
  already resolves the newest active row.
- `idp_client` is **empty on purpose** — phase 2's dynamic agent clients. Nothing reads it yet.
  Deleting it because it is unused would put a migration against a live database into the phase that
  adds the endpoint.

## Adding a dependency on another context

Don't. This context has no compile-time dependency on any other qits module and must not grow one —
least of all on a service it issues tokens for. Everything it knows arrives as config.

## Tests

- App-level config lives in `service/src/main/resources/application.properties` and Quarkus merges
  it into the test config. **Never re-declare an app-level setting in test resources.** The suite's
  copy re-declares exactly one — `qits.idp.clients`, because a test client cannot be added without
  restating the list — and says so where it does.
- **Tokens are verified against `GET /idp/jwks`, over HTTP, never against a key reachable
  in-process** (`PublishedJwks`). Verifying in-process would pass with an empty, wrong, or
  private-key-leaking JWKS, and the JWKS is the only thing a real consumer sees.
- `SigningKeyPersistenceTest` exercises the restart seam the suite cannot actually restart:
  `SigningKeys.reload()` drops the cache and goes back to the database. A generate-on-every-load
  regression changes the `kid` there.
- `IdpPackagedSurfaceIT` runs the **packaged artifact** and asserts what a native build can silently
  lose: the build-time route prefixes, the shipped `${user.home}`-rooted H2 default (it relocates
  `user.home` rather than restating the URL), Flyway's migration surviving as a resource, and RSA
  key generation plus signing in the packaged process.
