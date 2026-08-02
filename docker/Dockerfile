# qits-idp as a GraalVM-native container IMAGE — the same shape as its siblings' docker/Dockerfile:
# a Mandrel builder stage compiles the binary, a minimal runtime stage carries only it.
#
# This file is not how the binary is built; it is how the binary is SHIPPED. `.sdkmanrc` names a
# GraalVM (25.0.2-graalce), so `sdk env && ./mvnw package -Dnative` produces
# `service/target/qits-idp` with no container involved.
#
# Build from the repo root:
#
#     docker build -t qits/idp:latest -f docker/Dockerfile .
#
# There is no client to build first and no npm anywhere: phase 1 of this service serves two JSON
# documents and a token endpoint. That is the one way this Dockerfile is shorter than its siblings'.
#
# --- this image does NOT run with an empty environment, and that is not a packaging bug ------------
# `docker run --rm qits/idp:latest` dies before the HTTP listener: uid 1001 has no /etc/passwd entry
# in ubi-minimal, a native image resolves user.home through getpwuid(2) rather than $HOME, and the
# ${user.home}-rooted H2 default the `idp` jar ships has nowhere to land. IT IS DELIBERATELY LEFT
# THAT WAY (the qits-ci/qits-cd stance), and here the stake is higher than for any sibling:
#
#   THE SIGNING KEY LIVES IN THAT DATABASE. An idp that comes up healthy on an empty environment
#   writes its keypair into the container's own writable layer, and the next redeploy generates a
#   new one — invalidating every token in flight, everywhere, with nothing in any log to say why.
#   A container that refuses to start is the failure you see; one that starts on ephemeral storage
#   is the failure that hides for a week.
#
# So a deployment mounts a volume at /data (which this image owns, see below) and names the
# database:
#
#   docker run -v qits-idp-data:/data \
#     -e QUARKUS_DATASOURCE_IDP_JDBC_URL=jdbc:h2:file:/data/idp/h2/idp \
#     -e QITS_IDP_CLIENT_QITS_CI_SECRET=... \
#     ...
#
# --- what else a deployment owns ------------------------------------------------------------------
#
#   QITS_IDP_CLIENT_<ID>_SECRET
#                           EVERY STATIC CLIENT SHIPS WITHOUT A SECRET AND IS THEREFORE UNUSABLE.
#                           That is the safe direction — a blank secret is refused, never accepted —
#                           but it also means an idp nobody configured issues nothing at all, and
#                           the only symptom is `invalid_client` in the caller's log. The client ids
#                           are the service names: qits-ci, qits-cd, qits-artifacts, qits-workspaces,
#                           qits-gateway.
#   QITS_IDP_ISSUER         the `iss` of every token and the base of every advertised endpoint.
#                           Defaults to http://qits-idp:8080/idp, which is what consumers on qits-net
#                           use. Change it and EVERY consumer's configured issuer must change with
#                           it; a mismatch is rejected at validation.
#   QITS_OBSERVABILITY_URL  where OTLP export goes; absent qits-observability, the exporter logs a
#                           warning per export loudly enough to bury real lines
#                           (OTEL_SDK_DISABLED=true is the escape hatch).
#
# This image needs no docker socket, no git, and no network access to anything but the callers that
# dial it. It talks to nothing.
#
# --- stage `build`: native-compile ----------------------------------------------------------------
# The builder JDK MUST be 25: native-image cannot read bytecode newer than its own JDK, and this
# project targets release 25.
FROM quay.io/quarkus/ubi9-quarkus-mandrel-builder-image:jdk-25 AS build
USER root
WORKDIR /src

# Fetch the Maven distribution first, keyed only on the wrapper files, so a source-only change does
# not re-download it.
COPY mvnw .
COPY .mvn/ .mvn/
RUN ./mvnw --version

# The whole reactor, not a module list. `-am` builds `service`'s dependency from source —
# `qits-idp-domain` is a 1.0.0-SNAPSHOT this repo never publishes, so a builder container with an
# empty ~/.m2 has nowhere else to get it. `.dockerignore` is what keeps this cheap.
COPY . .

# Tests are skipped because `./mvnw verify` on a clone is their gate (AGENTS.md); stopping at
# `package` rather than `verify` keeps IdpPackagedSurfaceIT out of the image build. Cap
# native-image RAM so the build is deterministic on small machines.
RUN ./mvnw -B -ntp -pl service -am package -Dnative -DskipTests \
      -Dquarkus.native.native-image-xmx=4g

# --- runtime --------------------------------------------------------------------------------------
FROM registry.access.redhat.com/ubi9/ubi-minimal:9.6
WORKDIR /work

# curl, so the container answers a docker healthcheck — qits-cd injects one at `docker run` and
# polls it through `docker inspect`, and the probe runs INSIDE the container.
RUN curl --version >/dev/null

# `quarkus.package.output-name` names the binary `qits-idp` (no -runner suffix), so the process is
# identifiable in `ps`/`docker top`. That name is spelled a third time in service/pom.xml as
# failsafe's `native.image.path`; all three move together.
COPY --from=build --chown=1001:root /src/service/target/qits-idp /work/qits-idp
RUN chmod +x /work/qits-idp

# The mount point for the H2 url, created here so it is OWNED. Docker seeds a fresh named volume
# from whatever the image has at the mount path, ownership included; with no such directory it
# makes one root-owned 0755, and the boot then dies on an AccessDeniedException rather than on the
# config error the header documents. Group-writable and group-root because a ubi image is meant to
# survive being assigned an arbitrary UID with GID 0.
RUN mkdir -p /data/idp && chown -R 1001:root /data && chmod -R 775 /data

EXPOSE 8080
USER 1001

# Quarkus binds 127.0.0.1 outside dev mode, which inside a container means nothing can reach it —
# not the gateway, not a peer on qits-net.
ENTRYPOINT ["/work/qits-idp", "-Dquarkus.http.host=0.0.0.0"]
