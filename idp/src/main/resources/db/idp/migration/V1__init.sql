-- The idp schema. Two tables, and one of them is empty by design.

-- The signing keys. ROTATION IS A DATA CHANGE, not a schema change, and this table is shaped for
-- it: many rows may exist, the newest ACTIVE one signs, and every row is published in the JWKS so
-- a token minted before a rotation still verifies until it expires. A rotation is therefore
-- "insert a new ACTIVE row, set the old one RETIRED"; a cleanup is "delete RETIRED rows whose keys
-- can no longer have live tokens". Nothing here has to change for that to work.
--
-- There is deliberately NO unique constraint on "exactly one ACTIVE": H2 has no partial unique
-- index, and the reader already resolves the newest ACTIVE row, so a second one is a harmless
-- overlap rather than a boot failure. The private key is PKCS#8 PEM and the public key is X.509
-- SubjectPublicKeyInfo PEM — the public half is stored rather than derived so the JWKS can be
-- built without unwrapping the private key.
create table idp_signing_key (
    kid varchar(64) not null primary key,
    algorithm varchar(16) not null,
    status varchar(16) not null check (status in ('ACTIVE', 'RETIRED')),
    private_key_pem clob not null,
    public_key_pem clob not null,
    created_at timestamp(6) with time zone not null,
    retired_at timestamp(6) with time zone
);

create index idx_idp_signing_key_status on idp_signing_key (status, created_at);

-- Dynamic clients — PHASE 2, and empty until then. It exists now so the phase that adds
-- POST/DELETE /idp/api/clients is an endpoint plus a repository and not a migration against a
-- live database. Nothing reads it yet; the static service clients are config, not rows
-- (see the idp jar's META-INF/microprofile-config.properties).
--
-- lease_expires_at is the lease: a registrar asks for a TTL, the row carries the deadline, and
-- expired rows are collected — an orphaned agent loses access with no cleanup code on the
-- registrar's side. registered_by names the static client that minted this one, which is what the
-- granting-template check is audited against.
create table idp_client (
    client_id varchar(128) not null primary key,
    secret_hash varchar(255) not null,
    audiences varchar(1024) not null,
    claims clob,
    registered_by varchar(128),
    lease_expires_at timestamp(6) with time zone,
    created_at timestamp(6) with time zone not null
);

create index idx_idp_client_lease_expires_at on idp_client (lease_expires_at);
