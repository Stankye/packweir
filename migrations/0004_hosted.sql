CREATE TABLE hosted_stages (
    id UUID PRIMARY KEY,
    repository TEXT NOT NULL,
    package_name TEXT NOT NULL,
    version TEXT NOT NULL,
    package JSONB NOT NULL,
    owner TEXT NOT NULL CHECK (length(owner) BETWEEN 1 AND 128),
    state TEXT NOT NULL DEFAULT 'open' CHECK (state IN ('open','sealed','published','revoked','aborted')),
    manifest JSONB,
    manifest_digest TEXT CHECK (manifest_digest ~ '^[0-9a-f]{64}$'),
    promotion_receipt JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    sealed_at TIMESTAMPTZ,
    published_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    aborted_at TIMESTAMPTZ,
    CHECK ((manifest IS NULL) = (manifest_digest IS NULL)),
    CHECK (state NOT IN ('sealed','published') OR (manifest IS NOT NULL AND sealed_at IS NOT NULL)),
    CHECK (state <> 'published' OR (promotion_receipt IS NOT NULL AND published_at IS NOT NULL)),
    CHECK (state <> 'revoked' OR revoked_at IS NOT NULL),
    CHECK (state <> 'aborted' OR (aborted_at IS NOT NULL AND manifest IS NULL AND sealed_at IS NULL AND published_at IS NULL AND revoked_at IS NULL))
);
CREATE UNIQUE INDEX hosted_reserved_coordinate ON hosted_stages(repository,package_name,version) WHERE state<>'aborted';
CREATE TABLE hosted_files (
    stage_id UUID NOT NULL REFERENCES hosted_stages(id),
    path TEXT NOT NULL CHECK (length(path) BETWEEN 1 AND 2048),
    digest TEXT NOT NULL CHECK (digest ~ '^[0-9a-f]{64}$'),
    artifact JSONB NOT NULL CHECK (artifact->>'digest' IS NOT NULL AND artifact->>'digest'=digest),
    PRIMARY KEY(stage_id,path)
);
CREATE INDEX hosted_file_digest ON hosted_files(digest);
