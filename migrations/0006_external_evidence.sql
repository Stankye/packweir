-- Administrative evidence exchange is an immutable foreign-claim archive.
-- These records are deliberately separate from local policy and scanner inputs.
CREATE TABLE external_imports (
    id UUID PRIMARY KEY,
    subject TEXT NOT NULL CHECK (subject ~ '^[0-9a-f]{64}$'),
    manifest_digest TEXT NOT NULL CHECK (manifest_digest ~ '^sha256:[0-9a-f]{64}$'),
    source JSONB NOT NULL,
    snapshot_metadata JSONB NOT NULL,
    imported_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    verified BOOLEAN NOT NULL DEFAULT false CHECK (verified = false),
    trust_status TEXT NOT NULL DEFAULT 'unverified' CHECK (trust_status = 'unverified'),
    approval_effect TEXT NOT NULL DEFAULT 'none' CHECK (approval_effect = 'none'),
    UNIQUE(subject, manifest_digest)
);
CREATE INDEX external_imports_subject ON external_imports(subject, imported_at, id);

CREATE TABLE external_import_blobs (
    import_id UUID NOT NULL REFERENCES external_imports(id),
    digest TEXT NOT NULL CHECK (digest ~ '^[0-9a-f]{64}$'),
    size BIGINT NOT NULL CHECK (size >= 0),
    is_manifest BOOLEAN NOT NULL DEFAULT false,
    PRIMARY KEY(import_id, digest)
);
CREATE INDEX external_import_blob_references ON external_import_blobs(digest);
