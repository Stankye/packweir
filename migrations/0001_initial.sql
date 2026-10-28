CREATE TABLE artifacts (
    repository TEXT NOT NULL,
    origin TEXT NOT NULL,
    digest TEXT NOT NULL CHECK (digest ~ '^[0-9a-f]{64}$'),
    size BIGINT NOT NULL CHECK (size >= 0),
    filename TEXT NOT NULL,
    content_type TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (repository, origin)
);
CREATE INDEX artifact_digest ON artifacts(digest);

CREATE TABLE contexts (
    subject TEXT PRIMARY KEY,
    revision BIGINT NOT NULL DEFAULT 0
);

CREATE TABLE evidence (
    id UUID PRIMARY KEY,
    subject TEXT NOT NULL,
    check_name TEXT NOT NULL,
    configuration TEXT NOT NULL,
    context_revision BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    document JSONB NOT NULL
);
CREATE INDEX evidence_lookup ON evidence(subject, configuration, check_name, created_at DESC);

CREATE TABLE jobs (
    id UUID PRIMARY KEY,
    subject TEXT NOT NULL,
    configuration TEXT NOT NULL,
    context_revision BIGINT NOT NULL DEFAULT 0,
    filename TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'queued' CHECK (state IN ('queued','running','complete','failed')),
    lease_token UUID,
    lease_until TIMESTAMPTZ,
    attempts INTEGER NOT NULL DEFAULT 0,
    error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(subject, configuration)
);

CREATE TABLE documents (
    id UUID PRIMARY KEY,
    subject TEXT NOT NULL,
    kind TEXT NOT NULL,
    origin TEXT NOT NULL CHECK (origin IN ('publisher_declared','artifact_observed','client_resolved')),
    blob_digest TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(subject, kind, origin, blob_digest)
);

CREATE TABLE decisions (
    id BIGSERIAL PRIMARY KEY,
    repository TEXT NOT NULL,
    subject TEXT NOT NULL,
    configuration TEXT NOT NULL,
    document JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE audit (
    id BIGSERIAL PRIMARY KEY,
    action TEXT NOT NULL,
    subject TEXT NOT NULL,
    details JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
