-- Derived analysis products are observations, not new package registrations or
-- input documents. Keep producing evidence and its exact context immutable.
CREATE TABLE analysis_outputs (
    id UUID PRIMARY KEY,
    evidence_id UUID NOT NULL REFERENCES evidence(id),
    job_id UUID NOT NULL REFERENCES jobs(id),
    subject TEXT NOT NULL CHECK (subject ~ '^[0-9a-f]{64}$'),
    configuration TEXT NOT NULL,
    context_revision BIGINT NOT NULL CHECK (context_revision >= 0),
    check_name TEXT NOT NULL,
    manifest_sha256 TEXT NOT NULL CHECK (manifest_sha256 ~ '^[0-9a-f]{64}$'),
    input_sha256 TEXT NOT NULL CHECK (input_sha256 ~ '^[0-9a-f]{64}$'),
    producer_identity_sha256 TEXT NOT NULL CHECK (producer_identity_sha256 ~ '^[0-9a-f]{64}$'),
    output_sha256 TEXT NOT NULL CHECK (output_sha256 ~ '^[0-9a-f]{64}$'),
    kind TEXT NOT NULL CHECK (kind IN ('decompiled_c','pcode','decoded_bytes')),
    media_type TEXT NOT NULL,
    size BIGINT NOT NULL CHECK (size >= 0 AND size <= 262144),
    derivation_sha256 TEXT NOT NULL CHECK (derivation_sha256 ~ '^[0-9a-f]{64}$'),
    metadata JSONB NOT NULL CHECK (octet_length(metadata::text) <= 1048576),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    approval_effect TEXT NOT NULL DEFAULT 'none' CHECK (approval_effect = 'none'),
    UNIQUE (evidence_id,manifest_sha256,output_sha256,kind,derivation_sha256)
);
CREATE INDEX analysis_outputs_subject ON analysis_outputs(subject,created_at,id);
CREATE INDEX analysis_outputs_blob_references ON analysis_outputs(output_sha256);
