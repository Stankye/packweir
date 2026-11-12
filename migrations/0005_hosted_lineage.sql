CREATE TABLE hosted_lineage (
    destination_stage_id UUID PRIMARY KEY REFERENCES hosted_stages(id),
    source_stage_id UUID NOT NULL REFERENCES hosted_stages(id),
    source_manifest_digest TEXT NOT NULL CHECK (source_manifest_digest ~ '^[0-9a-f]{64}$'),
    destination_manifest_digest TEXT NOT NULL CHECK (destination_manifest_digest ~ '^[0-9a-f]{64}$'),
    actor TEXT NOT NULL CHECK (length(actor) BETWEEN 1 AND 128),
    created_at TIMESTAMPTZ NOT NULL,
    receipt JSONB NOT NULL CHECK (jsonb_typeof(receipt)='object'),
    CHECK (destination_stage_id <> source_stage_id)
);
CREATE INDEX hosted_lineage_source ON hosted_lineage(source_stage_id);
