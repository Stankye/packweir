-- A deferred poll is ordinary queued work, not a failed scan attempt.
ALTER TABLE jobs ADD COLUMN not_before TIMESTAMPTZ NOT NULL DEFAULT now();
ALTER TABLE jobs ADD COLUMN analysis_checkpoint JSONB;
ALTER TABLE jobs ADD COLUMN checkpoint_context_revision BIGINT;
CREATE INDEX jobs_deferred_queue ON jobs(not_before, created_at) WHERE state = 'queued';

-- This ledger records intent before an external POST. A submitting row without
-- an attached SID is ambiguous after interruption; it is never safe to replay
-- that POST merely because the local worker did not receive the response.
CREATE TABLE remote_analysis (
    id UUID PRIMARY KEY,
    job_id UUID NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
    subject TEXT NOT NULL CHECK (subject ~ '^[0-9a-f]{64}$'),
    configuration TEXT NOT NULL,
    context_revision BIGINT NOT NULL,
    generation INTEGER NOT NULL DEFAULT 0 CHECK (generation >= 0),
    check_name TEXT NOT NULL CHECK (length(check_name) BETWEEN 1 AND 128),
    service_fingerprint TEXT NOT NULL CHECK (service_fingerprint ~ '^[0-9a-f]{64}$'),
    request_digest TEXT NOT NULL CHECK (request_digest ~ '^[0-9a-f]{64}$'),
    evidence_digest TEXT NOT NULL CHECK (evidence_digest ~ '^[0-9a-f]{64}$'),
    state TEXT NOT NULL DEFAULT 'prepared'
        CHECK (state IN ('prepared','submitting','submitted','complete','failed','ambiguous')),
    remote_id TEXT CHECK (length(remote_id) BETWEEN 1 AND 256),
    submission_token UUID,
    submission_lease UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    deadline_at TIMESTAMPTZ NOT NULL,
    next_poll_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at TIMESTAMPTZ,
    output JSONB,
    error TEXT CHECK (octet_length(error) <= 4096),
    poll_attempts INTEGER NOT NULL DEFAULT 0 CHECK (poll_attempts >= 0),
    poll_failures INTEGER NOT NULL DEFAULT 0 CHECK (poll_failures >= 0),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (job_id, check_name, context_revision, generation),
    CHECK (deadline_at > created_at),
    CHECK (state NOT IN ('submitted','complete') OR remote_id IS NOT NULL),
    CHECK (state NOT IN ('prepared','submitting','ambiguous') OR remote_id IS NULL),
    CHECK ((state = 'complete') = (output IS NOT NULL)),
    CHECK ((state IN ('complete','failed','ambiguous')) = (completed_at IS NOT NULL)),
    CHECK (state NOT IN ('submitting','submitted','complete','ambiguous') OR submission_token IS NOT NULL)
);
CREATE INDEX remote_analysis_subject ON remote_analysis(subject, context_revision);
