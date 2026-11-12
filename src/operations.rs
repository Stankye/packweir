//! Operational database observations, independent of delivery policy evaluation.
//!
//! Gauges count recorded metadata across all configurations. They neither probe
//! retained blobs nor establish worker liveness or current policy approval.
use crate::store::Store;
use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use std::fmt::Write;

#[derive(Debug, Clone, Serialize)]
pub struct OperationalSnapshot {
    /// PostgreSQL's statement timestamp; all counts use the same MVCC snapshot.
    pub observed_at: DateTime<Utc>,
    pub coverage: Coverage,
    pub jobs: JobCounts,
    pub evidence: EvidenceCounts,
    pub artifacts: ArtifactCounts,
    pub documents: DocumentCounts,
    pub decisions: DecisionCounts,
    pub audit_records: i64,
    pub discovery: DiscoveryCounts,
    pub hosted: HostedCounts,
    pub hosted_jobs: HostedJobCounts,
}

#[derive(Debug, Clone, Serialize)]
pub struct Coverage {
    pub database_scope: &'static str,
    pub physical_storage_verified: bool,
    pub worker_liveness_verified: bool,
    pub current_policy_approval_verified: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobCounts {
    pub queued: i64,
    pub running: i64,
    pub complete: i64,
    pub failed: i64,
    pub expired_leases: i64,
    pub retryable_expired_leases: i64,
    pub exhausted_expired_leases: i64,
    pub invalid_running_leases: i64,
    pub exhausted_queued: i64,
    pub stale_context_active: i64,
    /// Zero when no queued jobs exist. Future timestamps do not produce negative ages.
    pub oldest_queued_age_seconds: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceCounts {
    pub total: i64,
    pub current_context_time_valid: i64,
    pub expired: i64,
    pub future_dated: i64,
    pub invalidated_context: i64,
    pub binding_invalid: i64,
    /// Outcomes of current-context, time-valid rows with consistent document bindings.
    pub outcomes: OutcomeCounts,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutcomeCounts {
    pub pass: i64,
    pub fail: i64,
    pub inconclusive: i64,
    pub unsupported: i64,
    pub error: i64,
    pub skipped: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactCounts {
    pub references: i64,
    pub distinct_digests: i64,
    pub repositories: i64,
    /// Sum of the largest recorded size for each digest, not physical disk/S3 use.
    pub recorded_digest_bytes: i64,
    pub inconsistent_size_digests: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DocumentCounts {
    pub references: i64,
    pub distinct_blob_digests: i64,
    pub publisher_declared: i64,
    pub artifact_observed: i64,
    pub client_resolved: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionCounts {
    pub approved: i64,
    pub denied: i64,
    pub pending: i64,
    pub unknown: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryCounts {
    pub claims: i64,
    pub unidentified_claims: i64,
    pub conflicting_artifact_urls: i64,
}

/// Recorded lifecycle states and references, never a current approval decision.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostedCounts {
    pub open: i64,
    pub sealed: i64,
    pub published: i64,
    pub revoked: i64,
    pub aborted: i64,
    pub file_references: i64,
    pub distinct_file_digests: i64,
    /// Sum of valid recorded sizes per file reference, including shared blobs.
    pub recorded_reference_bytes: i64,
    pub oldest_open_age_seconds: f64,
    pub copied_stages: i64,
    /// Historical source state only; destination approval/revocation is independent.
    pub copies_with_revoked_source: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostedJobCounts {
    pub queued: i64,
    pub running: i64,
    pub complete: i64,
    pub failed: i64,
    pub expired_leases: i64,
    pub oldest_queued_age_seconds: f64,
}

// A single statement keeps cross-table counts and database time consistent even
// while workers register results. JSON timestamps are guarded before casting;
// invalid stored documents must not turn into a misleading valid-evidence count.
// PostgreSQL stores microseconds while chrono JSON may retain nanoseconds, so a
// one-microsecond representation difference is accepted for timestamp bindings.
const SNAPSHOT_QUERY: &str = r#"
WITH observation AS MATERIALIZED (
    SELECT statement_timestamp() AS observed_at
), evidence_bindings AS MATERIALIZED (
    SELECT e.*,
        e.context_revision = COALESCE(c.revision, 0) AS current_context,
        COALESCE(
            jsonb_typeof(e.document) = 'object'
            AND (CASE WHEN jsonb_typeof(e.document)='object' THEN e.document ELSE '{}'::jsonb END)
                - ARRAY['subject','check','tool_version','configuration','outcome',
                'created_at','expires_at','details','references']::text[] = '{}'::jsonb
            AND e.document->>'subject' = e.subject
            AND jsonb_typeof(e.document->'subject') = 'string'
            AND e.document->>'check' = e.check_name
            AND jsonb_typeof(e.document->'check') = 'string'
            AND e.document->>'configuration' = e.configuration
            AND jsonb_typeof(e.document->'configuration') = 'string'
            AND jsonb_typeof(e.document->'tool_version') = 'string'
            AND e.document->>'outcome' IN ('pass','fail','inconclusive','unsupported','error','skipped')
            AND (NOT (e.document ? 'references') OR (
                jsonb_typeof(e.document->'references') = 'array'
                AND NOT EXISTS (SELECT 1 FROM jsonb_array_elements(
                    CASE WHEN jsonb_typeof(e.document->'references') = 'array'
                        THEN e.document->'references' ELSE '[]'::jsonb END
                ) AS reference WHERE jsonb_typeof(reference) <> 'string')
            ))
            AND e.document->>'created_at' ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?(Z|[+-]\d{2}:\d{2})$'
            AND e.document->>'expires_at' ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?(Z|[+-]\d{2}:\d{2})$'
            AND CASE WHEN pg_input_is_valid(e.document->>'created_at', 'timestamptz')
                AND pg_input_is_valid(e.document->>'expires_at', 'timestamptz')
                THEN CASE WHEN isfinite((e.document->>'created_at')::timestamptz)
                    AND isfinite((e.document->>'expires_at')::timestamptz)
                    AND isfinite(e.created_at) AND isfinite(e.expires_at)
                    THEN abs(extract(epoch FROM ((e.document->>'created_at')::timestamptz - e.created_at))) <= 0.000001
                    AND abs(extract(epoch FROM ((e.document->>'expires_at')::timestamptz - e.expires_at))) <= 0.000001
                    ELSE false END
                ELSE false END,
            false
        ) AS binding_valid
    FROM evidence e LEFT JOIN contexts c ON c.subject=e.subject
), hosted_jobs AS MATERIALIZED (
    SELECT j.* FROM jobs j
    WHERE jsonb_typeof(j.scope)='object'
        AND jsonb_typeof(j.scope->'repository')='string'
        AND jsonb_typeof(j.scope->'origin')='string'
        AND jsonb_typeof(j.scope->'filename')='string'
        AND jsonb_typeof(j.scope->'package')='object'
        AND j.scope->'package'->>'ecosystem'='maven'
        AND j.scope->'package'->>'basis'='hosted_coordinates_declared'
        AND jsonb_typeof(j.scope->'package'->'name')='string'
        AND jsonb_typeof(j.scope->'package'->'version')='string'
        AND jsonb_typeof(j.scope->'package'->'namespace')='string'
        AND jsonb_typeof(j.scope->'package'->'purl')='string'
        AND EXISTS (SELECT 1 FROM hosted_files f WHERE f.digest=j.subject
            AND j.scope=jsonb_build_object('repository',f.artifact->'repository',
                'origin',f.artifact->'origin','filename',f.artifact->'filename',
                'package',f.artifact->'package'))
), classified_evidence AS MATERIALIZED (
    SELECT e.document->>'outcome' AS outcome,
        CASE WHEN NOT e.binding_valid THEN 'binding_invalid'
            WHEN NOT e.current_context THEN 'invalidated_context'
            WHEN e.created_at > o.observed_at THEN 'future_dated'
            WHEN e.expires_at <= o.observed_at THEN 'expired'
            ELSE 'current_context_time_valid' END AS status
    FROM evidence_bindings e CROSS JOIN observation o
)
SELECT o.observed_at,
    (SELECT jsonb_build_object(
        'queued', count(*) FILTER (WHERE j.state='queued'),
        'running', count(*) FILTER (WHERE j.state='running'),
        'complete', count(*) FILTER (WHERE j.state='complete'),
        'failed', count(*) FILTER (WHERE j.state='failed'),
        'expired_leases', count(*) FILTER (WHERE j.state='running' AND j.lease_until<o.observed_at),
        'retryable_expired_leases', count(*) FILTER (WHERE j.state='running' AND j.lease_until<o.observed_at AND j.attempts<3),
        'exhausted_expired_leases', count(*) FILTER (WHERE j.state='running' AND j.lease_until<o.observed_at AND j.attempts>=3),
        'invalid_running_leases', count(*) FILTER (WHERE j.state='running' AND (j.lease_until IS NULL OR j.lease_token IS NULL)),
        'exhausted_queued', count(*) FILTER (WHERE j.state='queued' AND j.attempts>=3),
        'stale_context_active', count(*) FILTER (WHERE j.state IN ('queued','running') AND j.context_revision<>COALESCE(c.revision,0)),
        'oldest_queued_age_seconds', COALESCE(GREATEST(0, extract(epoch FROM (o.observed_at-min(j.created_at) FILTER (WHERE j.state='queued')))),0)
    ) FROM jobs j LEFT JOIN contexts c ON c.subject=j.subject) AS jobs,
    (SELECT jsonb_build_object(
        'total', count(*),
        'current_context_time_valid', count(*) FILTER (WHERE status='current_context_time_valid'),
        'expired', count(*) FILTER (WHERE status='expired'),
        'future_dated', count(*) FILTER (WHERE status='future_dated'),
        'invalidated_context', count(*) FILTER (WHERE status='invalidated_context'),
        'binding_invalid', count(*) FILTER (WHERE status='binding_invalid'),
        'outcomes', jsonb_build_object(
            'pass', count(*) FILTER (WHERE status='current_context_time_valid' AND outcome='pass'),
            'fail', count(*) FILTER (WHERE status='current_context_time_valid' AND outcome='fail'),
            'inconclusive', count(*) FILTER (WHERE status='current_context_time_valid' AND outcome='inconclusive'),
            'unsupported', count(*) FILTER (WHERE status='current_context_time_valid' AND outcome='unsupported'),
            'error', count(*) FILTER (WHERE status='current_context_time_valid' AND outcome='error'),
            'skipped', count(*) FILTER (WHERE status='current_context_time_valid' AND outcome='skipped')
        )
    ) FROM classified_evidence) AS evidence,
    (SELECT jsonb_build_object(
        'references', count(*),
        'distinct_digests', count(DISTINCT digest),
        'repositories', count(DISTINCT repository),
        'recorded_digest_bytes', (SELECT COALESCE(sum(bytes),0)::bigint FROM (SELECT max(size) AS bytes FROM artifacts GROUP BY digest) AS digest_sizes),
        'inconsistent_size_digests', (SELECT count(*) FROM (SELECT digest FROM artifacts GROUP BY digest HAVING min(size)<>max(size)) AS inconsistent)
    ) FROM artifacts) AS artifacts,
    (SELECT jsonb_build_object(
        'references', count(*),
        'distinct_blob_digests', count(DISTINCT blob_digest),
        'publisher_declared', count(*) FILTER (WHERE origin='publisher_declared'),
        'artifact_observed', count(*) FILTER (WHERE origin='artifact_observed'),
        'client_resolved', count(*) FILTER (WHERE origin='client_resolved')
    ) FROM documents) AS documents,
    (SELECT jsonb_build_object(
        'approved', count(*) FILTER (WHERE document->>'state'='approved'),
        'denied', count(*) FILTER (WHERE document->>'state'='denied'),
        'pending', count(*) FILTER (WHERE document->>'state'='pending'),
        'unknown', count(*) FILTER (WHERE COALESCE(document->>'state','') NOT IN ('approved','denied','pending'))
    ) FROM decisions) AS decisions,
    (SELECT count(*) FROM audit) AS audit_records,
    (SELECT jsonb_build_object(
        'claims', count(*),
        'unidentified_claims', count(*) FILTER (WHERE package IS NULL),
        'conflicting_artifact_urls', (SELECT count(*) FROM (SELECT repository,origin FROM package_claims GROUP BY repository,origin HAVING count(*)>1) AS conflicts)
    ) FROM package_claims) AS discovery,
    (SELECT jsonb_build_object(
        'open',count(*) FILTER (WHERE state='open'),
        'sealed',count(*) FILTER (WHERE state='sealed'),
        'published',count(*) FILTER (WHERE state='published'),
        'revoked',count(*) FILTER (WHERE state='revoked'),
        'aborted',count(*) FILTER (WHERE state='aborted'),
        'oldest_open_age_seconds',COALESCE(GREATEST(0,extract(epoch FROM (o.observed_at-min(created_at) FILTER (WHERE state='open')))),0),
        'file_references',(SELECT count(*) FROM hosted_files),
        'distinct_file_digests',(SELECT count(DISTINCT digest) FROM hosted_files),
        'recorded_reference_bytes',(SELECT COALESCE(sum(CASE WHEN jsonb_typeof(artifact->'size')='number' AND artifact->>'size' ~ '^[0-9]{1,18}$' THEN (artifact->>'size')::bigint ELSE 0 END),0)::bigint FROM hosted_files),
        'copied_stages',(SELECT count(*) FROM hosted_lineage),
        'copies_with_revoked_source',(SELECT count(*) FROM hosted_lineage l JOIN hosted_stages s ON s.id=l.source_stage_id WHERE s.state='revoked')
    ) FROM hosted_stages) AS hosted,
    (SELECT jsonb_build_object(
        'queued',count(*) FILTER (WHERE state='queued'),
        'running',count(*) FILTER (WHERE state='running'),
        'complete',count(*) FILTER (WHERE state='complete'),
        'failed',count(*) FILTER (WHERE state='failed'),
        'expired_leases',count(*) FILTER (WHERE state='running' AND lease_until<o.observed_at),
        'oldest_queued_age_seconds',COALESCE(GREATEST(0,extract(epoch FROM (o.observed_at-min(created_at) FILTER (WHERE state='queued')))),0)
    ) FROM hosted_jobs) AS hosted_jobs
FROM observation o
"#;

pub async fn snapshot(store: &Store) -> Result<OperationalSnapshot> {
    let row = sqlx::query(SNAPSHOT_QUERY).fetch_one(&store.pool).await?;
    Ok(OperationalSnapshot {
        observed_at: row.get("observed_at"),
        coverage: Coverage {
            database_scope: "all_configurations",
            physical_storage_verified: false,
            worker_liveness_verified: false,
            current_policy_approval_verified: false,
        },
        jobs: serde_json::from_value(row.get("jobs"))?,
        evidence: serde_json::from_value(row.get("evidence"))?,
        artifacts: serde_json::from_value(row.get("artifacts"))?,
        documents: serde_json::from_value(row.get("documents"))?,
        decisions: serde_json::from_value(row.get("decisions"))?,
        audit_records: row.get("audit_records"),
        discovery: serde_json::from_value(row.get("discovery"))?,
        hosted: serde_json::from_value(row.get("hosted"))?,
        hosted_jobs: serde_json::from_value(row.get("hosted_jobs"))?,
    })
}

impl OperationalSnapshot {
    /// Prometheus 0.0.4 text exposition using only fixed metric/label names.
    /// All values are database gauges; deletion/maintenance may reduce them.
    pub fn render_prometheus(&self) -> String {
        let mut output = String::new();
        gauge(
            &mut output,
            "packweir_operations_snapshot_timestamp_seconds",
            "Database observation time in Unix seconds.",
            self.observed_at.timestamp_millis() as f64 / 1000.0,
        );
        family(
            &mut output,
            "packweir_jobs",
            "Recorded jobs by state across all configurations.",
            "state",
            &[
                ("queued", self.jobs.queued),
                ("running", self.jobs.running),
                ("complete", self.jobs.complete),
                ("failed", self.jobs.failed),
            ],
        );
        family(
            &mut output,
            "packweir_expired_job_leases",
            "Running records whose lease deadline has expired.",
            "retry",
            &[
                ("retryable", self.jobs.retryable_expired_leases),
                ("exhausted", self.jobs.exhausted_expired_leases),
            ],
        );
        gauge(
            &mut output,
            "packweir_invalid_running_leases",
            "Running records missing a lease token or deadline.",
            self.jobs.invalid_running_leases,
        );
        gauge(
            &mut output,
            "packweir_exhausted_queued_jobs",
            "Queued records with no attempts remaining.",
            self.jobs.exhausted_queued,
        );
        gauge(
            &mut output,
            "packweir_stale_context_active_jobs",
            "Queued or running records whose document revision is stale.",
            self.jobs.stale_context_active,
        );
        gauge(
            &mut output,
            "packweir_oldest_queued_job_age_seconds",
            "Oldest recorded queued job age; zero for an empty queue.",
            self.jobs.oldest_queued_age_seconds,
        );
        family(
            &mut output,
            "packweir_evidence_records",
            "Recorded evidence classified by binding, context, and time; not policy approval.",
            "status",
            &[
                (
                    "current_context_time_valid",
                    self.evidence.current_context_time_valid,
                ),
                ("expired", self.evidence.expired),
                ("future_dated", self.evidence.future_dated),
                ("invalidated_context", self.evidence.invalidated_context),
                ("binding_invalid", self.evidence.binding_invalid),
            ],
        );
        family(
            &mut output,
            "packweir_current_context_evidence_outcomes",
            "Outcomes on time-valid rows with consistent bindings in the current document context.",
            "outcome",
            &[
                ("pass", self.evidence.outcomes.pass),
                ("fail", self.evidence.outcomes.fail),
                ("inconclusive", self.evidence.outcomes.inconclusive),
                ("unsupported", self.evidence.outcomes.unsupported),
                ("error", self.evidence.outcomes.error),
                ("skipped", self.evidence.outcomes.skipped),
            ],
        );
        gauge(
            &mut output,
            "packweir_artifact_references",
            "Artifact URL references recorded in PostgreSQL, regardless of blob retention.",
            self.artifacts.references,
        );
        gauge(
            &mut output,
            "packweir_artifact_digest_references",
            "Distinct artifact digests referenced in PostgreSQL, not confirmed retained blobs.",
            self.artifacts.distinct_digests,
        );
        gauge(
            &mut output,
            "packweir_artifact_recorded_digest_bytes",
            "Sum of largest recorded size per artifact digest; not physical storage usage.",
            self.artifacts.recorded_digest_bytes,
        );
        gauge(
            &mut output,
            "packweir_artifact_inconsistent_size_digests",
            "Artifact digests with inconsistent recorded sizes.",
            self.artifacts.inconsistent_size_digests,
        );
        gauge(
            &mut output,
            "packweir_repository_references",
            "Distinct repository identifiers in artifact metadata.",
            self.artifacts.repositories,
        );
        gauge(
            &mut output,
            "packweir_document_blob_references",
            "Distinct document blob digests referenced in PostgreSQL.",
            self.documents.distinct_blob_digests,
        );
        family(
            &mut output,
            "packweir_document_records",
            "Recorded document references by evidence origin.",
            "origin",
            &[
                ("publisher_declared", self.documents.publisher_declared),
                ("artifact_observed", self.documents.artifact_observed),
                ("client_resolved", self.documents.client_resolved),
            ],
        );
        family(
            &mut output,
            "packweir_decision_records",
            "Historical recorded delivery decisions, not current package approvals.",
            "state",
            &[
                ("approved", self.decisions.approved),
                ("denied", self.decisions.denied),
                ("pending", self.decisions.pending),
                ("unknown", self.decisions.unknown),
            ],
        );
        gauge(
            &mut output,
            "packweir_audit_records",
            "Recorded audit rows.",
            self.audit_records,
        );
        gauge(
            &mut output,
            "packweir_discovery_claims",
            "Recorded registry package identity claims.",
            self.discovery.claims,
        );
        gauge(
            &mut output,
            "packweir_unidentified_discovery_claims",
            "Recorded registry claims lacking recognized coordinates.",
            self.discovery.unidentified_claims,
        );
        gauge(
            &mut output,
            "packweir_conflicting_discovery_urls",
            "Repository artifact URLs with multiple recorded coordinate claims.",
            self.discovery.conflicting_artifact_urls,
        );
        family(
            &mut output,
            "packweir_hosted_stages",
            "Recorded hosted lifecycle states, independent of current security approval.",
            "state",
            &[
                ("open", self.hosted.open),
                ("sealed", self.hosted.sealed),
                ("published", self.hosted.published),
                ("revoked", self.hosted.revoked),
                ("aborted", self.hosted.aborted),
            ],
        );
        gauge(
            &mut output,
            "packweir_hosted_file_references",
            "Recorded hosted file references, including shared blobs.",
            self.hosted.file_references,
        );
        gauge(
            &mut output,
            "packweir_hosted_file_digest_references",
            "Distinct digests referenced by hosted files; physical presence is not verified.",
            self.hosted.distinct_file_digests,
        );
        gauge(
            &mut output,
            "packweir_hosted_recorded_reference_bytes",
            "Sum of valid recorded hosted file sizes per reference, not disk or deduplicated storage use.",
            self.hosted.recorded_reference_bytes,
        );
        gauge(
            &mut output,
            "packweir_hosted_oldest_open_age_seconds",
            "Age of the oldest recorded open stage, zero when none exist.",
            self.hosted.oldest_open_age_seconds,
        );
        gauge(
            &mut output,
            "packweir_hosted_copied_stages",
            "Recorded hosted copy lineage rows.",
            self.hosted.copied_stages,
        );
        gauge(
            &mut output,
            "packweir_hosted_copies_with_revoked_source",
            "Recorded copies whose source lifecycle state is revoked; destination state and approval are independent.",
            self.hosted.copies_with_revoked_source,
        );
        family(
            &mut output,
            "packweir_hosted_jobs",
            "Recorded jobs with exact hosted file delivery bindings across all configurations.",
            "state",
            &[
                ("queued", self.hosted_jobs.queued),
                ("running", self.hosted_jobs.running),
                ("complete", self.hosted_jobs.complete),
                ("failed", self.hosted_jobs.failed),
            ],
        );
        gauge(
            &mut output,
            "packweir_hosted_expired_job_leases",
            "Running hosted-bound jobs whose recorded lease deadline has expired.",
            self.hosted_jobs.expired_leases,
        );
        gauge(
            &mut output,
            "packweir_hosted_oldest_queued_age_seconds",
            "Age of the oldest queued hosted-bound job, zero when none exist.",
            self.hosted_jobs.oldest_queued_age_seconds,
        );
        output
    }
}

fn gauge(output: &mut String, name: &str, help: &str, value: impl std::fmt::Display) {
    writeln!(
        output,
        "# HELP {name} {help}\n# TYPE {name} gauge\n{name} {value}"
    )
    .expect("string write");
}

fn family(output: &mut String, name: &str, help: &str, label: &str, samples: &[(&str, i64)]) {
    writeln!(output, "# HELP {name} {help}\n# TYPE {name} gauge").expect("string write");
    for (value, count) in samples {
        writeln!(output, "{name}{{{label}=\"{value}\"}} {count}").expect("string write");
    }
}
