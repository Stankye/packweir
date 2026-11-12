use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Ecosystem {
    Npm,
    Pypi,
    Cargo,
    Maven,
    Nuget,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Pass,
    Fail,
    Inconclusive,
    Unsupported,
    Error,
    /// The engine deliberately did not execute a check. This is never a passing verdict.
    Skipped,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evidence {
    pub subject: String,
    pub check: String,
    pub tool_version: String,
    pub configuration: String,
    pub outcome: Outcome,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    #[serde(default)]
    pub details: serde_json::Value,
    #[serde(default)]
    pub references: Vec<String>,
}

impl Evidence {
    pub fn applicable(
        &self,
        digest: &str,
        check: &str,
        configuration: &str,
        now: DateTime<Utc>,
    ) -> bool {
        self.subject == digest
            && self.check == check
            && self.configuration == configuration
            && self.created_at <= now
            && self.expires_at > now
    }
}

/// Stable engine binding between an investigation and each supplied finding.
/// Evidence is serialized as its typed record, rather than a database JSON object's key order.
pub fn evidence_fingerprint(evidence: &Evidence) -> String {
    // PostgreSQL's authoritative timestamps have microsecond precision. Canonicalize
    // these two fields so a finding keeps its binding after a database round trip.
    let mut canonical = evidence.clone();
    canonical.created_at = DateTime::from_timestamp_micros(evidence.created_at.timestamp_micros())
        .expect("representable evidence timestamp");
    canonical.expires_at = DateTime::from_timestamp_micros(evidence.expires_at.timestamp_micros())
        .expect("representable evidence timestamp");
    sha256(&serde_json::to_vec(&canonical).expect("serializable evidence"))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", content = "reasons", rename_all = "snake_case")]
pub enum Decision {
    Approved,
    Denied(Vec<String>),
    Pending(Vec<String>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Artifact {
    pub repository: String,
    pub origin: String,
    pub digest: String,
    pub size: i64,
    pub filename: String,
    pub content_type: String,
    #[serde(default)]
    pub package: Option<crate::identity::PackageIdentity>,
}

impl Artifact {
    pub fn scope(&self) -> crate::identity::DeliveryScope {
        crate::identity::DeliveryScope {
            repository: self.repository.clone(),
            origin: self.origin.clone(),
            filename: self.filename.clone(),
            package: self.package.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileRecord {
    pub path: String,
    pub sha256: String,
    pub size: u64,
    pub kind: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Inventory {
    pub subject: String,
    pub files: Vec<FileRecord>,
    pub warnings: Vec<String>,
    pub coverage: String,
}

pub fn sha256(bytes: &[u8]) -> String {
    use sha2::Digest;
    hex::encode(sha2::Sha256::digest(bytes))
}

pub fn agent_binding(details: &serde_json::Value) -> bool {
    [
        "model",
        "prompt_digest",
        "toolset_digest",
        "evidence_digest",
        "trace_digest",
    ]
    .iter()
    .all(|key| {
        details
            .get(key)
            .and_then(|v| v.as_str())
            .is_some_and(|v| !v.is_empty())
    })
}

pub type EvidenceMap = BTreeMap<String, Evidence>;
