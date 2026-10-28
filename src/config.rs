use crate::{
    model::{Ecosystem, sha256},
    policy::Policy,
};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, net::SocketAddr, path::Path};
use url::Url;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub listen: SocketAddr,
    pub public_url: Url,
    pub storage: StorageConfig,
    #[serde(default)]
    pub policy: Policy,
    pub repositories: BTreeMap<String, Repository>,
    #[serde(default)]
    pub scanners: BTreeMap<String, CommandScanner>,
    #[serde(default = "default_max")]
    pub max_download_bytes: usize,
    #[serde(default = "default_ttl")]
    pub evidence_ttl_seconds: i64,
    #[serde(default)]
    pub allow_private_upstreams: bool,
}
fn default_max() -> usize {
    128 * 1024 * 1024
}
fn default_ttl() -> i64 {
    86400
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum StorageConfig {
    Fs {
        root: String,
    },
    S3 {
        bucket: String,
        region: String,
        endpoint: Option<String>,
        #[serde(default)]
        root: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Repository {
    pub ecosystem: Ecosystem,
    pub upstream: Url,
    /// Exact origins (scheme, host, port), never suffix-matched hostnames.
    #[serde(default)]
    pub download_origins: Vec<Url>,
    #[serde(default = "yes")]
    pub retain: bool,
    pub token_env: Option<String>,
    pub cargo_download_template: Option<String>,
}
fn yes() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommandScanner {
    /// Operator-owned executable. Never a shell string supplied by a package.
    pub program: String,
    #[serde(default)]
    pub args: Vec<String>,
    pub version: String,
    #[serde(default = "scanner_timeout")]
    pub timeout_seconds: u64,
    #[serde(default)]
    pub environment: BTreeMap<String, String>,
}
fn scanner_timeout() -> u64 {
    120
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let config: Self = toml::from_str(&std::fs::read_to_string(path)?)?;
        config.validate()?;
        Ok(config)
    }
    pub fn validate(&self) -> Result<()> {
        ensure!(
            matches!(self.public_url.scheme(), "http" | "https")
                && self.public_url.host_str().is_some(),
            "public_url must be HTTP(S)"
        );
        ensure!(
            self.public_url.path() == "/"
                && self.public_url.query().is_none()
                && self.public_url.fragment().is_none()
                && self.public_url.username().is_empty()
                && self.public_url.password().is_none(),
            "public_url must be an origin URL"
        );
        ensure!(
            self.max_download_bytes > 0 && (1..=31_536_000).contains(&self.evidence_ttl_seconds),
            "download limit must be positive and evidence TTL must be between 1 second and 1 year"
        );
        ensure!(
            !self.repositories.is_empty(),
            "at least one repository required"
        );
        for (name, repo) in &self.repositories {
            ensure!(
                !name.is_empty() && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'),
                "invalid repository name"
            );
            ensure!(
                repo.upstream.path().ends_with('/'),
                "upstream must end with /: {name}"
            );
            ensure!(
                repo.upstream.query().is_none(),
                "upstream base must not contain a query"
            );
            for url in std::iter::once(&repo.upstream).chain(&repo.download_origins) {
                ensure!(
                    url.scheme() == "https"
                        || (self.allow_private_upstreams && url.scheme() == "http"),
                    "HTTPS required for upstreams"
                );
                ensure!(
                    url.host_str().is_some()
                        && url.username().is_empty()
                        && url.password().is_none()
                        && url.fragment().is_none(),
                    "invalid upstream URL"
                );
            }
            if repo.ecosystem == Ecosystem::Cargo {
                ensure!(
                    repo.cargo_download_template.is_some(),
                    "Cargo requires cargo_download_template"
                );
            }
        }
        for (name, scanner) in &self.scanners {
            ensure!(
                std::path::Path::new(&scanner.program).is_absolute(),
                "scanner executable must be an absolute path"
            );
            ensure!(
                !["inventory", "archive_safety", "integrity"].contains(&name.as_str()),
                "reserved scanner name"
            );
            ensure!(
                !scanner.version.is_empty() && (1..=3600).contains(&scanner.timeout_seconds),
                "scanner version and timeout between 1 and 3600 seconds required"
            );
        }
        ensure!(
            self.scanners.len() <= 32,
            "at most 32 scanner adapters are supported"
        );
        ensure!(
            !self.policy.required.is_empty(),
            "policy must require at least one check"
        );
        ensure!(
            !self.policy.required.iter().any(|c| c == "agent") || self.policy.trust_agent,
            "required agent check needs trust_agent=true"
        );
        Ok(())
    }
    /// Bind evidence to the entire security/routing configuration, never credentials.
    pub fn fingerprint(&self) -> String {
        sha256(&serde_json::to_vec(&serde_json::json!({"engine_version":env!("CARGO_PKG_VERSION"),"configuration":self})).expect("serializable configuration"))
    }
}
