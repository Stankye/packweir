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
    /// Optional executable pin; mandatory for built-in verification drivers.
    pub program_sha256: Option<String>,
    #[serde(default)]
    pub resources: BTreeMap<String, PinnedResource>,
    #[serde(default)]
    pub driver: ScannerDriver,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PinnedResource {
    pub path: String,
    pub sha256: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ScannerDriver {
    #[default]
    Command,
    Sigstore {
        certificate_identity: String,
        certificate_oidc_issuer: String,
        /// Name of an entry in this scanner's resources map.
        trusted_root: String,
    },
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

impl CommandScanner {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            Path::new(&self.program).is_absolute(),
            "scanner executable must be an absolute path"
        );
        ensure!(
            !self.version.is_empty() && (1..=3600).contains(&self.timeout_seconds),
            "scanner version and timeout between 1 and 3600 seconds required"
        );
        if let Some(digest) = &self.program_sha256 {
            ensure!(valid_digest(digest), "invalid scanner executable SHA-256");
        }
        ensure!(
            self.resources.len() <= 32,
            "at most 32 scanner resources are supported"
        );
        for (name, resource) in &self.resources {
            ensure!(
                !name.is_empty()
                    && name.len() <= 64
                    && name
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b)),
                "invalid scanner resource name"
            );
            ensure!(
                Path::new(&resource.path).is_absolute() && valid_digest(&resource.sha256),
                "scanner resources require absolute paths and lowercase SHA-256 pins"
            );
        }
        if let ScannerDriver::Sigstore {
            certificate_identity,
            certificate_oidc_issuer,
            trusted_root,
        } = &self.driver
        {
            ensure!(
                self.program_sha256.is_some(),
                "Sigstore requires an executable SHA-256 pin"
            );
            ensure!(
                self.args.is_empty() && self.environment.is_empty(),
                "Sigstore driver constructs its own arguments and environment"
            );
            ensure!(
                !certificate_identity.trim().is_empty()
                    && !certificate_oidc_issuer.trim().is_empty(),
                "Sigstore requires exact certificate identity and OIDC issuer"
            );
            ensure!(
                self.resources.contains_key(trusted_root),
                "Sigstore trusted_root must name a pinned resource"
            );
        }
        Ok(())
    }
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
            scanner.validate()?;
            ensure!(
                !["inventory", "archive_safety", "integrity"].contains(&name.as_str()),
                "reserved scanner name"
            );
            ensure!(
                !matches!(scanner.driver, ScannerDriver::Sigstore { .. })
                    || !["agent", "provenance"].contains(&name.as_str()),
                "Sigstore blob signatures cannot stand in for agents or provenance checks"
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
