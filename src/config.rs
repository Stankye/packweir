use crate::{
    model::{Ecosystem, sha256},
    policy::Policy,
};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::SocketAddr,
    path::Path,
};
use url::Url;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub listen: SocketAddr,
    pub public_url: Url,
    pub storage: StorageConfig,
    #[serde(default)]
    pub policy: Policy,
    #[serde(default)]
    pub policy_scopes: Vec<crate::policy::PolicyScope>,
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
    pub policy: Option<crate::policy::PolicyRequirements>,
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
    Slsa {
        builder_id: String,
        sources: Vec<SourceBinding>,
    },
    Osv {
        packages: Vec<PackageBinding>,
        databases: BTreeMap<String, OsvDatabase>,
    },
    Hipcheck {
        policy: String,
        execution: String,
        required_analyses: Vec<String>,
        sources: Vec<SourceBinding>,
        plugins: BTreeMap<String, PinnedResource>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceBinding {
    pub repository: String,
    pub origin: String,
    /// Canonical HTTPS GitHub repository URL, without a ref or .git suffix.
    pub source_uri: String,
    pub source_revision: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackageBinding {
    pub repository: String,
    pub origin: String,
    pub ecosystem: String,
    pub name: String,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OsvDatabase {
    pub path: String,
    pub sha256: String,
    pub revision: String,
    pub published_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

fn validate_binding(repository: &str, origin: &str) -> Result<()> {
    ensure!(
        !repository.is_empty()
            && repository
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-'),
        "invalid binding repository"
    );
    let url = Url::parse(origin)?;
    ensure!(
        matches!(url.scheme(), "http" | "https")
            && url.host_str().is_some()
            && url.username().is_empty()
            && url.password().is_none(),
        "binding origin must be an HTTP(S) URL without credentials"
    );
    ensure!(
        url.as_str() == origin,
        "binding origin must use the canonical artifact URL"
    );
    Ok(())
}

fn validate_sources(sources: &[SourceBinding]) -> Result<()> {
    ensure!(
        !sources.is_empty() && sources.len() <= 1024,
        "between 1 and 1024 source bindings required"
    );
    let mut identities = BTreeSet::new();
    for source in sources {
        validate_binding(&source.repository, &source.origin)?;
        ensure!(
            identities.insert((&source.repository, &source.origin)),
            "duplicate source binding"
        );
        let uri = Url::parse(&source.source_uri)?;
        let parts: Vec<_> = uri.path().trim_start_matches('/').split('/').collect();
        ensure!(
            uri.scheme() == "https"
                && uri.host_str() == Some("github.com")
                && uri.port().is_none()
                && uri.username().is_empty()
                && uri.password().is_none()
                && uri.query().is_none()
                && uri.fragment().is_none()
                && parts.len() == 2
                && parts.iter().all(|p| !p.is_empty()
                    && p.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)))
                && !uri.path().ends_with(".git")
                && uri.as_str() == source.source_uri,
            "source_uri must be a canonical HTTPS GitHub owner/repository URL"
        );
        ensure!(
            source.source_revision.len() == 40
                && source
                    .source_revision
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "source_revision must be a complete lowercase Git commit SHA-1"
        );
    }
    Ok(())
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
        if !matches!(self.driver, ScannerDriver::Command) {
            ensure!(
                self.program_sha256.is_some() && self.args.is_empty(),
                "built-in drivers require a pinned executable and construct their own arguments"
            );
        }
        match &self.driver {
            ScannerDriver::Slsa {
                builder_id,
                sources,
            } => {
                ensure!(
                    self.environment.is_empty(),
                    "SLSA driver controls its environment"
                );
                ensure!(
                    builder_id.starts_with("https://github.com/")
                        && builder_id.contains("@refs/tags/")
                        && !builder_id.ends_with('/'),
                    "SLSA requires an exact versioned GitHub builder identity"
                );
                validate_sources(sources)?;
            }
            ScannerDriver::Osv {
                packages,
                databases,
            } => {
                ensure!(
                    self.environment.is_empty(),
                    "OSV driver controls its offline database environment"
                );
                ensure!(
                    !packages.is_empty() && packages.len() <= 1024,
                    "between 1 and 1024 package bindings required"
                );
                let mut identities = BTreeSet::new();
                for package in packages {
                    validate_binding(&package.repository, &package.origin)?;
                    ensure!(
                        identities.insert((&package.repository, &package.origin)),
                        "duplicate package binding"
                    );
                    ensure!(
                        ["npm", "PyPI", "crates.io", "Maven", "NuGet"]
                            .contains(&package.ecosystem.as_str()),
                        "unsupported OSV ecosystem"
                    );
                    ensure!(
                        !package.name.trim().is_empty() && !package.version.trim().is_empty(),
                        "OSV package name and exact version required"
                    );
                    ensure!(
                        package.name.len() <= 512
                            && package
                                .name
                                .bytes()
                                .all(|b| b.is_ascii_alphanumeric() || b"@/:._-".contains(&b)),
                        "invalid OSV package name"
                    );
                    ensure!(
                        package.version.len() <= 256
                            && package.version.bytes().any(|b| b.is_ascii_digit())
                            && package
                                .version
                                .bytes()
                                .all(|b| b.is_ascii_alphanumeric() || b"._-+!".contains(&b)),
                        "OSV mappings require literal versions, not ranges or tags"
                    );
                    ensure!(
                        package.ecosystem != "Maven"
                            || package.name.split(':').count() == 2
                                && package.name.split(':').all(|p| !p.is_empty()),
                        "Maven mappings require group:artifact names"
                    );
                    ensure!(
                        databases.contains_key(&package.ecosystem),
                        "OSV requires a pinned database for each mapped ecosystem"
                    );
                }
                ensure!(
                    databases.len() <= 5,
                    "at most five OSV ecosystem databases supported"
                );
                for (ecosystem, database) in databases {
                    ensure!(
                        ["npm", "PyPI", "crates.io", "Maven", "NuGet"]
                            .contains(&ecosystem.as_str()),
                        "unsupported OSV database ecosystem"
                    );
                    ensure!(
                        Path::new(&database.path).is_absolute()
                            && valid_digest(&database.sha256)
                            && !database.revision.trim().is_empty(),
                        "OSV databases require absolute paths, SHA-256 pins and revisions"
                    );
                    ensure!(
                        database.expires_at > database.published_at,
                        "invalid OSV database validity interval"
                    );
                }
            }
            ScannerDriver::Hipcheck {
                policy,
                execution,
                required_analyses,
                sources,
                plugins,
            } => {
                ensure!(
                    self.resources.contains_key(policy) && self.resources.contains_key(execution),
                    "Hipcheck policy and execution must name pinned resources"
                );
                ensure!(
                    !required_analyses.is_empty()
                        && required_analyses.len() <= 32
                        && required_analyses.iter().all(|a| a.split('/').count() == 2
                            && a.split('/').all(|p| !p.is_empty()
                                && p.bytes()
                                    .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b)))),
                    "Hipcheck requires explicit publisher/plugin analysis names"
                );
                ensure!(
                    required_analyses.iter().collect::<BTreeSet<_>>().len()
                        == required_analyses.len(),
                    "duplicate required Hipcheck analysis"
                );
                validate_sources(sources)?;
                ensure!(
                    !plugins.is_empty()
                        && plugins.len() <= 32
                        && required_analyses.iter().all(|a| plugins.contains_key(a)),
                    "Hipcheck requires pinned binaries for every required analysis"
                );
                for plugin in plugins.values() {
                    ensure!(
                        Path::new(&plugin.path).is_absolute() && valid_digest(&plugin.sha256),
                        "Hipcheck plugin binaries require absolute paths and SHA-256 pins"
                    );
                }
            }
            _ => {}
        }
        Ok(())
    }
}
fn scanner_timeout() -> u64 {
    120
}

impl Config {
    pub fn effective_policy(
        &self,
        scope: &crate::identity::DeliveryScope,
    ) -> Result<crate::policy::EffectivePolicy> {
        let repo = self
            .repositories
            .get(&scope.repository)
            .ok_or_else(|| anyhow::anyhow!("unknown policy repository"))?;
        ensure!(
            scope
                .package
                .as_ref()
                .is_none_or(|p| p.ecosystem == repo.ecosystem && p.is_canonical()),
            "stored identity requires a fresh registry observation after an ecosystem or coordinate change"
        );
        let mut policy = self.policy.clone();
        let mut layers = vec![format!("global:{}", policy.revision)];
        if let Some(additions) = &repo.policy {
            policy.extend(additions);
            layers.push(format!(
                "repository:{}:{}",
                scope.repository, additions.revision
            ));
        }
        let mut identity_required = false;
        for rule in self
            .policy_scopes
            .iter()
            .filter(|r| r.repository == scope.repository)
        {
            identity_required = true;
            if scope.package.as_ref().is_some_and(|p| rule.matches(p)) {
                policy.extend(&rule.policy);
                layers.push(format!("scope:{}:{}", rule.name, rule.policy.revision));
            }
        }
        if identity_required {
            policy.required.push("package_identity".into());
            policy.required.sort();
            policy.required.dedup();
        }
        Ok(crate::policy::EffectivePolicy {
            policy,
            layers,
            identity_required,
        })
    }
    pub fn delivery_fingerprint(&self, scope: &crate::identity::DeliveryScope) -> Result<String> {
        Ok(sha256(&serde_json::to_vec(
            &serde_json::json!({"engine":self.fingerprint(),"scope":scope,"effective":self.effective_policy(scope)?}),
        )?))
    }
    pub fn identity_sufficient(&self, scope: &crate::identity::DeliveryScope) -> Result<bool> {
        let effective = self.effective_policy(scope)?;
        Ok(scope.package.as_ref().is_some_and(|p| {
            !effective.identity_required
                || !matches!(p.ecosystem, Ecosystem::Npm | Ecosystem::Pypi)
                || p.basis == "registry_metadata_observed"
        }))
    }
    pub fn load(path: &Path) -> Result<Self> {
        let config: Self = toml::from_str(&std::fs::read_to_string(path)?)?;
        config.validate()?;
        Ok(config)
    }
    pub fn validate(&self) -> Result<()> {
        fn checks(revision: &str, required: &[String], denied: &[String]) -> Result<()> {
            ensure!(
                !revision.is_empty() && revision.len() <= 256,
                "policy revision required (at most 256 characters)"
            );
            ensure!(
                required.len() <= 64 && denied.len() <= 64,
                "at most 64 checks per policy list"
            );
            ensure!(
                required.iter().chain(denied).all(|c| !c.is_empty()
                    && c.len() <= 128
                    && c.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))),
                "invalid policy check name"
            );
            Ok(())
        }
        checks(
            &self.policy.revision,
            &self.policy.required,
            &self.policy.deny_on_failure,
        )?;
        ensure!(self.policy_scopes.len() <= 256, "at most 256 policy scopes");
        let mut scope_names = BTreeSet::new();
        for scope in &self.policy_scopes {
            ensure!(
                !scope.name.is_empty()
                    && scope.name.len() <= 128
                    && scope
                        .name
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
                    && scope_names.insert(&scope.name),
                "policy scope names must be unique and nonempty"
            );
            let repo = self
                .repositories
                .get(&scope.repository)
                .ok_or_else(|| anyhow::anyhow!("unknown policy scope repository"))?;
            ensure!(
                scope.namespace.is_some() != scope.package.is_some(),
                "a policy scope must select exactly one namespace or package"
            );
            if let Some(name) = &scope.package {
                ensure!(
                    crate::identity::canonical_name(repo.ecosystem, name).as_ref() == Some(name),
                    "policy package selector must be canonical"
                );
            }
            if let Some(namespace) = &scope.namespace {
                let valid = match repo.ecosystem {
                    Ecosystem::Npm => {
                        namespace.starts_with('@')
                            && !namespace.contains('/')
                            && crate::identity::canonical_name(
                                Ecosystem::Npm,
                                &format!("{namespace}/placeholder"),
                            )
                            .as_ref()
                                == Some(&format!("{namespace}/placeholder"))
                    }
                    Ecosystem::Maven => crate::identity::canonical_name(
                        Ecosystem::Maven,
                        &format!("{namespace}:placeholder"),
                    )
                    .is_some(),
                    _ => false,
                };
                ensure!(
                    valid,
                    "namespaces support npm scopes and Maven group prefixes; use package selectors for other ecosystems"
                );
            }
            checks(
                &scope.policy.revision,
                &scope.policy.required,
                &scope.policy.deny_on_failure,
            )?;
            ensure!(
                !scope.policy.required.iter().any(|c| c == "agent") || self.policy.trust_agent,
                "scoped agent requirements need global trust_agent=true"
            );
        }
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
            if let Some(policy) = &repo.policy {
                checks(&policy.revision, &policy.required, &policy.deny_on_failure)?;
                ensure!(
                    !policy.required.iter().any(|c| c == "agent") || self.policy.trust_agent,
                    "repository agent requirements need global trust_agent=true"
                );
            }
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
                ![
                    "inventory",
                    "archive_safety",
                    "integrity",
                    "package_identity"
                ]
                .contains(&name.as_str()),
                "reserved scanner name"
            );
            ensure!(
                !matches!(scanner.driver, ScannerDriver::Sigstore { .. })
                    || !["agent", "provenance"].contains(&name.as_str()),
                "Sigstore blob signatures cannot stand in for agents or provenance checks"
            );
            ensure!(
                !matches!(
                    scanner.driver,
                    ScannerDriver::Osv { .. } | ScannerDriver::Hipcheck { .. }
                ) || !["agent", "provenance", "required_signature"].contains(&name.as_str()),
                "analysis drivers cannot stand in for cryptographic verification or agents"
            );
            ensure!(
                !matches!(scanner.driver, ScannerDriver::Slsa { .. }) || name != "agent",
                "SLSA verification cannot stand in for an agent"
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
