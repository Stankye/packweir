//! Operator-owned service credentials and Maven source reservations.
//! These permissions never replace artifact security policy or publisher verification.
use crate::{
    config::{Config, Repository, RepositoryKind},
    model::{Ecosystem, sha256},
};
use anyhow::{Result, ensure};
use axum::http::{HeaderMap, header};
use base64::Engine;
use chrono::{DateTime, Datelike, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use subtle::ConstantTimeEq;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Read,
    Write,
    Promote,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccessConfig {
    #[serde(default = "default_legacy_read")]
    pub legacy_read_enabled: bool,
    #[serde(default)]
    pub principals: BTreeMap<String, ServicePrincipal>,
    #[serde(default)]
    pub maven_owners: Vec<MavenOwnership>,
}
fn default_legacy_read() -> bool {
    true
}
impl Default for AccessConfig {
    fn default() -> Self {
        Self {
            legacy_read_enabled: true,
            principals: BTreeMap::new(),
            maven_owners: vec![],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServicePrincipal {
    pub token_env: String,
    pub expires_at: Option<DateTime<Utc>>,
    pub grants: Vec<Grant>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Grant {
    pub repository: String,
    pub actions: Vec<Action>,
    pub namespace: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MavenOwnership {
    pub namespace: String,
    pub repository: String,
    #[serde(default)]
    pub additional_repositories: Vec<String>,
}

impl MavenOwnership {
    fn admits(&self, repository: &str) -> bool {
        self.repository == repository
            || self
                .additional_repositories
                .iter()
                .any(|candidate| candidate == repository)
    }

    fn authoritative_set(&self) -> BTreeSet<&str> {
        std::iter::once(self.repository.as_str())
            .chain(self.additional_repositories.iter().map(String::as_str))
            .collect()
    }
}

fn namespace_matches(expected: &str, actual: &str) -> bool {
    expected == actual
        || actual
            .strip_prefix(expected)
            .is_some_and(|rest| rest.starts_with('.'))
}

fn valid_namespace(namespace: &str) -> bool {
    namespace.len() <= 192
        && crate::identity::canonical_name(Ecosystem::Maven, &format!("{namespace}:placeholder"))
            .as_deref()
            == Some(&format!("{namespace}:placeholder"))
}

fn valid_env(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name
            .bytes()
            .next()
            .is_some_and(|b| b.is_ascii_alphabetic() || b == b'_')
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

impl AccessConfig {
    pub fn validate(&self, repositories: &BTreeMap<String, Repository>) -> Result<()> {
        ensure!(
            self.principals.len() <= 256 && self.maven_owners.len() <= 256,
            "at most 256 service principals and Maven owners"
        );
        let mut environments = BTreeSet::new();
        for (id, principal) in &self.principals {
            ensure!(
                !id.is_empty()
                    && id.len() <= 128
                    && !["admin", "legacy-read"].contains(&id.as_str())
                    && id
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)),
                "invalid service principal id"
            );
            ensure!(
                valid_env(&principal.token_env) && environments.insert(&principal.token_env),
                "service credential environment names must be valid and unique"
            );
            ensure!(
                principal
                    .expires_at
                    .is_none_or(|date| date.timestamp() > 0 && date.year() <= 9999),
                "invalid service credential expiry"
            );
            ensure!(
                !principal.grants.is_empty() && principal.grants.len() <= 256,
                "between one and 256 service grants required"
            );
            for grant in &principal.grants {
                let repository = repositories
                    .get(&grant.repository)
                    .ok_or_else(|| anyhow::anyhow!("unknown grant repository"))?;
                let unique: BTreeSet<_> = grant.actions.iter().collect();
                ensure!(
                    !unique.is_empty() && unique.len() == grant.actions.len(),
                    "grant actions must be nonempty and unique"
                );
                ensure!(
                    repository.kind == RepositoryKind::Hosted
                        || grant.actions.iter().all(|action| *action == Action::Read),
                    "write and promote require a hosted repository"
                );
                ensure!(
                    grant
                        .namespace
                        .as_ref()
                        .is_none_or(|namespace| repository.ecosystem == Ecosystem::Maven
                            && valid_namespace(namespace)),
                    "namespace grants require a canonical Maven group"
                );
            }
        }
        let mut owners = BTreeSet::new();
        for owner in &self.maven_owners {
            ensure!(
                valid_namespace(&owner.namespace),
                "invalid Maven ownership namespace"
            );
            ensure!(
                repositories
                    .get(&owner.repository)
                    .is_some_and(|repo| repo.ecosystem == Ecosystem::Maven),
                "Maven ownership requires a Maven repository"
            );
            ensure!(
                owners.insert((&owner.namespace, &owner.repository)),
                "duplicate Maven ownership rule"
            );
            let additional: BTreeSet<_> = owner.additional_repositories.iter().collect();
            ensure!(
                owner.additional_repositories.len() <= 16
                    && additional.len() == owner.additional_repositories.len()
                    && !additional.contains(&owner.repository),
                "at most 16 unique additional authoritative repositories, excluding the primary"
            );
            ensure!(
                owner.additional_repositories.iter().all(|name| repositories
                    .get(name)
                    .is_some_and(|repo| repo.kind == RepositoryKind::Hosted
                        && repo.ecosystem == Ecosystem::Maven)),
                "additional authoritative repositories must be hosted Maven repositories"
            );
        }
        for (index, owner) in self.maven_owners.iter().enumerate() {
            for other in &self.maven_owners[index + 1..] {
                ensure!(
                    owner.authoritative_set() == other.authoritative_set()
                        || !(namespace_matches(&owner.namespace, &other.namespace)
                            || namespace_matches(&other.namespace, &owner.namespace)),
                    "overlapping Maven ownership must have identical authoritative repositories"
                );
            }
        }
        Ok(())
    }

    /// Reservations apply across all Maven repositories, including legacy read requests.
    pub fn owner_allowed(&self, repository: &str, group: &str) -> bool {
        valid_namespace(group)
            && self.maven_owners.iter().all(|owner| {
                !namespace_matches(&owner.namespace, group) || owner.admits(repository)
            })
    }

    /// Preflight before URL resolution, discovery requests, cache reads, or upstream I/O.
    /// Unknown CDN targets cannot establish that they are outside reserved namespaces.
    pub fn maven_path_allowed(&self, repository: &str, repo: &Repository, path: &str) -> bool {
        if repo.ecosystem != Ecosystem::Maven || self.maven_owners.is_empty() {
            return true;
        }
        let Some(relative) = maven_relative_path(repo, path) else {
            return false;
        };
        // Dotted directory components may describe the same semantic group.
        // Reserve their aliases even for unsupported snapshot/custom paths.
        let reservation_path = relative.replace('.', "/");
        self.maven_owners.iter().all(|owner| {
            let prefix = owner.namespace.replace('.', "/");
            !(reservation_path == prefix
                || reservation_path
                    .strip_prefix(&prefix)
                    .is_some_and(|tail| tail.starts_with('/')))
                || owner.admits(repository)
        })
    }

    pub fn maven_url_allowed(
        &self,
        repository: &str,
        repo: &Repository,
        target: &url::Url,
    ) -> bool {
        if repo.ecosystem != Ecosystem::Maven || self.maven_owners.is_empty() {
            return true;
        }
        target_relative_path(repo, target)
            .is_some_and(|path| self.maven_path_allowed(repository, repo, &path))
    }
}

fn target_relative_path(repo: &Repository, target: &url::Url) -> Option<String> {
    let upstream = repo.proxy_upstream().ok()?;
    if target.origin() != upstream.origin()
        || !target.username().is_empty()
        || target.password().is_some()
        || target.query().is_some()
    {
        return None;
    }
    Some(target.path().strip_prefix(upstream.path())?.to_owned())
}

/// Canonical Maven paths only. A wrapped URL must stay under the configured upstream base.
pub fn maven_relative_path(repo: &Repository, path: &str) -> Option<String> {
    if repo.ecosystem != Ecosystem::Maven {
        return None;
    }
    let relative = if let Some(encoded) = path.strip_prefix("_fetch/") {
        let target = crate::registry::unwrap_path(encoded).ok()?;
        target_relative_path(repo, &target)?
    } else {
        path.to_owned()
    };
    if relative.len() > 4096
        || relative.starts_with('/')
        || relative.contains(['%', '\\', '?', '#'])
        || relative.bytes().any(|byte| !byte.is_ascii_graphic())
        || relative
            .split('/')
            .any(|part| part == "." || part == ".." || (part.is_empty() && !relative.is_empty()))
    {
        return None;
    }
    Some(relative)
}

#[derive(Clone)]
pub struct Principal {
    pub id: String,
    legacy_read: bool,
    expires_at: Option<DateTime<Utc>>,
    grants: Vec<Grant>,
}

impl Principal {
    /// Copying grants no destination publication authority and transfers no source approval.
    pub fn allows_copy(&self, source: &str, destination: &str, group: &str) -> bool {
        source != destination
            && valid_namespace(group)
            && self.allows(source, Action::Read, Some(group))
            && self.allows(destination, Action::Write, Some(group))
    }

    pub fn allows(&self, repository: &str, action: Action, namespace: Option<&str>) -> bool {
        if self.expires_at.is_some_and(|expiry| expiry <= Utc::now()) {
            return false;
        }
        if self.legacy_read {
            return action == Action::Read;
        }
        self.grants.iter().any(|grant| {
            grant.repository == repository
                && grant.actions.contains(&action)
                && grant.namespace.as_ref().is_none_or(|expected| {
                    namespace.is_some_and(|actual| {
                        valid_namespace(actual) && namespace_matches(expected, actual)
                    })
                })
        })
    }

    pub fn allows_path(
        &self,
        repository: &str,
        repo: &Repository,
        action: Action,
        path: &str,
    ) -> bool {
        if self.allows(repository, action, None) {
            return true;
        }
        let Some(relative) = maven_relative_path(repo, path) else {
            return false;
        };
        let Ok(resource) = crate::maven::parse_read_path(&relative) else {
            return false;
        };
        let group = match resource {
            crate::maven::ReadPath::Artifact { coordinate }
            | crate::maven::ReadPath::Checksum { coordinate, .. } => coordinate.group,
            crate::maven::ReadPath::Metadata { name, .. } => match name.split_once(':') {
                Some((group, _)) => group.to_owned(),
                None => return false,
            },
        };
        self.allows(repository, action, Some(&group))
    }

    pub fn allows_url(
        &self,
        repository: &str,
        repo: &Repository,
        action: Action,
        target: &url::Url,
    ) -> bool {
        self.allows(repository, action, None)
            || target_relative_path(repo, target)
                .is_some_and(|path| self.allows_path(repository, repo, action, &path))
    }
}

#[derive(Clone)]
pub struct AccessControl {
    legacy_digest: Option<String>,
    services: Vec<(String, Principal)>,
}

impl AccessControl {
    /// Resolve secrets only in the serving process, never during config validation/workers.
    pub fn load(config: &Config, admin: &str, read: &str) -> Result<Self> {
        let mut tokens = BTreeMap::new();
        for (id, principal) in &config.access.principals {
            let value = std::env::var(&principal.token_env)
                .map_err(|_| anyhow::anyhow!("service credential environment value unavailable"))?;
            tokens.insert(id.clone(), value);
        }
        Self::from_tokens(config, admin, read, &tokens)
    }

    /// Explicit secret injection for embedders/tests; identical validation to environment loading.
    pub fn from_tokens(
        config: &Config,
        admin: &str,
        read: &str,
        tokens: &BTreeMap<String, String>,
    ) -> Result<Self> {
        config.access.validate(&config.repositories)?;
        ensure!(
            admin.len() >= 32 && read.len() >= 32 && admin != read,
            "distinct admin/read credentials of at least 32 bytes required"
        );
        ensure!(
            tokens.keys().eq(config.access.principals.keys()),
            "service credential set must match configured principals"
        );
        let mut seen = BTreeSet::from([sha256(admin.as_bytes()), sha256(read.as_bytes())]);
        let mut services = Vec::new();
        for (id, principal) in &config.access.principals {
            let token = &tokens[id];
            ensure!(
                token.len() >= 32
                    && token.len() <= 4096
                    && token.bytes().all(|b| b.is_ascii_graphic()),
                "service credentials require 32 through 4096 visible ASCII bytes"
            );
            let digest = sha256(token.as_bytes());
            ensure!(
                seen.insert(digest.clone()),
                "service credentials must be distinct"
            );
            services.push((
                digest,
                Principal {
                    id: id.clone(),
                    legacy_read: false,
                    expires_at: principal.expires_at,
                    grants: principal.grants.clone(),
                },
            ));
        }
        Ok(Self {
            legacy_digest: config
                .access
                .legacy_read_enabled
                .then(|| sha256(read.as_bytes())),
            services,
        })
    }

    pub fn authenticate(&self, headers: &HeaderMap) -> Option<Principal> {
        if headers.get_all(header::AUTHORIZATION).iter().count() != 1 {
            return None;
        }
        let raw = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
        if raw.len() > 8192 {
            return None;
        }
        let candidate = if let Some(value) = raw.strip_prefix("Bearer ") {
            value.to_owned()
        } else if let Some(value) = raw.strip_prefix("Basic ") {
            let decoded = base64::engine::general_purpose::STANDARD
                .decode(value)
                .ok()?;
            let decoded = String::from_utf8(decoded).ok()?;
            decoded.split_once(':')?.1.to_owned()
        } else {
            raw.to_owned()
        };
        let digest = sha256(candidate.as_bytes());
        let mut found = self
            .legacy_digest
            .as_ref()
            .is_some_and(|expected| bool::from(digest.as_bytes().ct_eq(expected.as_bytes())))
            .then(|| Principal {
                id: "legacy-read".into(),
                legacy_read: true,
                expires_at: None,
                grants: vec![],
            });
        for (expected, principal) in &self.services {
            if bool::from(digest.as_bytes().ct_eq(expected.as_bytes()))
                && principal
                    .expires_at
                    .is_none_or(|expiry| expiry > Utc::now())
            {
                found = Some(principal.clone());
            }
        }
        found
    }
}
