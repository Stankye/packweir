//! Operator-owned service credentials and ecosystem-specific source reservations.
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
    #[serde(default)]
    pub nuget_owners: Vec<NugetOwnership>,
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
            nuget_owners: vec![],
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

/// Canonical NuGet package IDs use exact or dot-delimited prefix ownership. This is
/// deliberately separate from Maven groups: NuGet identities have no namespace.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NugetOwnership {
    pub prefix: String,
    pub repository: String,
    #[serde(default)]
    pub additional_repositories: Vec<String>,
}

impl NugetOwnership {
    fn admits(&self, repository: &str) -> bool {
        self.repository == repository
            || self
                .additional_repositories
                .iter()
                .any(|name| name == repository)
    }

    fn authoritative_set(&self) -> BTreeSet<&str> {
        std::iter::once(self.repository.as_str())
            .chain(self.additional_repositories.iter().map(String::as_str))
            .collect()
    }
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

fn valid_nuget_prefix(prefix: &str) -> bool {
    crate::identity::canonical_name(Ecosystem::Nuget, prefix).as_deref() == Some(prefix)
}

fn valid_selector(ecosystem: Ecosystem, selector: &str) -> bool {
    match ecosystem {
        Ecosystem::Maven => valid_namespace(selector),
        Ecosystem::Nuget => valid_nuget_prefix(selector),
        _ => false,
    }
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
            self.principals.len() <= 256
                && self.maven_owners.len() <= 256
                && self.nuget_owners.len() <= 256,
            "at most 256 service principals and owners per ecosystem"
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
                        .is_none_or(|namespace| valid_selector(repository.ecosystem, namespace)),
                    "namespace grants require a canonical Maven group or NuGet package ID prefix"
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
        let mut owners = BTreeSet::new();
        for owner in &self.nuget_owners {
            ensure!(
                valid_nuget_prefix(&owner.prefix),
                "invalid NuGet ownership prefix"
            );
            ensure!(
                repositories
                    .get(&owner.repository)
                    .is_some_and(|repo| repo.ecosystem == Ecosystem::Nuget),
                "NuGet ownership requires a NuGet repository"
            );
            ensure!(
                owners.insert((&owner.prefix, &owner.repository)),
                "duplicate NuGet ownership rule"
            );
            let additional: BTreeSet<_> = owner.additional_repositories.iter().collect();
            ensure!(
                additional.len() <= 16
                    && additional.len() == owner.additional_repositories.len()
                    && !additional.contains(&owner.repository),
                "at most 16 unique additional authoritative repositories, excluding the primary"
            );
            ensure!(
                owner.additional_repositories.iter().all(|name| repositories
                    .get(name)
                    .is_some_and(|repo| repo.kind == RepositoryKind::Hosted
                        && repo.ecosystem == Ecosystem::Nuget)),
                "additional authoritative repositories must be hosted NuGet repositories"
            );
        }
        for (index, owner) in self.nuget_owners.iter().enumerate() {
            for other in &self.nuget_owners[index + 1..] {
                ensure!(
                    owner.authoritative_set() == other.authoritative_set()
                        || !(namespace_matches(&owner.prefix, &other.prefix)
                            || namespace_matches(&other.prefix, &owner.prefix)),
                    "overlapping NuGet ownership must have identical authoritative repositories"
                );
            }
        }
        Ok(())
    }

    pub fn owner_allowed_for(
        &self,
        repository: &str,
        ecosystem: Ecosystem,
        selector: &str,
    ) -> bool {
        match ecosystem {
            Ecosystem::Maven => self.owner_allowed(repository, selector),
            Ecosystem::Nuget => {
                valid_nuget_prefix(selector)
                    && self.nuget_owners.iter().all(|owner| {
                        !namespace_matches(&owner.prefix, selector) || owner.admits(repository)
                    })
            }
            _ => false,
        }
    }

    pub fn package_owner_allowed(
        &self,
        repository: &str,
        package: &crate::identity::PackageIdentity,
    ) -> bool {
        package.is_canonical()
            && package_selector(package).is_some_and(|selector| {
                self.owner_allowed_for(repository, package.ecosystem, selector)
            })
    }

    /// Preflight all supported source reservations before discovery, cache, and upstream I/O.
    pub fn path_allowed(&self, repository: &str, repo: &Repository, path: &str) -> bool {
        match repo.ecosystem {
            Ecosystem::Maven => self.maven_path_allowed(repository, repo, path),
            Ecosystem::Nuget if !self.nuget_owners.is_empty() => nuget_resource(repo, path)
                .is_some_and(|resource| match resource {
                    NugetResource::ServiceIndex => true,
                    NugetResource::Package(name) => {
                        self.owner_allowed_for(repository, Ecosystem::Nuget, &name)
                    }
                }),
            _ => true,
        }
    }

    pub fn url_allowed(&self, repository: &str, repo: &Repository, target: &url::Url) -> bool {
        match repo.ecosystem {
            Ecosystem::Maven => self.maven_url_allowed(repository, repo, target),
            Ecosystem::Nuget if !self.nuget_owners.is_empty() => nuget_url_resource(repo, target)
                .is_some_and(|resource| match resource {
                    NugetResource::ServiceIndex => true,
                    NugetResource::Package(name) => {
                        self.owner_allowed_for(repository, Ecosystem::Nuget, &name)
                    }
                }),
            _ => true,
        }
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

pub fn package_selector(package: &crate::identity::PackageIdentity) -> Option<&str> {
    match package.ecosystem {
        Ecosystem::Maven => package.namespace.as_deref(),
        Ecosystem::Nuget => Some(&package.name),
        _ => None,
    }
}

enum NugetResource {
    ServiceIndex,
    Package(String),
}

fn clean_relative_path(path: &str) -> bool {
    path.len() <= 4096
        && !path.starts_with('/')
        && !path.contains(['%', '\\', '?', '#'])
        && path.bytes().all(|byte| byte.is_ascii_graphic())
        && !path
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
}

/// Recognize package-bearing V3 resources, including the NuGet.org spelling and
/// flat-container resources used by private feeds. Unknown resources cannot prove
/// that they are outside a reservation and therefore have no ownership selector.
fn nuget_relative_resource(path: &str, direct_flat: bool) -> Option<NugetResource> {
    if !clean_relative_path(path) {
        return None;
    }
    let lower = path.to_ascii_lowercase();
    if matches!(lower.as_str(), "index.json" | "v3/index.json") {
        return Some(NugetResource::ServiceIndex);
    }
    let mut parts: Vec<_> = lower.split('/').collect();
    if parts.first() == Some(&"v3") {
        parts.remove(0);
    }
    if parts
        .first()
        .is_some_and(|part| matches!(*part, "flatcontainer" | "v3-flatcontainer" | "flat"))
    {
        return nuget_flat_resource(&parts[1..].join("/"));
    }
    if parts.first().is_some_and(|part| {
        matches!(
            *part,
            "registration"
                | "registrations"
                | "registration5-semver1"
                | "registration5-gz-semver1"
                | "registration5-gz-semver2"
        )
    }) {
        let tail = &parts[1..];
        let name = crate::identity::canonical_name(Ecosystem::Nuget, tail.first()?)?;
        let supported = match tail {
            [_, "index.json"] => true,
            [_, leaf] => leaf
                .strip_suffix(".json")
                .is_some_and(|version| crate::nuget::Coordinate::new(&name, version).is_ok()),
            [_, "page", first, last] => last.strip_suffix(".json").is_some_and(|last| {
                crate::nuget::Coordinate::new(&name, first).is_ok()
                    && crate::nuget::Coordinate::new(&name, last).is_ok()
            }),
            _ => false,
        };
        return supported.then_some(NugetResource::Package(name));
    }
    direct_flat.then(|| nuget_flat_resource(&lower)).flatten()
}

fn nuget_flat_resource(path: &str) -> Option<NugetResource> {
    use crate::nuget::ReadPath;
    let name = match crate::nuget::parse_read_path(path).ok()? {
        ReadPath::Versions { name } => name,
        ReadPath::Package { coordinate }
        | ReadPath::Nuspec { coordinate }
        | ReadPath::Sha512 { coordinate } => coordinate.name,
    };
    Some(NugetResource::Package(name))
}

fn nuget_url_resource(repo: &Repository, target: &url::Url) -> Option<NugetResource> {
    if repo.ecosystem != Ecosystem::Nuget
        || !crate::network::allowed(repo, target)
        || target.query().is_some()
        || !target.username().is_empty()
        || target.password().is_some()
    {
        return None;
    }
    if let Some(relative) = target_relative_path(repo, target) {
        let upstream = repo.proxy_upstream().ok()?;
        let direct_flat = upstream
            .path()
            .trim_end_matches('/')
            .rsplit('/')
            .next()
            .is_some_and(|part| matches!(part, "flatcontainer" | "v3-flatcontainer" | "flat"));
        if let Some(resource) = nuget_relative_resource(&relative, direct_flat) {
            return Some(resource);
        }
    }
    match nuget_relative_resource(target.path().strip_prefix('/')?, false)? {
        NugetResource::ServiceIndex => None,
        resource => Some(resource),
    }
}

fn nuget_resource(repo: &Repository, path: &str) -> Option<NugetResource> {
    if let Some(encoded) = path.strip_prefix("_fetch/") {
        return nuget_url_resource(repo, &crate::registry::unwrap_path(encoded).ok()?);
    }
    nuget_relative_resource(path, false)
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
    ecosystems: BTreeMap<String, Ecosystem>,
}

impl Principal {
    /// Copying grants no destination publication authority and transfers no source approval.
    pub fn allows_copy(&self, source: &str, destination: &str, group: &str) -> bool {
        source != destination
            && self.ecosystems.get(source) == Some(&Ecosystem::Maven)
            && self.ecosystems.get(destination) == Some(&Ecosystem::Maven)
            && valid_namespace(group)
            && self.allows(source, Action::Read, Some(group))
            && self.allows(destination, Action::Write, Some(group))
    }

    pub fn allows_package(
        &self,
        repository: &str,
        action: Action,
        package: &crate::identity::PackageIdentity,
    ) -> bool {
        package.is_canonical()
            && self.ecosystems.get(repository) == Some(&package.ecosystem)
            && package_selector(package)
                .is_some_and(|selector| self.allows(repository, action, Some(selector)))
    }

    pub fn allows_package_copy(
        &self,
        source: &str,
        destination: &str,
        package: &crate::identity::PackageIdentity,
    ) -> bool {
        source != destination
            && self.allows_package(source, Action::Read, package)
            && self.allows_package(destination, Action::Write, package)
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
                        self.ecosystems
                            .get(repository)
                            .is_some_and(|ecosystem| valid_selector(*ecosystem, actual))
                            && namespace_matches(expected, actual)
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
        if repo.ecosystem == Ecosystem::Nuget {
            return nuget_resource(repo, path).is_some_and(|resource| match resource {
                NugetResource::ServiceIndex => {
                    action == Action::Read
                        && !self.expires_at.is_some_and(|expiry| expiry <= Utc::now())
                        && self.grants.iter().any(|grant| {
                            grant.repository == repository && grant.actions.contains(&Action::Read)
                        })
                }
                NugetResource::Package(name) => self.allows(repository, action, Some(&name)),
            });
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
        if self.allows(repository, action, None) {
            return true;
        }
        if repo.ecosystem == Ecosystem::Nuget {
            return nuget_url_resource(repo, target).is_some_and(|resource| match resource {
                NugetResource::ServiceIndex => {
                    action == Action::Read
                        && !self.expires_at.is_some_and(|expiry| expiry <= Utc::now())
                        && self.grants.iter().any(|grant| {
                            grant.repository == repository && grant.actions.contains(&Action::Read)
                        })
                }
                NugetResource::Package(name) => self.allows(repository, action, Some(&name)),
            });
        }
        target_relative_path(repo, target)
            .is_some_and(|path| self.allows_path(repository, repo, action, &path))
    }
}

#[derive(Clone)]
pub struct AccessControl {
    legacy_digest: Option<String>,
    services: Vec<(String, Principal)>,
    ecosystems: BTreeMap<String, Ecosystem>,
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
                    ecosystems: config
                        .repositories
                        .iter()
                        .map(|(name, repo)| (name.clone(), repo.ecosystem))
                        .collect(),
                },
            ));
        }
        Ok(Self {
            legacy_digest: config
                .access
                .legacy_read_enabled
                .then(|| sha256(read.as_bytes())),
            services,
            ecosystems: config
                .repositories
                .iter()
                .map(|(name, repo)| (name.clone(), repo.ecosystem))
                .collect(),
        })
    }

    pub fn authenticate(&self, headers: &HeaderMap) -> Option<Principal> {
        if headers.contains_key("x-nuget-apikey") {
            return None;
        }
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
        self.authenticate_candidate(&candidate)
    }

    /// Native push credentials have authority only at the explicit NuGet push handler.
    /// A second credential source is ambiguous even when both contain the same secret.
    pub fn authenticate_nuget_push(&self, headers: &HeaderMap) -> Option<Principal> {
        let keys = headers.get_all("x-nuget-apikey").iter().count();
        if keys == 0 {
            return self.authenticate(headers);
        }
        if keys != 1 || headers.contains_key(header::AUTHORIZATION) {
            return None;
        }
        let candidate = headers.get("x-nuget-apikey")?.to_str().ok()?;
        if candidate.is_empty()
            || candidate.len() > 4096
            || !candidate.bytes().all(|b| b.is_ascii_graphic())
        {
            return None;
        }
        self.authenticate_candidate(candidate)
    }

    fn authenticate_candidate(&self, candidate: &str) -> Option<Principal> {
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
                ecosystems: self.ecosystems.clone(),
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
