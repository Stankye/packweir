//! Registry-path observations identify a delivery context, never a trusted publisher or source.
use crate::{config::Repository, model::Ecosystem};
use serde::{Deserialize, Serialize};
use url::Url;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackageIdentity {
    pub ecosystem: Ecosystem,
    pub name: String,
    pub version: String,
    pub namespace: Option<String>,
    pub purl: String,
    pub basis: String,
}

impl PackageIdentity {
    pub fn is_canonical(&self) -> bool {
        let Some(mut expected) = package(self.ecosystem, &self.name, &self.version) else {
            return false;
        };
        if !["registry_path_observed", "registry_metadata_observed"].contains(&self.basis.as_str())
        {
            return false;
        }
        expected.basis = self.basis.clone();
        &expected == self
    }
}

pub struct IdentityClaim {
    pub origin: String,
    pub source: String,
    pub package: Option<PackageIdentity>,
}

fn target_from_rewritten(raw: &str) -> anyhow::Result<Url> {
    let wrapped = Url::parse(raw)?;
    let encoded = wrapped
        .path()
        .split_once("/_fetch/")
        .ok_or_else(|| anyhow::anyhow!("distribution link was not rewritten"))?
        .1;
    let decoded = percent_encoding::percent_decode_str(encoded).decode_utf8()?;
    crate::registry::unwrap_path(&decoded)
}

fn metadata_identity(
    ecosystem: Ecosystem,
    name: &str,
    version: &str,
) -> anyhow::Result<PackageIdentity> {
    let mut identity = package(ecosystem, name, version)
        .ok_or_else(|| anyhow::anyhow!("invalid registry coordinates"))?;
    identity.basis = "registry_metadata_observed".into();
    Ok(identity)
}

pub fn json_claims(
    repo: &Repository,
    source: &Url,
    value: &serde_json::Value,
) -> anyhow::Result<Vec<IdentityClaim>> {
    use anyhow::{Context, ensure};
    if source.origin() != repo.upstream.origin() {
        return Ok(vec![]);
    }
    let relative = percent_encoding::percent_decode_str(
        source
            .path()
            .strip_prefix(repo.upstream.path())
            .unwrap_or(""),
    )
    .decode_utf8()?
    .trim_matches('/')
    .to_owned();
    let mut claims = Vec::new();
    match repo.ecosystem {
        Ecosystem::Npm => {
            let parts: Vec<_> = relative.split('/').collect();
            let count = if relative.starts_with('@') { 2 } else { 1 };
            let has_packages = value.get("versions").is_some() || value.get("dist").is_some();
            if !has_packages {
                return Ok(claims);
            }
            ensure!(
                (parts.len() == count || parts.len() == count + 1) && parts.len() >= count,
                "unsupported npm discovery route"
            );
            let requested = canonical_name(Ecosystem::Npm, &parts[..count].join("/"))
                .context("invalid requested npm package")?;
            if let Some(name) = value.get("name").and_then(|v| v.as_str()) {
                ensure!(
                    canonical_name(Ecosystem::Npm, name).as_deref() == Some(&requested),
                    "npm discovery package name mismatch"
                );
            }
            let mut add = |version: &str, entry: &serde_json::Value| -> anyhow::Result<()> {
                if let Some(name) = entry.get("name").and_then(|v| v.as_str()) {
                    ensure!(
                        canonical_name(Ecosystem::Npm, name).as_deref() == Some(&requested),
                        "npm manifest package mismatch"
                    );
                }
                if let Some(declared) = entry.get("version").and_then(|v| v.as_str()) {
                    ensure!(declared == version, "npm manifest version mismatch");
                }
                if let Some(raw) = entry.pointer("/dist/tarball").and_then(|v| v.as_str()) {
                    ensure!(
                        claims.len() < 10000,
                        "registry identity claim limit exceeded"
                    );
                    let target = target_from_rewritten(raw)?;
                    claims.push(IdentityClaim {
                        origin: target.into(),
                        source: source.to_string(),
                        package: Some(metadata_identity(Ecosystem::Npm, &requested, version)?),
                    });
                }
                Ok(())
            };
            if let Some(versions) = value.get("versions").and_then(|v| v.as_object()) {
                for (version, entry) in versions {
                    add(version, entry)?;
                }
            } else {
                let version = value
                    .get("version")
                    .and_then(|v| v.as_str())
                    .context("npm manifest version missing")?;
                add(version, value)?;
            }
        }
        Ecosystem::Pypi => {
            let Some(name) = pypi_project(&relative) else {
                return Ok(claims);
            };
            if let Some(files) = value.get("files").and_then(|v| v.as_array()) {
                for file in files {
                    let raw = file
                        .get("url")
                        .and_then(|v| v.as_str())
                        .context("PyPI file URL missing")?;
                    let target = target_from_rewritten(raw)?;
                    let package = file
                        .get("filename")
                        .and_then(|v| v.as_str())
                        .and_then(pypi_coordinates)
                        .and_then(|(observed, version)| {
                            (canonical_name(Ecosystem::Pypi, observed).as_ref() == Some(&name))
                                .then_some(version)
                        })
                        .map(|version| metadata_identity(Ecosystem::Pypi, &name, version))
                        .transpose()?;
                    claims.push(IdentityClaim {
                        origin: target.into(),
                        source: source.to_string(),
                        package,
                    });
                }
            }
        }
        _ => {}
    }
    anyhow::ensure!(
        claims.len() <= 10000,
        "registry identity claim limit exceeded"
    );
    Ok(claims)
}

fn pypi_project(relative: &str) -> Option<String> {
    (!relative.contains('/') && !relative.is_empty())
        .then(|| canonical_name(Ecosystem::Pypi, relative))
        .flatten()
}

fn pypi_coordinates(file: &str) -> Option<(&str, &str)> {
    if let Some(stem) = file.strip_suffix(".whl") {
        let parts: Vec<_> = stem.split('-').collect();
        if !(parts.len() == 5 || parts.len() == 6) {
            return None;
        }
        Some((parts[0], parts[1]))
    } else {
        file.strip_suffix(".tar.gz")?.rsplit_once('-')
    }
}

pub fn html_claims(
    repo: &Repository,
    source: &Url,
    html: &str,
) -> anyhow::Result<Vec<IdentityClaim>> {
    use lol_html::{RewriteStrSettings, element, rewrite_str};
    if source.origin() != repo.upstream.origin() {
        return Ok(vec![]);
    }
    let relative = source
        .path()
        .strip_prefix(repo.upstream.path())
        .unwrap_or("")
        .trim_matches('/');
    let Some(name) = pypi_project(relative) else {
        return Ok(vec![]);
    };
    let mut claims = Vec::new();
    rewrite_str(
        html,
        RewriteStrSettings {
            element_content_handlers: vec![element!("a[href]", |el| {
                if let Some(raw) = el.get_attribute("href") {
                    let target = source.join(&raw)?;
                    let package =
                        observe(repo, &target, "")
                            .filter(|p| p.name == name)
                            .map(|mut p| {
                                p.basis = "registry_metadata_observed".into();
                                p
                            });
                    claims.push(IdentityClaim {
                        origin: target.into(),
                        source: source.to_string(),
                        package,
                    });
                    if claims.len() > 10000 {
                        return Err("registry identity claim limit exceeded".into());
                    }
                }
                Ok(())
            })],
            ..RewriteStrSettings::default()
        },
    )?;
    Ok(claims)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeliveryScope {
    pub repository: String,
    pub origin: String,
    pub filename: String,
    pub package: Option<PackageIdentity>,
}

fn simple(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        && value
            .bytes()
            .next()
            .is_some_and(|b| b.is_ascii_alphanumeric())
        && value
            .bytes()
            .last()
            .is_some_and(|b| b.is_ascii_alphanumeric())
}

pub fn canonical_name(ecosystem: Ecosystem, value: &str) -> Option<String> {
    match ecosystem {
        Ecosystem::Npm => {
            let parts: Vec<_> = value.trim_start_matches('@').split('/').collect();
            if !((parts.len() == 1 && !value.starts_with('@'))
                || (parts.len() == 2 && value.starts_with('@')))
                || !parts.iter().all(|p| simple(p))
                || value.contains("@@")
            {
                return None;
            }
            Some(value.to_ascii_lowercase())
        }
        Ecosystem::Maven => {
            let (group, artifact) = value.split_once(':')?;
            (group.split('.').all(simple) && simple(artifact)).then(|| value.to_owned())
        }
        Ecosystem::Pypi => {
            if !simple(value) {
                return None;
            }
            let mut result = String::new();
            for c in value.chars() {
                if matches!(c, '-' | '_' | '.') {
                    if !result.ends_with('-') {
                        result.push('-');
                    }
                } else {
                    result.push(c.to_ascii_lowercase());
                }
            }
            Some(result)
        }
        Ecosystem::Cargo => {
            (simple(value) && !value.contains('.')).then(|| value.to_ascii_lowercase())
        }
        Ecosystem::Nuget => simple(value).then(|| value.to_ascii_lowercase()),
    }
}

fn encode(value: &str) -> String {
    let mut encoded = String::new();
    for b in value.bytes() {
        if b.is_ascii_alphanumeric() || b"._~-".contains(&b) {
            encoded.push(b as char);
        } else {
            encoded.push_str(&format!("%{b:02X}"));
        }
    }
    encoded
}

fn package(ecosystem: Ecosystem, name: &str, version: &str) -> Option<PackageIdentity> {
    let name = canonical_name(ecosystem, name)?;
    if version.is_empty()
        || version.len() > 256
        || !version
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._+-".contains(&b))
    {
        return None;
    }
    let (kind, namespace, path) = match ecosystem {
        Ecosystem::Npm => (
            "npm",
            name.split_once('/').map(|(n, _)| n.to_owned()),
            name.split('/').map(encode).collect::<Vec<_>>().join("/"),
        ),
        Ecosystem::Pypi => ("pypi", None, encode(&name)),
        Ecosystem::Cargo => ("cargo", None, encode(&name)),
        Ecosystem::Nuget => ("nuget", None, encode(&name)),
        Ecosystem::Maven => {
            let (group, artifact) = name.split_once(':')?;
            (
                "maven",
                Some(group.to_owned()),
                format!("{}/{}", encode(group), encode(artifact)),
            )
        }
    };
    Some(PackageIdentity {
        ecosystem,
        name,
        version: version.into(),
        namespace,
        purl: format!("pkg:{kind}/{path}@{}", encode(version)),
        basis: "registry_path_observed".into(),
    })
}

pub fn observe(repo: &Repository, url: &Url, route: &str) -> Option<PackageIdentity> {
    let segments: Vec<String> = url
        .path_segments()?
        .map(|p| {
            let part = percent_encoding::percent_decode_str(p)
                .decode_utf8()
                .ok()?
                .into_owned();
            (!part.contains(['/', '\\']) && !part.chars().any(char::is_control)).then_some(part)
        })
        .collect::<Option<_>>()?;
    let file = segments.last()?.as_str();
    match repo.ecosystem {
        Ecosystem::Cargo => {
            let parts: Vec<_> = route.strip_prefix("_cargo/")?.split('/').collect();
            if parts.len() != 3 || parts[2] != "download" {
                return None;
            }
            package(repo.ecosystem, parts[0], parts[1])
        }
        Ecosystem::Npm => {
            let separator = segments.iter().rposition(|p| p == "-")?;
            if separator == 0 || segments.len() != separator + 2 {
                return None;
            }
            let bare = &segments[separator - 1];
            let name = if separator >= 2 && segments[separator - 2].starts_with('@') {
                format!("{}/{bare}", segments[separator - 2])
            } else {
                bare.clone()
            };
            let version = file
                .strip_prefix(&format!("{bare}-"))?
                .strip_suffix(".tgz")?;
            package(repo.ecosystem, &name, version)
        }
        Ecosystem::Pypi => {
            let (name, version) = pypi_coordinates(file)?;
            package(repo.ecosystem, name, version)
        }
        Ecosystem::Nuget => {
            if segments.len() < 3 {
                return None;
            }
            let name = &segments[segments.len() - 3];
            let version = &segments[segments.len() - 2];
            if !file.eq_ignore_ascii_case(&format!("{name}.{version}.nupkg")) {
                return None;
            }
            package(repo.ecosystem, name, version)
        }
        Ecosystem::Maven => {
            if url.origin() != repo.upstream.origin() {
                return None;
            }
            let relative = url.path().strip_prefix(repo.upstream.path())?;
            let parts: Vec<_> = relative.split('/').collect();
            if parts.len() < 4 {
                return None;
            }
            let name = parts[parts.len() - 3];
            let version = parts[parts.len() - 2];
            let suffix = file.strip_prefix(&format!("{name}-{version}"))?;
            if !suffix.starts_with(['.', '-']) {
                return None;
            }
            let group = parts[..parts.len() - 3].join(".");
            package(repo.ecosystem, &format!("{group}:{name}"), version)
        }
    }
}
