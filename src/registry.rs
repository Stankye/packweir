use crate::{config::Repository, model::Ecosystem, network::allowed};
use anyhow::{Result, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::Value;
use url::Url;

pub fn wrap(public: &Url, name: &str, target: &Url) -> String {
    let mut wrapped = public.clone();
    let token = URL_SAFE_NO_PAD.encode(target.as_str());
    {
        let mut segments = wrapped.path_segments_mut().expect("HTTP gateway URL");
        segments
            .pop_if_empty()
            .extend(["r", name, "_fetch", &token]);
        if target.path().ends_with('/') {
            segments.push("");
        } else if let Some(filename) = filename(target) {
            segments.push(&filename);
        }
    }
    // Keep the expected digest inside the routed target AND visible to native clients.
    wrapped.set_fragment(target.fragment());
    wrapped.into()
}

fn filename(target: &Url) -> Option<String> {
    percent_encoding::percent_decode_str(target.path().rsplit('/').next()?)
        .decode_utf8()
        .ok()
        .map(|v| v.into_owned())
}

/// Displayed filenames cannot redirect a file request; directory resources remain appendable.
pub fn unwrap_path(encoded: &str) -> Result<Url> {
    let (token, tail) = encoded.split_once('/').unwrap_or((encoded, ""));
    let base = unwrap(token)?;
    if tail.is_empty() {
        return Ok(base);
    }
    if base.path().ends_with('/') {
        ensure!(
            !tail.starts_with('/') && !tail.contains('\\') && !tail.split('/').any(|p| p == ".."),
            "invalid registry resource suffix"
        );
        let joined = base.join(tail)?;
        ensure!(
            joined.origin() == base.origin(),
            "registry suffix cannot change origin"
        );
        Ok(joined)
    } else {
        ensure!(
            filename(&base).as_deref() == Some(tail),
            "displayed filename does not match encoded target"
        );
        Ok(base)
    }
}
pub fn unwrap(token: &str) -> Result<Url> {
    Ok(Url::parse(std::str::from_utf8(
        &URL_SAFE_NO_PAD.decode(token)?,
    )?)?)
}

pub fn is_metadata(ecosystem: Ecosystem, url: &Url) -> bool {
    let p = url.path().to_ascii_lowercase();
    match ecosystem {
        Ecosystem::Npm => !p.ends_with(".tgz") && !p.ends_with(".tar.gz"),
        Ecosystem::Pypi => {
            p.split('/').any(|part| part == "simple")
                && (p.ends_with('/') || !p.rsplit('/').next().unwrap_or("").contains('.'))
        }
        Ecosystem::Cargo => !p.ends_with(".crate") && !p.ends_with("/download"),
        Ecosystem::Maven => {
            p.rsplit('/').next() == Some("maven-metadata.xml")
                || p.ends_with(".sha1")
                || p.ends_with(".sha256")
                || p.ends_with(".sha512")
                || p.ends_with(".md5")
                || p.ends_with(".asc")
        }
        Ecosystem::Nuget => {
            p.ends_with(".json") || p.trim_end_matches('/').rsplit('/').next() == Some("query")
        }
    }
}

pub fn rewrite_json(value: &mut Value, repo: &Repository, name: &str, public: &Url) -> Result<()> {
    match value {
        Value::Object(map) => {
            if repo.ecosystem == Ecosystem::Pypi
                && map.contains_key("filename")
                && map.contains_key("url")
            {
                if let Some(raw) = map.get("url").and_then(Value::as_str) {
                    let mut url = repo.upstream.join(raw)?;
                    ensure!(
                        allowed(repo, &url),
                        "PyPI distribution origin must be configured"
                    );
                    if let Some(hash) = map
                        .get("hashes")
                        .and_then(|v| v.get("sha256"))
                        .and_then(Value::as_str)
                    {
                        url.set_fragment(Some(&format!("sha256={hash}")));
                    }
                    map.insert("url".into(), Value::String(wrap(public, name, &url)));
                }
                // Clients should retrieve the complete, gated artifact until sidecar routing is supported.
                map.insert("core-metadata".into(), Value::Bool(false));
                map.insert("dist-info-metadata".into(), Value::Bool(false));
            }
            // Carry npm's upstream integrity into the artifact URL; client-visible integrity stays unchanged.
            if let Some(Value::Object(dist)) = map.get_mut("dist")
                && let Some(tarball) = dist.get("tarball").and_then(Value::as_str)
            {
                let mut url = Url::parse(tarball)?;
                ensure!(allowed(repo, &url), "npm tarball origin must be configured");
                if let Some(sri) = dist.get("integrity").and_then(Value::as_str) {
                    let sha512 = sri
                        .split_whitespace()
                        .find_map(|p| p.strip_prefix("sha512-"));
                    if let Some(hash) = sha512 {
                        url.set_fragment(Some(&format!("sha512={hash}")));
                    }
                } else if let Some(hash) = dist.get("shasum").and_then(Value::as_str) {
                    url.set_fragment(Some(&format!("sha1={hash}")));
                }
                dist.insert("tarball".into(), Value::String(wrap(public, name, &url)));
            }
            for child in map.values_mut() {
                rewrite_json(child, repo, name, public)?;
            }
        }
        Value::Array(array) => {
            for child in array {
                rewrite_json(child, repo, name, public)?;
            }
        }
        Value::String(s) => {
            if let Ok(url) = Url::parse(s)
                && allowed(repo, &url)
            {
                *s = wrap(public, name, &url);
            }
        }
        _ => {}
    }
    Ok(())
}

pub fn rewrite_html(
    html: &str,
    upstream: &Url,
    repo: &Repository,
    name: &str,
    public: &Url,
) -> Result<String> {
    use lol_html::{RewriteStrSettings, element, rewrite_str};
    // Reconstruct the simple index. Do not pass arbitrary upstream HTML or binary polyglots through.
    let mut links = Vec::new();
    rewrite_str(
        html,
        RewriteStrSettings {
            element_content_handlers: vec![element!("a[href]", |el| {
                if let Some(href) = el.get_attribute("href") {
                    let url = upstream.join(&href)?;
                    if !allowed(repo, &url) {
                        return Err("PyPI distribution origin must be configured".into());
                    }
                    let mut attributes = String::new();
                    for key in ["data-requires-python", "data-yanked"] {
                        if let Some(value) = el.get_attribute(key) {
                            attributes.push_str(&format!(" {key}=\"{}\"", html_escape(&value)));
                        }
                    }
                    let label = url
                        .path()
                        .trim_end_matches('/')
                        .rsplit('/')
                        .next()
                        .unwrap_or("package");
                    links.push(format!(
                        "<a href=\"{}\"{attributes}>{}</a>",
                        html_escape(&wrap(public, name, &url)),
                        html_escape(label)
                    ));
                }
                Ok(())
            })],
            ..RewriteStrSettings::default()
        },
    )?;
    Ok(format!(
        "<!doctype html><html><body>{}</body></html>",
        links.join("\n")
    ))
}

fn html_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

pub fn cargo_index_path(name: &str) -> Result<String> {
    ensure!(
        !name.is_empty()
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
        "invalid crate name"
    );
    let name = name.to_ascii_lowercase();
    Ok(match name.len() {
        1 => format!("1/{name}"),
        2 => format!("2/{name}"),
        3 => format!("3/{}/{name}", &name[..1]),
        _ => format!("{}/{}/{name}", &name[..2], &name[2..4]),
    })
}

pub fn validate_cargo_index(bytes: &[u8]) -> Result<()> {
    let text = std::str::from_utf8(bytes)?;
    ensure!(!text.trim().is_empty(), "empty sparse index");
    for line in text.lines() {
        let entry: Value = serde_json::from_str(line)?;
        ensure!(
            entry["name"].is_string() && entry["vers"].is_string(),
            "invalid sparse index entry"
        );
        let checksum = entry["cksum"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("missing sparse checksum"))?;
        ensure!(
            checksum.len() == 64 && checksum.bytes().all(|b| b.is_ascii_hexdigit()),
            "invalid sparse checksum"
        );
    }
    Ok(())
}
