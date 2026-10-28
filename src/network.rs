pub use crate::bounds::public_ip;
use crate::config::Repository;
use anyhow::{Result, bail, ensure};
use bytes::Bytes;
use reqwest::header::{ACCEPT, AUTHORIZATION, LOCATION};
use std::{net::SocketAddr, time::Duration};
use url::Url;

pub struct Download {
    pub bytes: Bytes,
    pub content_type: String,
    pub status: u16,
}

pub fn allowed(repo: &Repository, url: &Url) -> bool {
    url.username().is_empty()
        && url.password().is_none()
        && ((repo.upstream.origin() == url.origin()
            && url.path().starts_with(repo.upstream.path()))
            || repo
                .download_origins
                .iter()
                .any(|base| base.origin() == url.origin()))
}

pub async fn fetch(
    repo: &Repository,
    target: &Url,
    accept: Option<&str>,
    max: usize,
    allow_private: bool,
) -> Result<Download> {
    let mut current = target.clone();
    current.set_fragment(None);
    for _ in 0..6 {
        ensure!(allowed(repo, &current), "upstream origin is not allowed");
        ensure!(
            current.scheme() == "https" || (allow_private && current.scheme() == "http"),
            "HTTPS required"
        );
        let host = current
            .host_str()
            .ok_or_else(|| anyhow::anyhow!("missing host"))?
            .trim_matches(['[', ']']);
        let port = current
            .port_or_known_default()
            .ok_or_else(|| anyhow::anyhow!("missing port"))?;
        let addresses: Vec<SocketAddr> = tokio::time::timeout(
            Duration::from_secs(10),
            tokio::net::lookup_host((host, port)),
        )
        .await??
        .collect();
        ensure!(
            !addresses.is_empty() && (allow_private || addresses.iter().all(|a| public_ip(a.ip()))),
            "upstream resolved to a forbidden address"
        );
        // Pin this connection to the validated resolution, avoiding a DNS rebind between check and connect.
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .timeout(Duration::from_secs(60))
            .connect_timeout(Duration::from_secs(10))
            .resolve_to_addrs(host, &addresses)
            .build()?;
        let mut request = client.get(current.clone());
        if let Some(accept) = accept {
            request = request.header(ACCEPT, accept);
        }
        // Credentials are operator-owned and never forwarded to a download/redirect origin.
        if current.origin() == repo.upstream.origin()
            && current.path().starts_with(repo.upstream.path())
            && let Some(name) = &repo.token_env
        {
            request = request.header(AUTHORIZATION, format!("Bearer {}", std::env::var(name)?));
        }
        let mut response = request.send().await?;
        if response.status().is_redirection() {
            let location = response
                .headers()
                .get(LOCATION)
                .ok_or_else(|| anyhow::anyhow!("redirect missing location"))?
                .to_str()?;
            current = current.join(location)?;
            continue;
        }
        let status = response.status().as_u16();
        let content_type = response
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("application/octet-stream")
            .to_owned();
        if let Some(size) = response.content_length() {
            ensure!(size <= max as u64, "download exceeds configured size limit");
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            ensure!(
                bytes.len().saturating_add(chunk.len()) <= max,
                "download exceeds configured size limit"
            );
            bytes.extend_from_slice(&chunk);
        }
        return Ok(Download {
            bytes: bytes.into(),
            content_type,
            status,
        });
    }
    bail!("redirect limit exceeded")
}

pub fn verify_fragment(url: &Url, bytes: &[u8]) -> Result<()> {
    use base64::Engine;
    use sha2::Digest;
    if let Some(fragment) = url.fragment() {
        if let Some(expected) = fragment.strip_prefix("sha256=") {
            ensure!(
                crate::model::sha256(bytes).eq_ignore_ascii_case(expected),
                "upstream SHA-256 mismatch"
            );
        } else if let Some(expected) = fragment.strip_prefix("sha512=") {
            let digest =
                base64::engine::general_purpose::STANDARD.encode(sha2::Sha512::digest(bytes));
            ensure!(digest == expected, "upstream SHA-512 mismatch");
        } else if let Some(expected) = fragment.strip_prefix("sha1=") {
            ensure!(
                hex::encode(sha1::Sha1::digest(bytes)).eq_ignore_ascii_case(expected),
                "upstream SHA-1 mismatch"
            );
        } else if fragment.contains('=') {
            bail!("unsupported integrity fragment");
        }
    }
    Ok(())
}
