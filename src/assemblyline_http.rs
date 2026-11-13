//! Authenticated transport to one explicitly configured Assemblyline instance.
//! Remote analysis is scheduled through durable records, never a gateway request.
use crate::{
    assemblyline::AssemblylinePolicy,
    config::PinnedResource,
    model::sha256,
    remote_analysis::{self, Binding, State},
    scanner::ScannerOutput,
    store::{Job, Store},
};
use anyhow::{Result, ensure};
use chrono::{DateTime, Utc};
use reqwest::{
    Client, Method,
    header::{HeaderMap, HeaderValue},
    multipart,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{collections::BTreeMap, net::SocketAddr, sync::Arc, time::Duration};
use url::Url;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RemoteScanner {
    Assemblyline(AssemblylineConfig),
}

impl RemoteScanner {
    pub fn assemblyline(&self) -> &AssemblylineConfig {
        match self {
            Self::Assemblyline(config) => config,
        }
    }
    pub fn validate(&self) -> Result<()> {
        self.assemblyline().validate()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssemblylineConfig {
    pub endpoint: Url,
    pub server_version: String,
    pub user_env: String,
    pub api_key_env: String,
    /// Explicit operator consent to send original package bytes to this instance.
    pub allow_upload: bool,
    pub classification: String,
    pub retention_days: u32,
    pub profile_revision: String,
    pub submission_profile: Option<String>,
    #[serde(default)]
    pub service_spec: BTreeMap<String, BTreeMap<String, Value>>,
    pub policy: AssemblylinePolicy,
    #[serde(default)]
    pub binary_analysis: Option<crate::binary_analysis::BinaryAnalysisPolicy>,
    #[serde(default)]
    pub allow_private_network: bool,
    #[serde(default)]
    pub allow_insecure_http: bool,
    #[serde(default)]
    pub allow_external_services: bool,
    #[serde(default)]
    pub allow_privileged_services: bool,
    pub ca_certificate: Option<PinnedResource>,
    #[serde(default = "request_timeout")]
    pub request_timeout_seconds: u64,
    #[serde(default = "analysis_timeout")]
    pub analysis_timeout_seconds: u64,
    #[serde(default = "poll_interval")]
    pub poll_interval_seconds: u64,
    #[serde(default = "max_failures")]
    pub max_poll_failures: u32,
}
fn request_timeout() -> u64 {
    30
}
fn analysis_timeout() -> u64 {
    3600
}
fn poll_interval() -> u64 {
    15
}
fn max_failures() -> u32 {
    3
}

fn text(value: &str, max: usize) -> bool {
    !value.trim().is_empty() && value.len() <= max && !value.chars().any(char::is_control)
}
fn environment_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .enumerate()
            .all(|(i, b)| b == b'_' || b.is_ascii_alphabetic() || (i > 0 && b.is_ascii_digit()))
}
impl AssemblylineConfig {
    pub fn validate(&self) -> Result<()> {
        self.policy.validate()?;
        if let Some(binary) = &self.binary_analysis {
            binary.validate()?;
            let pin = self
                .policy
                .required_services
                .get(&binary.service)
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "binary-analysis service must be explicitly selected and pinned"
                    )
                })?;
            ensure!(
                pin.tool_version
                    .as_deref()
                    .is_some_and(|v| v.ends_with(&format!(".identity/{}", binary.identity_sha256))),
                "binary-analysis tool version must bind the exact producer identity"
            );
        }
        ensure!(
            self.allow_upload,
            "Assemblyline requires explicit allow_upload=true"
        );
        ensure!(
            self.endpoint.host_str().is_some()
                && self.endpoint.path() == "/"
                && self.endpoint.query().is_none()
                && self.endpoint.fragment().is_none()
                && self.endpoint.username().is_empty()
                && self.endpoint.password().is_none()
                && (self.endpoint.scheme() == "https"
                    || (self.allow_insecure_http && self.endpoint.scheme() == "http")),
            "Assemblyline endpoint must be a credential-free HTTPS origin (HTTP requires explicit opt-in)"
        );
        ensure!(
            environment_name(&self.user_env)
                && environment_name(&self.api_key_env)
                && self.user_env != self.api_key_env,
            "invalid Assemblyline credential environment names"
        );
        ensure!(
            text(&self.classification, 256)
                && text(&self.profile_revision, 256)
                && text(&self.server_version, 128)
                && self.server_version.starts_with("4.")
                && self
                    .submission_profile
                    .as_deref()
                    .is_none_or(|v| text(v, 128)),
            "invalid Assemblyline profile or classification"
        );
        ensure!(
            (1..=30).contains(&self.retention_days),
            "Assemblyline retention must be 1..=30 days"
        );
        ensure!(
            (1..=60).contains(&self.request_timeout_seconds)
                && (1..=86400).contains(&self.analysis_timeout_seconds)
                && (1..=300).contains(&self.poll_interval_seconds)
                && (1..=10).contains(&self.max_poll_failures),
            "invalid Assemblyline scheduling limits"
        );
        ensure!(
            self.service_spec
                .keys()
                .all(|s| self.policy.required_services.contains_key(s))
                && serde_json::to_vec(&self.service_spec)?.len() <= 16 * 1024,
            "Assemblyline service specifications must be bounded and explicitly selected"
        );
        if let Some(ca) = &self.ca_certificate {
            crate::oci::validate_subject(&ca.sha256)?;
            ensure!(
                !ca.path.is_empty(),
                "Assemblyline CA certificate path required"
            );
        }
        Ok(())
    }
    pub fn fingerprint(&self) -> String {
        sha256(&serde_json::to_vec(self).expect("serializable Assemblyline config"))
    }
}

struct Instance {
    client: Client,
    endpoint: Url,
    headers: HeaderMap,
    server_version: String,
}
impl Instance {
    async fn new(config: &AssemblylineConfig) -> Result<Self> {
        config.validate()?;
        let host = config
            .endpoint
            .host_str()
            .expect("validated host")
            .trim_matches(['[', ']']);
        let addresses: Vec<SocketAddr> = tokio::time::timeout(
            Duration::from_secs(10),
            tokio::net::lookup_host((
                host,
                config.endpoint.port_or_known_default().expect("HTTP port"),
            )),
        )
        .await??
        .collect();
        ensure!(
            !addresses.is_empty()
                && (config.allow_private_network
                    || addresses.iter().all(|a| crate::bounds::public_ip(a.ip()))),
            "Assemblyline instance resolved to a forbidden address"
        );
        let mut builder = Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(config.request_timeout_seconds))
            .resolve_to_addrs(host, &addresses);
        if let Some(ca) = &config.ca_certificate {
            let bytes =
                crate::scanner::read_bounded(tokio::fs::File::open(&ca.path).await?, 1024 * 1024)
                    .await?;
            ensure!(
                sha256(&bytes) == ca.sha256,
                "Assemblyline CA certificate digest mismatch"
            );
            builder = builder.add_root_certificate(reqwest::Certificate::from_pem(&bytes)?);
        }
        let mut headers = HeaderMap::new();
        for (header, variable) in [
            ("x-user", &config.user_env),
            ("x-apikey", &config.api_key_env),
        ] {
            let secret = std::env::var(variable)
                .map_err(|_| anyhow::anyhow!("Assemblyline credential unavailable"))?;
            ensure!(
                !secret.is_empty() && secret.len() <= 8192,
                "Assemblyline credential invalid"
            );
            let mut value = HeaderValue::from_str(&secret)
                .map_err(|_| anyhow::anyhow!("Assemblyline credential invalid"))?;
            value.set_sensitive(true);
            headers.insert(header, value);
        }
        Ok(Self {
            client: builder.build()?,
            endpoint: config.endpoint.clone(),
            headers,
            server_version: config.server_version.clone(),
        })
    }
    async fn response(&self, request: reqwest::RequestBuilder) -> Result<Value> {
        let mut response = request
            .headers(self.headers.clone())
            .send()
            .await
            .map_err(|_| anyhow::anyhow!("Assemblyline request unavailable"))?;
        ensure!(
            response.status().is_success(),
            "Assemblyline request rejected (HTTP {})",
            response.status().as_u16()
        );
        ensure!(
            response.content_length().is_none_or(|n| n <= 1024 * 1024),
            "Assemblyline response exceeds limit"
        );
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            ensure!(
                chunk.len() <= (1024usize * 1024).saturating_sub(bytes.len()),
                "Assemblyline response exceeds limit"
            );
            bytes.extend_from_slice(&chunk);
        }
        let envelope = crate::oci::strict_json(&bytes)?;
        ensure!(
            envelope["api_error_message"].as_str() == Some("")
                && envelope["api_status_code"]
                    .as_u64()
                    .is_some_and(|code| (200..300).contains(&code))
                && envelope["api_server_version"].as_str() == Some(&self.server_version),
            "Assemblyline API returned an error or a different server version"
        );
        envelope
            .get("api_response")
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("Assemblyline response missing"))
    }
    async fn get(&self, path: &str) -> Result<Value> {
        self.response(self.client.request(Method::GET, self.endpoint.join(path)?))
            .await
    }
    async fn submit(
        &self,
        config: &AssemblylineConfig,
        job: &Job,
        record: &remote_analysis::Record,
        bytes: &[u8],
    ) -> Result<(String, Value)> {
        let metadata = json!({"packweir_run_id":record.id,"packweir_request_digest":record.binding.request_digest});
        let mut body = json!({"name":format!("packweir-{}.bin",&job.subject[..12]),"metadata":metadata,
            "params":submission_params(config)});
        if let Some(profile) = &config.submission_profile {
            body["submission_profile"] = json!(profile);
        }
        let form = multipart::Form::new()
            .text("json", serde_json::to_string(&body)?)
            .part(
                "bin",
                multipart::Part::bytes(bytes.to_vec())
                    .file_name("artifact.bin")
                    .mime_str("application/octet-stream")?,
            );
        let value = self
            .response(
                self.client
                    .post(self.endpoint.join("api/v4/submit/")?)
                    .multipart(form),
            )
            .await?;
        let sid = value["sid"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("Assemblyline submission identifier missing"))?;
        validate_sid(sid)?;
        Ok((sid.into(), value))
    }
    async fn services(&self, config: &AssemblylineConfig) -> Result<()> {
        let response = self.get("api/v4/service/all/").await?;
        let services = response
            .as_array()
            .ok_or_else(|| anyhow::anyhow!("Assemblyline service inventory missing"))?;
        ensure!(
            services.len() <= 1024,
            "Assemblyline service inventory exceeds limit"
        );
        for (name, pin) in &config.policy.required_services {
            let matching: Vec<_> = services
                .iter()
                .filter(|s| s["name"].as_str() == Some(name))
                .collect();
            ensure!(
                matching.len() == 1,
                "Assemblyline selected service unavailable or ambiguous"
            );
            let service = matching[0];
            ensure!(
                service["enabled"] == true && service["version"].as_str() == Some(&pin.version),
                "Assemblyline selected service disabled or version differs"
            );
            ensure!(
                service["is_external"]
                    .as_bool()
                    .is_some_and(|external| !external || config.allow_external_services)
                    && service["privileged"]
                        .as_bool()
                        .is_some_and(|privileged| !privileged || config.allow_privileged_services),
                "Assemblyline service disclosure or privilege policy denied"
            );
        }
        Ok(())
    }
}

pub fn validate_sid(sid: &str) -> Result<()> {
    ensure!(
        !sid.is_empty()
            && sid.len() <= 128
            && sid
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b)),
        "invalid Assemblyline submission identifier"
    );
    Ok(())
}
fn submission_params(config: &AssemblylineConfig) -> Value {
    json!({"classification":config.classification,"ttl":config.retention_days,"description":"Packweir artifact analysis",
        "services":{"selected":config.policy.required_services.keys().collect::<Vec<_>>(),"excluded":[],"rescan":[],"resubmit":[]},
        "service_spec":config.service_spec,"ignore_cache":false,"deep_scan":false,"ignore_recursion_prevention":false,
        "ignore_filtering":false,"ignore_size":false,"max_extracted":255,"max_supplementary":64,
        "generate_alert":false,"auto_archive":false,"delete_after_archive":false,"use_archive_alternate_dtl":false,
        "default_external_sources":[]})
}

pub enum Step {
    Pending(DateTime<Utc>),
    Finished(ScannerOutput),
}

fn unresolved(record: &remote_analysis::Record, reason: &str) -> ScannerOutput {
    ScannerOutput {
        outcome: crate::model::Outcome::Inconclusive,
        details: json!({"reason":reason,"remote_analysis_id":record.id,"submission_id":record.remote_id,
            "state":record.state,"original_subject":record.subject,"approval_scope":"Assemblyline service observations"}),
        references: vec![],
        valid_until: Some(record.deadline_at),
    }
}

/// Perform at most one submission or one bounded status/full/tree polling cycle.
pub async fn advance(
    store: &Store,
    job: &Job,
    name: &str,
    config: &AssemblylineConfig,
    bytes: &Arc<[u8]>,
    bundle: &Value,
    evidence_digest: &str,
) -> Result<Step> {
    config.validate()?;
    ensure!(
        sha256(bytes) == job.subject,
        "Assemblyline artifact digest mismatch"
    );
    ensure!(
        sha256(&serde_json::to_vec(bundle)?) == evidence_digest,
        "Assemblyline evidence bundle digest differs"
    );
    let local_inventory =
        crate::analysis_coverage::LocalInventory::from_bundle(&job.subject, bytes.len(), bundle)?;
    let profile = config.fingerprint();
    let binding = Binding {
        check_name: name.into(),
        service_fingerprint: profile.clone(),
        evidence_digest: evidence_digest.into(),
        request_digest: sha256(&serde_json::to_vec(
            &json!({"subject":job.subject,"configuration":job.configuration,
            "context_revision":job.context_revision,"profile":profile,"evidence_digest":evidence_digest}),
        )?),
    };
    let mut record =
        remote_analysis::prepare(store, job, &binding, config.analysis_timeout_seconds as i64)
            .await?;
    match record.state {
        State::Complete => {
            let mut output = record.output.take().expect("complete record output");
            if let Some(binary) = &config.binary_analysis {
                crate::binary_remote::reconcile_with_empty_policy(
                    binary,
                    &job.filename,
                    Arc::clone(bytes),
                    &mut output,
                    config.policy.max_result_age_seconds,
                    config.policy.allow_empty_files,
                )
                .await?;
            }
            return Ok(Step::Finished(output));
        }
        State::Failed | State::Ambiguous => {
            return Ok(Step::Finished(unresolved(
                &record,
                record
                    .error
                    .as_deref()
                    .unwrap_or("remote analysis unresolved"),
            )));
        }
        State::Submitting => {
            record = remote_analysis::ambiguous(
                store,
                job,
                &record,
                "submission outcome unknown; reconcile the recorded correlation before retrying",
            )
            .await?;
            return Ok(Step::Finished(unresolved(
                &record,
                "submission outcome unknown; administrative reconciliation required",
            )));
        }
        _ => {}
    }
    if Utc::now() >= record.deadline_at {
        record =
            remote_analysis::fail(store, job, &record, "remote analysis deadline expired").await?;
        return Ok(Step::Finished(unresolved(
            &record,
            "remote analysis deadline expired",
        )));
    }
    if record.next_poll_at > Utc::now() {
        return Ok(Step::Pending(record.next_poll_at));
    }
    let instance = match Instance::new(config).await {
        Ok(instance) => instance,
        Err(_) if record.state == State::Submitted => {
            if record.poll_failures >= config.max_poll_failures.saturating_sub(1) as i32 {
                record = remote_analysis::fail(
                    store,
                    job,
                    &record,
                    "remote instance unavailable during polling",
                )
                .await?;
                return Ok(Step::Finished(unresolved(
                    &record,
                    "remote instance unavailable during polling",
                )));
            }
            record = remote_analysis::pending(
                store,
                job,
                &record,
                config.poll_interval_seconds,
                Some("remote instance unavailable during polling"),
            )
            .await?;
            return Ok(Step::Pending(record.next_poll_at));
        }
        Err(error) => return Err(error),
    };
    if record.state == State::Prepared {
        instance.services(config).await?;
        let permit = remote_analysis::begin_submit(store, job, &record).await?;
        match instance.submit(config, job, &record, bytes).await {
            Ok((sid, accepted)) => {
                record = remote_analysis::submitted(store, job, &record, &permit, &sid).await?;
                if verify_submission(config, job, &record, &accepted).is_err() {
                    record = remote_analysis::fail(
                        store,
                        job,
                        &record,
                        "accepted submission parameters or subject differ",
                    )
                    .await?;
                    return Ok(Step::Finished(unresolved(
                        &record,
                        "accepted submission parameters or subject differ",
                    )));
                }
            }
            Err(_) => {
                record = remote_analysis::ambiguous(
                    store,
                    job,
                    &record,
                    "submission outcome unknown; administrative reconciliation required",
                )
                .await?;
                return Ok(Step::Finished(unresolved(
                    &record,
                    "submission outcome unknown; administrative reconciliation required",
                )));
            }
        }
    } else {
        let sid = record
            .remote_id
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("remote submission binding missing"))?;
        validate_sid(sid)?;
        let poll: Result<Option<ScannerOutput>> = async {
            let status = instance.get(&format!("api/v4/submission/{sid}/")).await?;
            verify_submission(config, job, &record, &status)?;
            match status["state"].as_str() {
                Some("completed") => {
                    let report = instance
                        .get(&format!("api/v4/submission/full/{sid}/?get_full_tree=true"))
                        .await?;
                    verify_submission(config, job, &record, &report)?;
                    let tree = instance
                        .get(&format!("api/v4/submission/tree/{sid}/?get_full_tree=true"))
                        .await?;
                    let mut output = crate::assemblyline::normalize_at(
                        &job.subject,
                        sid,
                        &report,
                        &tree,
                        &config.policy,
                        Utc::now(),
                    )?;
                    local_inventory.reconcile(&mut output, config.policy.allow_empty_files)?;
                    if let Some(binary) = &config.binary_analysis {
                        crate::binary_remote::reconcile_with_empty_policy(
                            binary,
                            &job.filename,
                            Arc::clone(bytes),
                            &mut output,
                            config.policy.max_result_age_seconds,
                            config.policy.allow_empty_files,
                        )
                        .await?;
                    }
                    output.valid_until = Some(
                        output
                            .valid_until
                            .unwrap_or(record.deadline_at)
                            .min(record.deadline_at),
                    );
                    output.details["remote_analysis_id"] = json!(record.id);
                    output.details["request_digest"] = json!(record.binding.request_digest);
                    output.details["profile_fingerprint"] =
                        json!(record.binding.service_fingerprint);
                    output.details["evidence_digest"] = json!(record.binding.evidence_digest);
                    output.details["server_version"] = json!(config.server_version);
                    output.details["instance"] = json!(config.endpoint);
                    output.references = vec![
                        config
                            .endpoint
                            .join(&format!("api/v4/submission/full/{sid}/?get_full_tree=true"))?
                            .to_string(),
                        config
                            .endpoint
                            .join(&format!("api/v4/submission/tree/{sid}/?get_full_tree=true"))?
                            .to_string(),
                    ];
                    Ok(Some(output))
                }
                Some("submitted") => Ok(None),
                _ => anyhow::bail!("Assemblyline submission failed or has an unknown state"),
            }
        }
        .await;
        match poll {
            Ok(Some(output)) => {
                record = remote_analysis::complete(store, job, &record, &output).await?;
                return Ok(Step::Finished(
                    record.output.take().expect("complete output"),
                ));
            }
            Ok(None) => {
                record = remote_analysis::pending(
                    store,
                    job,
                    &record,
                    config.poll_interval_seconds,
                    None,
                )
                .await?;
            }
            Err(_) if record.poll_failures >= config.max_poll_failures.saturating_sub(1) as i32 => {
                record = remote_analysis::fail(
                    store,
                    job,
                    &record,
                    "remote analysis polling failed or result binding invalid",
                )
                .await?;
                return Ok(Step::Finished(unresolved(
                    &record,
                    "remote analysis polling failed or result binding invalid",
                )));
            }
            Err(_) => {
                record = remote_analysis::pending(
                    store,
                    job,
                    &record,
                    config.poll_interval_seconds,
                    Some("remote analysis poll unavailable or invalid"),
                )
                .await?;
            }
        }
        return Ok(Step::Pending(record.next_poll_at));
    }
    record =
        remote_analysis::pending(store, job, &record, config.poll_interval_seconds, None).await?;
    Ok(Step::Pending(record.next_poll_at))
}

fn verify_submission(
    config: &AssemblylineConfig,
    job: &Job,
    record: &remote_analysis::Record,
    report: &Value,
) -> Result<()> {
    ensure!(
        report["sid"].as_str() == record.remote_id.as_deref(),
        "remote submission mismatch"
    );
    ensure!(
        report["metadata"]["packweir_run_id"].as_str() == Some(record.id.to_string().as_str())
            && report["metadata"]["packweir_request_digest"].as_str()
                == Some(record.binding.request_digest.as_str()),
        "remote correlation mismatch"
    );
    let files = report["files"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("remote original file missing"))?;
    ensure!(
        files.len() == 1 && files[0]["sha256"].as_str() == Some(&job.subject),
        "remote original subject mismatch"
    );
    let params = &report["params"];
    let selected = params["services"]["selected"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("remote service selection missing"))?;
    let actual: std::collections::BTreeSet<_> = selected
        .iter()
        .map(|v| {
            v.as_str()
                .ok_or_else(|| anyhow::anyhow!("invalid remote service name"))
        })
        .collect::<Result<_>>()?;
    let expected: std::collections::BTreeSet<_> = config
        .policy
        .required_services
        .keys()
        .map(String::as_str)
        .collect();
    ensure!(
        actual == expected && actual.len() == selected.len(),
        "remote service selection differs"
    );
    for list in ["excluded", "rescan", "resubmit"] {
        ensure!(
            params["services"]
                .get(list)
                .is_none_or(|value| value.as_array().is_some_and(Vec::is_empty)),
            "remote service exclusions or resubmissions differ"
        );
    }
    ensure!(
        params["classification"].as_str() == Some(&config.classification)
            && params["ttl"]
                .as_u64()
                .is_some_and(|ttl| ttl > 0 && ttl <= config.retention_days as u64)
            && params["service_spec"] == json!(config.service_spec),
        "remote disclosure or service specification differs"
    );
    for flag in [
        "ignore_cache",
        "deep_scan",
        "ignore_recursion_prevention",
        "ignore_filtering",
        "ignore_size",
        "generate_alert",
        "auto_archive",
        "delete_after_archive",
        "use_archive_alternate_dtl",
    ] {
        ensure!(params[flag] == false, "remote submission flags differ");
    }
    for (field, max) in [("max_extracted", 255), ("max_supplementary", 64)] {
        ensure!(
            params[field].as_u64().is_some_and(|n| n > 0 && n <= max),
            "remote extraction limits differ"
        );
    }
    Ok(())
}
