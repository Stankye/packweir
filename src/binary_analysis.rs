//! Provider-neutral, bounded binary-analysis observations and derived bytes.
//! Completion records requested analysis coverage; it never asserts malware safety.
use crate::model::sha256;
use anyhow::{Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use chrono::{DateTime, Utc};
use serde::{
    Deserialize, Serialize,
    de::{self, MapAccess, SeqAccess, Visitor},
};
use serde_json::{Map, Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

pub const SCHEMA_VERSION: &str = "packweir.binary-analysis.v1";
pub const MAX_MANIFEST_BYTES: usize = 512 * 1024;
pub const MAX_OUTPUT_BYTES: usize = 256 * 1024;
pub const MAX_OUTPUTS: usize = 256;
const CAPABILITIES: [&str; 3] = ["decompile", "pcode", "decode_xor"];
const INPUT_KINDS: [&str; 5] = ["elf", "pe", "wasm", "mach_o_or_java", "binary"];

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BinaryAnalysisPolicy {
    /// The caller must bind this selector to the actual originating service.
    pub service: String,
    pub identity_sha256: String,
    pub required_capabilities: Vec<String>,
    /// Exact reviewed diagnostics; the producer pin and full configuration bind this policy.
    #[serde(default)]
    pub informational_warnings: Vec<String>,
    #[serde(default = "default_candidate_kinds")]
    pub candidate_kinds: Vec<String>,
}

pub fn default_candidate_kinds() -> Vec<String> {
    INPUT_KINDS[..4].iter().map(|kind| (*kind).into()).collect()
}

impl BinaryAnalysisPolicy {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            plain(&self.service, 128) && !self.service.contains(['/', '\\']),
            "invalid binary-analysis service selector"
        );
        ensure!(
            digest(&self.identity_sha256),
            "binary-analysis identity must be a full lowercase SHA256"
        );
        unique_members(
            &self.required_capabilities,
            &CAPABILITIES,
            "required capabilities",
        )?;
        unique_members(&self.candidate_kinds, &INPUT_KINDS, "candidate kinds")?;
        ensure!(
            self.informational_warnings.len() <= 32
                && self
                    .informational_warnings
                    .iter()
                    .all(|warning| message(warning, 4096))
                && self
                    .informational_warnings
                    .iter()
                    .collect::<BTreeSet<_>>()
                    .len()
                    == self.informational_warnings.len(),
            "invalid or duplicate informational warnings"
        );
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct ValidatedOutput {
    pub kind: String,
    pub media_type: String,
    pub sha256: String,
    pub size: u64,
    pub bytes: Vec<u8>,
    pub derivation: Value,
    pub metadata: Value,
}

#[derive(Debug, Clone)]
pub struct ValidatedManifest {
    pub complete: bool,
    pub manifest_sha256: String,
    pub producer_identity_sha256: String,
    pub input_bytes_verified: bool,
    pub details: Value,
    pub outputs: Vec<ValidatedOutput>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema_version: String,
    input: Input,
    producer: Producer,
    analysis: Analysis,
    observations: Vec<Observation>,
    outputs: Vec<Output>,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    sha256: String,
    size: u64,
    kind: String,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Producer {
    engine: String,
    engine_version: String,
    engine_archive_sha256: String,
    jdk_version: String,
    jdk_archive_sha256: String,
    decompiler_sha256: String,
    scripts_sha256: String,
    profile_sha256: String,
    driver_sha256: String,
    identity_sha256: String,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Analysis {
    started_at: String,
    completed_at: String,
    status: String,
    timed_out: bool,
    errors: Vec<String>,
    warnings: Vec<String>,
    language_id: Option<String>,
    compiler_spec_id: Option<String>,
    requested_capabilities: Vec<String>,
    capabilities: Capabilities,
    functions_total: u64,
    functions_decompiled: u64,
    functions_failed: u64,
    export_truncated: bool,
    log_sha256: String,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Capabilities {
    decompile: String,
    pcode: String,
    decode_xor: String,
}
impl Capabilities {
    fn get(&self, name: &str) -> &str {
        match name {
            "decompile" => &self.decompile,
            "pcode" => &self.pcode,
            "decode_xor" => &self.decode_xor,
            _ => unreachable!(),
        }
    }
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Observation {
    kind: String,
    name: String,
    value: String,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Output {
    kind: String,
    media_type: String,
    sha256: String,
    size: u64,
    data_base64: String,
    derivation: Derivation,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Derivation {
    operation: String,
    version: String,
    input_sha256: String,
    parameters: BTreeMap<String, Value>,
    source_spans: Vec<SourceSpan>,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceSpan {
    offset: u64,
    length: u64,
    sha256: String,
}

fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn plain(value: &str, max: usize) -> bool {
    !value.trim().is_empty() && value.len() <= max && !value.chars().any(char::is_control)
}
fn message(value: &str, max: usize) -> bool {
    !value.trim().is_empty()
        && value.len() <= max
        && value
            .chars()
            .all(|c| !c.is_control() || matches!(c, '\n' | '\r' | '\t'))
}
fn unique_members(values: &[String], allowed: &[&str], label: &str) -> Result<()> {
    let distinct: BTreeSet<_> = values.iter().map(String::as_str).collect();
    ensure!(
        !values.is_empty()
            && values.len() <= allowed.len()
            && distinct.len() == values.len()
            && values.iter().all(|value| allowed.contains(&value.as_str())),
        "invalid or duplicate binary-analysis {label}"
    );
    Ok(())
}

// A Value parsed first by serde_json would silently collapse duplicate keys.
// This visitor rejects them at every object level before typed validation.
struct UniqueValue(Value);
impl<'de> Deserialize<'de> for UniqueValue {
    fn deserialize<D: de::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        struct UniqueVisitor;
        impl<'de> Visitor<'de> for UniqueVisitor {
            type Value = UniqueValue;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("JSON without duplicate object keys")
            }
            fn visit_bool<E: de::Error>(self, v: bool) -> std::result::Result<Self::Value, E> {
                Ok(UniqueValue(v.into()))
            }
            fn visit_i64<E: de::Error>(self, v: i64) -> std::result::Result<Self::Value, E> {
                Ok(UniqueValue(v.into()))
            }
            fn visit_u64<E: de::Error>(self, v: u64) -> std::result::Result<Self::Value, E> {
                Ok(UniqueValue(v.into()))
            }
            fn visit_f64<E: de::Error>(self, v: f64) -> std::result::Result<Self::Value, E> {
                serde_json::Number::from_f64(v)
                    .map(|n| UniqueValue(Value::Number(n)))
                    .ok_or_else(|| E::custom("non-finite JSON number"))
            }
            fn visit_str<E: de::Error>(self, v: &str) -> std::result::Result<Self::Value, E> {
                Ok(UniqueValue(v.into()))
            }
            fn visit_string<E: de::Error>(self, v: String) -> std::result::Result<Self::Value, E> {
                Ok(UniqueValue(v.into()))
            }
            fn visit_unit<E: de::Error>(self) -> std::result::Result<Self::Value, E> {
                Ok(UniqueValue(Value::Null))
            }
            fn visit_none<E: de::Error>(self) -> std::result::Result<Self::Value, E> {
                Ok(UniqueValue(Value::Null))
            }
            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> std::result::Result<Self::Value, A::Error> {
                let mut values = Vec::new();
                while let Some(UniqueValue(value)) = seq.next_element()? {
                    values.push(value);
                }
                Ok(UniqueValue(Value::Array(values)))
            }
            fn visit_map<A: MapAccess<'de>>(
                self,
                mut map: A,
            ) -> std::result::Result<Self::Value, A::Error> {
                let mut values = Map::new();
                while let Some((key, UniqueValue(value))) =
                    map.next_entry::<String, UniqueValue>()?
                {
                    if values.insert(key, value).is_some() {
                        return Err(de::Error::custom("duplicate JSON object key"));
                    }
                }
                Ok(UniqueValue(Value::Object(values)))
            }
        }
        deserializer.deserialize_any(UniqueVisitor)
    }
}

fn typed(value: &Value) -> Result<Manifest> {
    let mut pending = vec![(value, 0usize)];
    let mut nodes = 0usize;
    while let Some((value, depth)) = pending.pop() {
        nodes += 1;
        ensure!(
            depth <= 16 && nodes <= 16_384,
            "binary-analysis JSON structure exceeds limit"
        );
        match value {
            Value::Array(values) => pending.extend(values.iter().map(|value| (value, depth + 1))),
            Value::Object(values) => {
                pending.extend(values.values().map(|value| (value, depth + 1)))
            }
            _ => {}
        }
    }
    ensure!(
        serde_json::to_vec(value)?.len() <= MAX_MANIFEST_BYTES,
        "binary-analysis manifest exceeds limit"
    );
    let analysis = value
        .get("analysis")
        .and_then(Value::as_object)
        .ok_or_else(|| anyhow::anyhow!("binary-analysis analysis object missing"))?;
    ensure!(
        analysis.contains_key("language_id") && analysis.contains_key("compiler_spec_id"),
        "binary-analysis nullable identity fields must be present"
    );
    let manifest: Manifest = serde_json::from_value(value.clone())?;
    ensure!(
        manifest.schema_version == SCHEMA_VERSION,
        "unknown binary-analysis schema version"
    );
    Ok(manifest)
}

pub fn parse_manifest(raw: &str) -> Result<Value> {
    ensure!(
        raw.len() <= MAX_MANIFEST_BYTES,
        "binary-analysis manifest exceeds limit"
    );
    let UniqueValue(value) = serde_json::from_str(raw)?;
    typed(&value)?;
    Ok(value)
}

/// Compact UTF-8 JSON, sorted producer keys, excluding only identity_sha256.
/// This is a pinned identity observation, not cryptographic tool attestation.
pub fn producer_identity_sha256(producer: &Value) -> Result<String> {
    let mut fields = producer
        .as_object()
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("binary-analysis producer object missing"))?;
    fields.remove("identity_sha256");
    let expected = [
        "engine",
        "engine_version",
        "engine_archive_sha256",
        "jdk_version",
        "jdk_archive_sha256",
        "decompiler_sha256",
        "scripts_sha256",
        "profile_sha256",
        "driver_sha256",
    ];
    ensure!(
        fields.len() == expected.len() && expected.iter().all(|name| fields.contains_key(*name)),
        "binary-analysis producer fields differ"
    );
    for (name, value) in &fields {
        let value = value
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("binary-analysis producer values must be strings"))?;
        ensure!(
            if name.ends_with("_sha256") {
                digest(value)
            } else {
                plain(value, 128)
            },
            "invalid binary-analysis producer identity field"
        );
    }
    Ok(sha256(&serde_json::to_vec(&fields)?))
}

/// Validate source identity and inline bytes; incomplete observations remain visible.
/// The caller independently binds policy.service and report/result freshness.
pub fn validate_manifest(
    policy: &BinaryAnalysisPolicy,
    input_sha256: &str,
    input_size: u64,
    input_kind: &str,
    input_bytes: Option<&[u8]>,
    manifest: &Value,
    now: DateTime<Utc>,
) -> Result<ValidatedManifest> {
    policy.validate()?;
    ensure!(
        digest(input_sha256) && INPUT_KINDS.contains(&input_kind),
        "invalid binary-analysis expected input"
    );
    if let Some(bytes) = input_bytes {
        ensure!(
            bytes.len() as u64 == input_size && sha256(bytes) == input_sha256,
            "binary-analysis supplied input bytes differ"
        );
    }
    let value = typed(manifest)?;
    ensure!(
        value.input.sha256 == input_sha256
            && value.input.size == input_size
            && value.input.kind == input_kind,
        "binary-analysis input binding differs"
    );
    let producer_id = producer_identity_sha256(&serde_json::to_value(&value.producer)?)?;
    ensure!(
        value.producer.identity_sha256 == producer_id && producer_id == policy.identity_sha256,
        "binary-analysis producer identity differs from pin"
    );
    let analysis = &value.analysis;
    ensure!(
        ["complete", "unsupported", "incomplete", "error"].contains(&analysis.status.as_str()),
        "invalid binary-analysis status"
    );
    unique_members(
        &analysis.requested_capabilities,
        &CAPABILITIES,
        "requested capabilities",
    )?;
    for name in CAPABILITIES {
        let status = analysis.capabilities.get(name);
        ensure!(
            [
                "complete",
                "unsupported",
                "incomplete",
                "error",
                "not_requested"
            ]
            .contains(&status),
            "invalid binary-analysis capability status"
        );
        let requested = analysis
            .requested_capabilities
            .iter()
            .any(|value| value == name);
        ensure!(
            requested != (status == "not_requested"),
            "binary-analysis capability request/status differs"
        );
    }
    for messages in [&analysis.errors, &analysis.warnings] {
        ensure!(
            messages.len() <= 64 && messages.iter().all(|text| message(text, 4096)),
            "binary-analysis diagnostic limit exceeded"
        );
    }
    ensure!(
        analysis
            .language_id
            .as_deref()
            .is_none_or(|v| plain(v, 256))
            && analysis
                .compiler_spec_id
                .as_deref()
                .is_none_or(|v| plain(v, 256)),
        "invalid binary-analysis language or compiler identity"
    );
    ensure!(
        analysis.started_at.len() <= 64 && analysis.completed_at.len() <= 64,
        "invalid binary-analysis timestamp length"
    );
    let started = DateTime::parse_from_rfc3339(&analysis.started_at)?.with_timezone(&Utc);
    let completed = DateTime::parse_from_rfc3339(&analysis.completed_at)?.with_timezone(&Utc);
    ensure!(
        started <= completed && completed <= now,
        "binary-analysis timestamps are unordered or future-dated"
    );
    ensure!(
        digest(&analysis.log_sha256),
        "invalid binary-analysis log SHA256"
    );
    ensure!(
        analysis.functions_total <= 1_000_000
            && analysis.functions_decompiled <= analysis.functions_total
            && analysis.functions_failed <= analysis.functions_total
            && analysis
                .functions_decompiled
                .checked_add(analysis.functions_failed)
                .is_some_and(|v| v <= analysis.functions_total),
        "inconsistent binary-analysis function counts"
    );
    ensure!(
        value.observations.len() <= 2048,
        "binary-analysis observation limit exceeded"
    );
    for observation in &value.observations {
        ensure!(
            [
                "header",
                "section",
                "symbol",
                "string",
                "function",
                "language",
                "compiler",
                "xor_candidate",
                "note"
            ]
            .contains(&observation.kind.as_str())
                && plain(&observation.name, 128)
                && message(&observation.value, 8192),
            "invalid binary-analysis observation"
        );
    }
    let mut reasons = BTreeSet::new();
    if !policy.candidate_kinds.iter().any(|kind| kind == input_kind) {
        reasons.insert("input kind is outside the configured candidate policy".to_owned());
    }
    if analysis.status != "complete" {
        reasons.insert(format!("analysis status is {}", analysis.status));
    }
    if analysis.timed_out {
        reasons.insert("analysis timed out".into());
    }
    let acknowledged_warnings: Vec<_> = analysis
        .warnings
        .iter()
        .filter(|warning| policy.informational_warnings.contains(warning))
        .collect();
    let unacknowledged_warnings: Vec<_> = analysis
        .warnings
        .iter()
        .filter(|warning| !policy.informational_warnings.contains(warning))
        .collect();
    if !analysis.errors.is_empty() {
        reasons.insert("analysis contains errors".into());
    }
    if !unacknowledged_warnings.is_empty() {
        reasons.insert("analysis contains unacknowledged warnings".into());
    }
    if analysis.export_truncated {
        reasons.insert("analysis exports were truncated".into());
    }
    for name in &policy.required_capabilities {
        if !analysis.requested_capabilities.contains(name)
            || analysis.capabilities.get(name) != "complete"
        {
            reasons.insert(format!(
                "required capability {name} is missing or incomplete"
            ));
        }
    }
    for name in &analysis.requested_capabilities {
        if analysis.capabilities.get(name) != "complete" {
            reasons.insert(format!("requested capability {name} is incomplete"));
        }
    }
    if analysis.functions_failed != 0 {
        reasons.insert("function analysis failed".into());
    }
    if analysis
        .requested_capabilities
        .iter()
        .any(|name| name == "decompile" || name == "pcode")
        && (analysis.language_id.is_none() || analysis.compiler_spec_id.is_none())
    {
        reasons.insert("decompiler language or compiler identity is missing".into());
    }
    if analysis
        .requested_capabilities
        .iter()
        .any(|name| name == "decompile")
        && (analysis.functions_total == 0
            || analysis.functions_decompiled != analysis.functions_total)
    {
        reasons.insert("decompilation does not cover every discovered internal function".into());
    }
    ensure!(
        value.outputs.len() <= MAX_OUTPUTS,
        "binary-analysis output count exceeded"
    );
    let mut total_bytes = 0usize;
    let mut outputs = Vec::new();
    let mut output_kinds = BTreeSet::new();
    let mut function_entries: BTreeMap<&str, BTreeSet<String>> = BTreeMap::new();
    for output in &value.outputs {
        let capability = match (
            output.kind.as_str(),
            output.media_type.as_str(),
            output.derivation.operation.as_str(),
        ) {
            ("decompiled_c", "text/x-c", "ghidra.decompile") => "decompile",
            ("pcode", "text/plain", "ghidra.pcode") => "pcode",
            ("decoded_bytes", "application/octet-stream", "xor.decode") => "decode_xor",
            _ => anyhow::bail!("binary-analysis output kind, media type or operation differs"),
        };
        ensure!(
            analysis
                .requested_capabilities
                .iter()
                .any(|name| name == capability),
            "binary-analysis output was not requested"
        );
        ensure!(
            output.size > 0
                && output.size <= MAX_OUTPUT_BYTES as u64
                && output.data_base64.len() <= MAX_OUTPUT_BYTES.div_ceil(3) * 4,
            "binary-analysis inline output exceeds limit"
        );
        let bytes = STANDARD.decode(&output.data_base64)?;
        ensure!(
            STANDARD.encode(&bytes) == output.data_base64
                && bytes.len() as u64 == output.size
                && digest(&output.sha256)
                && sha256(&bytes) == output.sha256,
            "binary-analysis output byte binding differs"
        );
        total_bytes = total_bytes
            .checked_add(bytes.len())
            .ok_or_else(|| anyhow::anyhow!("binary-analysis output size overflow"))?;
        ensure!(
            total_bytes <= MAX_OUTPUT_BYTES,
            "binary-analysis combined output limit exceeded"
        );
        let derivation = &output.derivation;
        ensure!(
            derivation.input_sha256 == input_sha256 && plain(&derivation.version, 128),
            "binary-analysis derivation input or version differs"
        );
        ensure!(
            !derivation.source_spans.is_empty()
                && derivation.source_spans.len() <= 64
                && derivation.parameters.len() <= 64,
            "binary-analysis derivation bounds exceeded"
        );
        for (key, parameter) in &derivation.parameters {
            ensure!(
                plain(key, 64)
                    && key
                        .bytes()
                        .all(|c| c.is_ascii_alphanumeric() || b"_.-".contains(&c))
                    && match parameter {
                        Value::String(text) => message(text, 4096),
                        Value::Null | Value::Bool(_) | Value::Number(_) => true,
                        _ => false,
                    },
                "invalid binary-analysis derivation parameter"
            );
        }
        for span in &derivation.source_spans {
            let end = span
                .offset
                .checked_add(span.length)
                .ok_or_else(|| anyhow::anyhow!("binary-analysis source span overflow"))?;
            ensure!(
                span.length > 0 && end <= input_size && digest(&span.sha256),
                "binary-analysis source span is invalid"
            );
            if let Some(input) = input_bytes {
                let start = usize::try_from(span.offset)?;
                let end = usize::try_from(end)?;
                ensure!(
                    sha256(&input[start..end]) == span.sha256,
                    "binary-analysis source span SHA256 differs"
                );
            } else if span.offset == 0 && span.length == input_size {
                ensure!(
                    span.sha256 == input_sha256,
                    "binary-analysis complete source span SHA256 differs"
                );
            }
        }
        let source_spans_verified = input_bytes.is_some();
        let mut xor_recomputed = false;
        if capability == "decode_xor" {
            ensure!(
                derivation.version == "1"
                    && derivation.parameters.len() == 1
                    && derivation.source_spans.len() == 1,
                "invalid XOR derivation version or fields"
            );
            let key_hex = derivation
                .parameters
                .get("key_hex")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow::anyhow!("XOR derivation key missing"))?;
            ensure!(
                (2..=64).contains(&key_hex.len())
                    && key_hex.len() % 2 == 0
                    && key_hex
                        .bytes()
                        .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)),
                "invalid XOR derivation key"
            );
            let key = hex::decode(key_hex)?;
            let span = &derivation.source_spans[0];
            ensure!(
                span.length == output.size,
                "XOR output and source span lengths differ"
            );
            if let Some(input) = input_bytes {
                let offset = usize::try_from(span.offset)?;
                ensure!(
                    bytes.iter().enumerate().all(
                        |(index, byte)| *byte == input[offset + index] ^ key[index % key.len()]
                    ),
                    "XOR derived bytes do not match the source and key"
                );
                xor_recomputed = true;
            } else {
                reasons.insert("XOR derivation lacks independently supplied source bytes".into());
            }
        } else {
            ensure!(
                derivation.version == value.producer.engine_version,
                "decompiler operation version differs from producer"
            );
            let text = std::str::from_utf8(&bytes)?;
            ensure!(
                !text.contains('\0'),
                "binary-analysis text output contains NUL"
            );
            if text.chars().all(|c| c.is_whitespace() || c.is_control()) {
                reasons.insert(format!(
                    "{} output contains no meaningful text",
                    output.kind
                ));
            }
            if let Some(entry) = derivation.parameters.get("function_entry") {
                let entry = entry
                    .as_str()
                    .filter(|entry| plain(entry, 256))
                    .ok_or_else(|| anyhow::anyhow!("invalid decompiler function entry"))?;
                if !function_entries
                    .entry(capability)
                    .or_default()
                    .insert(entry.to_owned())
                {
                    reasons.insert(format!("{capability} repeats a function entry"));
                }
            } else {
                reasons.insert(format!("{capability} output has no function entry"));
            }
        }
        output_kinds.insert(output.kind.as_str());
        let metadata = json!({"kind":output.kind,"media_type":output.media_type,"sha256":output.sha256,"size":output.size,
            "derivation":derivation,"source_spans_verified":source_spans_verified,
            "xor_recomputed":xor_recomputed,"semantic_equivalence_verified":false});
        outputs.push(ValidatedOutput {
            kind: output.kind.clone(),
            media_type: output.media_type.clone(),
            sha256: output.sha256.clone(),
            size: output.size,
            bytes,
            derivation: serde_json::to_value(derivation)?,
            metadata,
        });
    }
    for (capability, kind) in [("decompile", "decompiled_c"), ("pcode", "pcode")] {
        if analysis
            .requested_capabilities
            .iter()
            .any(|name| name == capability)
            && analysis.capabilities.get(capability) == "complete"
            && !output_kinds.contains(kind)
        {
            reasons.insert(format!(
                "completed capability {capability} has no attributable output"
            ));
        }
        if analysis
            .requested_capabilities
            .iter()
            .any(|name| name == capability)
            && analysis.capabilities.get(capability) == "complete"
            && function_entries.get(capability).map_or(0, BTreeSet::len) as u64
                != analysis.functions_total
        {
            reasons.insert(format!(
                "{capability} exports do not cover every discovered internal function"
            ));
        }
    }
    if analysis
        .requested_capabilities
        .iter()
        .any(|name| name == "decompile")
        && analysis
            .requested_capabilities
            .iter()
            .any(|name| name == "pcode")
        && function_entries.get("decompile") != function_entries.get("pcode")
    {
        reasons.insert("decompile and pcode function entry sets differ".into());
    }
    let canonical = serde_json::to_value(&value)?;
    let manifest_sha256 = sha256(&serde_json::to_vec(&canonical)?);
    let complete = reasons.is_empty();
    let details = json!({"schema_version":SCHEMA_VERSION,"manifest_sha256":manifest_sha256,"manifest":canonical,
        "input_sha256":input_sha256,"producer_id":producer_id,"producer_identity_sha256":producer_id,
        "validation":{"complete":complete,"reasons":reasons,"input_bytes_verified":input_bytes.is_some(),
            "informational_warning_policy":policy.informational_warnings,
            "acknowledged_warnings":acknowledged_warnings,"unacknowledged_warnings":unacknowledged_warnings,
            "output_count":outputs.len(),"output_bytes":total_bytes,
            "outputs":outputs.iter().map(|output| &output.metadata).collect::<Vec<_>>()},
        "analysis_scope":"binary observations and bounded derivations; malware safety is not established"});
    Ok(ValidatedManifest {
        complete,
        manifest_sha256,
        producer_identity_sha256: producer_id,
        input_bytes_verified: input_bytes.is_some(),
        details,
        outputs,
    })
}
