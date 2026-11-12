//! A deliberately local OCI 1.1 evidence interchange format.
//!
//! A package's SHA-256 identifies its bytes, not an OCI manifest, so it is carried
//! in the evidence envelope rather than the OCI `subject` relationship. Neither
//! annotations nor exported source/snapshot claims confer local policy authority.

use anyhow::{Context, Result, bail, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{
    Deserialize, Deserializer, Serialize,
    de::{self, MapAccess, SeqAccess, Visitor},
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    fs::{self, OpenOptions},
    io::{Read, Write},
    path::{Component, Path, PathBuf},
};

pub const ARTIFACT_TYPE: &str = "application/vnd.packweir.evidence.v1";
pub const ENVELOPE_MEDIA_TYPE: &str = "application/vnd.packweir.evidence-envelope.v1+json";
pub const DOCUMENT_MEDIA_TYPE: &str = "application/json";
pub const OCI_MANIFEST_MEDIA_TYPE: &str = "application/vnd.oci.image.manifest.v1+json";
pub const OCI_INDEX_MEDIA_TYPE: &str = "application/vnd.oci.image.index.v1+json";
pub const EMPTY_CONFIG_MEDIA_TYPE: &str = "application/vnd.oci.empty.v1+json";
pub const EMPTY_CONFIG_DIGEST: &str =
    "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a";
pub const MAX_METADATA_BYTES: usize = 1024 * 1024;
pub const MAX_DOCUMENT_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_PAYLOAD_BYTES: usize = 32 * 1024 * 1024;
pub const MAX_DOCUMENTS: usize = 256;
pub const MAX_TRANSFER_BYTES: usize = 48 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EvidenceDocument {
    pub digest: String,
    pub size: u64,
    pub media_type: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceEnvelope {
    pub schema_version: u32,
    /// Raw package SHA-256, without an OCI algorithm prefix.
    pub subject: String,
    /// Untrusted claims supplied by the exporting service.
    pub source: Value,
    /// An opaque, untrusted snapshot, never an authorization decision.
    pub snapshot: Value,
    pub documents: Vec<EvidenceDocument>,
}

/// Standard padded base64, so JSON transport never normalizes document bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EncodedBlob(pub String);

impl EncodedBlob {
    pub fn encode(bytes: &[u8]) -> Self {
        Self(STANDARD.encode(bytes))
    }

    pub fn decode(&self, limit: usize) -> Result<Vec<u8>> {
        let encoded_limit = limit
            .div_ceil(3)
            .checked_mul(4)
            .context("invalid OCI blob decode limit")?;
        ensure!(
            self.0.len() <= encoded_limit,
            "encoded OCI blob exceeds limit"
        );
        let bytes = STANDARD
            .decode(&self.0)
            .context("invalid OCI blob base64")?;
        ensure!(bytes.len() <= limit, "decoded OCI blob exceeds limit");
        ensure!(
            STANDARD.encode(&bytes) == self.0,
            "noncanonical OCI blob base64"
        );
        Ok(bytes)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Transfer {
    pub manifest_digest: String,
    pub manifest: EncodedBlob,
    #[serde(deserialize_with = "unique_blob_map")]
    pub blobs: BTreeMap<String, EncodedBlob>,
}

#[derive(Debug, Clone)]
pub struct ValidatedBundle {
    manifest_digest: String,
    manifest_bytes: Vec<u8>,
    envelope: EvidenceEnvelope,
    blobs: BTreeMap<String, Vec<u8>>,
}

impl ValidatedBundle {
    pub fn manifest_digest(&self) -> &str {
        &self.manifest_digest
    }
    pub fn manifest_bytes(&self) -> &[u8] {
        &self.manifest_bytes
    }
    pub fn envelope(&self) -> &EvidenceEnvelope {
        &self.envelope
    }
    pub fn blobs(&self) -> &BTreeMap<String, Vec<u8>> {
        &self.blobs
    }
    pub fn document_bytes(&self, index: usize) -> Option<&[u8]> {
        self.envelope
            .documents
            .get(index)
            .and_then(|d| self.blobs.get(&d.digest))
            .map(Vec::as_slice)
    }
    pub fn transfer(&self) -> Transfer {
        Transfer {
            manifest_digest: self.manifest_digest.clone(),
            manifest: EncodedBlob::encode(&self.manifest_bytes),
            blobs: self
                .blobs
                .iter()
                .map(|(digest, bytes)| (digest.clone(), EncodedBlob::encode(bytes)))
                .collect(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Descriptor {
    media_type: String,
    digest: String,
    size: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    urls: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    data: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    artifact_type: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    annotations: BTreeMap<String, String>,
}

impl Descriptor {
    fn new(media_type: &str, bytes: &[u8]) -> Self {
        Self {
            media_type: media_type.into(),
            digest: digest(bytes),
            size: bytes.len() as u64,
            urls: None,
            data: None,
            artifact_type: None,
            annotations: BTreeMap::new(),
        }
    }
    fn validate(&self, media_type: &str, limit: usize) -> Result<()> {
        ensure!(
            self.media_type == media_type,
            "unsupported OCI descriptor media type: {}",
            self.media_type
        );
        validate_digest(&self.digest)?;
        ensure!(
            self.size <= limit as u64,
            "OCI descriptor exceeds size limit"
        );
        ensure!(
            self.urls.is_none(),
            "external OCI descriptor URLs are unsupported"
        );
        ensure!(
            self.artifact_type
                .as_deref()
                .is_none_or(|a| a == ARTIFACT_TYPE),
            "unsupported OCI descriptor artifact type"
        );
        if let Some(data) = &self.data {
            let embedded = EncodedBlob(data.clone()).decode(limit)?;
            verify_bytes(self, &embedded)?;
        }
        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Manifest {
    schema_version: u32,
    media_type: String,
    artifact_type: String,
    config: Descriptor,
    layers: Vec<Descriptor>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    subject: Option<Value>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    annotations: BTreeMap<String, String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Index {
    schema_version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    media_type: Option<String>,
    manifests: Vec<Descriptor>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    artifact_type: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    annotations: BTreeMap<String, String>,
}

/// Hash bytes using the only algorithm supported by this bounded profile.
pub fn digest(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

pub fn validate_subject(subject: &str) -> Result<()> {
    ensure!(
        subject.len() == 64
            && subject
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "evidence subject must be a lowercase package SHA-256"
    );
    Ok(())
}

pub fn validate_digest(value: &str) -> Result<()> {
    let Some(raw) = value.strip_prefix("sha256:") else {
        bail!("only sha256 OCI digests are supported")
    };
    validate_subject(raw).context("invalid OCI digest")
}

/// Build a standalone artifact. Document JSON is checked but never reserialized.
pub fn build_bundle(
    subject: &str,
    source: Value,
    snapshot: Value,
    documents: Vec<Vec<u8>>,
) -> Result<ValidatedBundle> {
    validate_subject(subject)?;
    ensure!(
        documents.len() <= MAX_DOCUMENTS,
        "too many OCI evidence documents"
    );
    let mut blobs = BTreeMap::new();
    blobs.insert(EMPTY_CONFIG_DIGEST.into(), b"{}".to_vec());
    let mut references = Vec::new();
    let mut layers = Vec::new();
    let mut payload_size = 0usize;
    let mut seen = BTreeSet::new();
    for bytes in documents {
        ensure!(
            bytes.len() <= MAX_DOCUMENT_BYTES,
            "OCI evidence document exceeds limit"
        );
        payload_size = payload_size
            .checked_add(bytes.len())
            .context("OCI payload size overflow")?;
        ensure!(
            payload_size <= MAX_PAYLOAD_BYTES,
            "OCI evidence payload exceeds limit"
        );
        validate_document(&bytes)?;
        let descriptor = Descriptor::new(DOCUMENT_MEDIA_TYPE, &bytes);
        ensure!(
            seen.insert(descriptor.digest.clone()),
            "duplicate OCI document descriptor"
        );
        references.push(EvidenceDocument {
            digest: descriptor.digest.clone(),
            size: descriptor.size,
            media_type: DOCUMENT_MEDIA_TYPE.into(),
        });
        blobs.insert(descriptor.digest.clone(), bytes);
        layers.push(descriptor);
    }
    let envelope = EvidenceEnvelope {
        schema_version: 1,
        subject: subject.into(),
        source,
        snapshot,
        documents: references,
    };
    let envelope_bytes = serde_json::to_vec(&envelope)?;
    ensure!(
        envelope_bytes.len() <= MAX_METADATA_BYTES,
        "OCI evidence envelope exceeds limit"
    );
    let envelope_descriptor = Descriptor::new(ENVELOPE_MEDIA_TYPE, &envelope_bytes);
    blobs.insert(envelope_descriptor.digest.clone(), envelope_bytes);
    layers.insert(0, envelope_descriptor);
    let manifest = Manifest {
        schema_version: 2,
        media_type: OCI_MANIFEST_MEDIA_TYPE.into(),
        artifact_type: ARTIFACT_TYPE.into(),
        config: Descriptor::new(EMPTY_CONFIG_MEDIA_TYPE, b"{}"),
        layers,
        subject: None,
        annotations: BTreeMap::new(),
    };
    let manifest_bytes = serde_json::to_vec(&manifest)?;
    validate_raw(&digest(&manifest_bytes), manifest_bytes, blobs)
}

/// Parse the HTTP representation with a hard input bound and duplicate-key checks.
pub fn parse_transfer(bytes: &[u8]) -> Result<ValidatedBundle> {
    ensure!(
        bytes.len() <= MAX_TRANSFER_BYTES,
        "OCI transfer exceeds limit"
    );
    let transfer: Transfer =
        serde_json::from_value(strict_json(bytes)?).context("invalid OCI transfer schema")?;
    validate_transfer(transfer)
}

pub fn validate_transfer(transfer: Transfer) -> Result<ValidatedBundle> {
    validate_digest(&transfer.manifest_digest)?;
    ensure!(
        transfer.blobs.len() <= MAX_DOCUMENTS + 2,
        "too many OCI blobs"
    );
    let manifest = transfer.manifest.decode(MAX_METADATA_BYTES)?;
    // Validate descriptors before decoding potentially large blob contents.
    let parsed = parse_manifest(&manifest)?;
    let requirements = manifest_requirements(&parsed)?;
    ensure!(
        transfer.blobs.len() == requirements.len(),
        "OCI transfer has missing or unreferenced blobs"
    );
    let mut total = 0usize;
    let mut blobs = BTreeMap::new();
    for (key, encoded) in transfer.blobs {
        let limit = *requirements.get(&key).context("unreferenced OCI blob")?;
        let raw = encoded.decode(limit)?;
        total = total
            .checked_add(raw.len())
            .context("OCI blob size overflow")?;
        ensure!(
            total <= MAX_PAYLOAD_BYTES + MAX_METADATA_BYTES + 2,
            "OCI transfer decoded payload exceeds limit"
        );
        blobs.insert(key, raw);
    }
    validate_raw(&transfer.manifest_digest, manifest, blobs)
}

fn parse_manifest(bytes: &[u8]) -> Result<Manifest> {
    ensure!(
        bytes.len() <= MAX_METADATA_BYTES,
        "OCI manifest exceeds limit"
    );
    let value = strict_json(bytes)?;
    ensure!(
        !value.as_object().is_some_and(|v| v.contains_key("subject")),
        "standalone evidence must not use an OCI manifest subject"
    );
    let manifest: Manifest =
        serde_json::from_value(value).context("invalid OCI evidence manifest schema")?;
    ensure!(
        manifest.schema_version == 2,
        "unsupported OCI manifest schema version"
    );
    ensure!(
        manifest.media_type == OCI_MANIFEST_MEDIA_TYPE,
        "unsupported OCI manifest media type"
    );
    ensure!(
        manifest.artifact_type == ARTIFACT_TYPE,
        "unsupported OCI evidence artifact type"
    );
    Ok(manifest)
}

fn manifest_requirements(manifest: &Manifest) -> Result<BTreeMap<String, usize>> {
    manifest.config.validate(EMPTY_CONFIG_MEDIA_TYPE, 2)?;
    ensure!(
        manifest.config.digest == EMPTY_CONFIG_DIGEST && manifest.config.size == 2,
        "OCI evidence requires the empty JSON config"
    );
    ensure!(
        !manifest.layers.is_empty() && manifest.layers.len() <= MAX_DOCUMENTS + 1,
        "invalid OCI evidence layer count"
    );
    let mut requirements = BTreeMap::from([(manifest.config.digest.clone(), 2)]);
    let mut seen = BTreeSet::new();
    let mut payload_size = 0u64;
    for (index, layer) in manifest.layers.iter().enumerate() {
        let (media, limit) = if index == 0 {
            (ENVELOPE_MEDIA_TYPE, MAX_METADATA_BYTES)
        } else {
            (DOCUMENT_MEDIA_TYPE, MAX_DOCUMENT_BYTES)
        };
        layer.validate(media, limit)?;
        ensure!(seen.insert(&layer.digest), "duplicate OCI layer descriptor");
        if index > 0 {
            payload_size = payload_size
                .checked_add(layer.size)
                .context("OCI payload size overflow")?;
            ensure!(
                payload_size <= MAX_PAYLOAD_BYTES as u64,
                "OCI evidence payload exceeds limit"
            );
        }
        // Bound reads and base64 decoding by the declared size as well as the
        // media limit. False small sizes must fail before retaining large blobs.
        let declared_size = layer.size as usize;
        requirements
            .entry(layer.digest.clone())
            .and_modify(|v| *v = (*v).min(declared_size))
            .or_insert(declared_size);
    }
    Ok(requirements)
}

fn validate_raw(
    manifest_digest: &str,
    manifest_bytes: Vec<u8>,
    blobs: BTreeMap<String, Vec<u8>>,
) -> Result<ValidatedBundle> {
    validate_digest(manifest_digest)?;
    ensure!(
        digest(&manifest_bytes) == manifest_digest,
        "OCI manifest digest mismatch"
    );
    let manifest = parse_manifest(&manifest_bytes)?;
    let requirements = manifest_requirements(&manifest)?;
    ensure!(
        requirements.len() == blobs.len() && requirements.keys().eq(blobs.keys()),
        "OCI bundle has missing or unreferenced blobs"
    );
    for descriptor in std::iter::once(&manifest.config).chain(manifest.layers.iter()) {
        let bytes = blobs.get(&descriptor.digest).context("missing OCI blob")?;
        verify_bytes(descriptor, bytes)?;
        if let Some(data) = &descriptor.data {
            ensure!(
                EncodedBlob(data.clone()).decode(bytes.len())? == *bytes,
                "embedded OCI descriptor data mismatch"
            );
        }
    }
    ensure!(
        blobs[EMPTY_CONFIG_DIGEST] == b"{}",
        "invalid empty OCI config bytes"
    );
    let envelope_bytes = &blobs[&manifest.layers[0].digest];
    let envelope: EvidenceEnvelope = serde_json::from_value(strict_json(envelope_bytes)?)
        .context("invalid OCI evidence envelope schema")?;
    ensure!(
        envelope.schema_version == 1,
        "unsupported evidence envelope schema version"
    );
    validate_subject(&envelope.subject)?;
    ensure!(
        envelope.source.is_object() && envelope.snapshot.is_object(),
        "evidence source and snapshot claims must be JSON objects"
    );
    ensure!(
        envelope.documents.len() == manifest.layers.len() - 1,
        "envelope and OCI document count mismatch"
    );
    for (document, layer) in envelope
        .documents
        .iter()
        .zip(manifest.layers.iter().skip(1))
    {
        ensure!(
            document.digest == layer.digest
                && document.size == layer.size
                && document.media_type == layer.media_type,
            "envelope and OCI document descriptor mismatch"
        );
        validate_document(&blobs[&document.digest])?;
    }
    Ok(ValidatedBundle {
        manifest_digest: manifest_digest.into(),
        manifest_bytes,
        envelope,
        blobs,
    })
}

fn verify_bytes(descriptor: &Descriptor, bytes: &[u8]) -> Result<()> {
    ensure!(
        bytes.len() as u64 == descriptor.size,
        "OCI blob size mismatch"
    );
    ensure!(
        digest(bytes) == descriptor.digest,
        "OCI blob digest mismatch"
    );
    Ok(())
}

fn validate_document(bytes: &[u8]) -> Result<()> {
    let value = strict_json(bytes).context("invalid raw JSON evidence document")?;
    ensure!(
        value.is_object() || value.is_array(),
        "raw JSON evidence document must be an object or array"
    );
    Ok(())
}

/// Read only the immutable root digest explicitly selected by the caller.
/// Missing content is an error; this reader never completes a layout over a network.
pub fn read_layout(path: &Path, manifest_digest: &str) -> Result<ValidatedBundle> {
    validate_digest(manifest_digest)?;
    let path = absolute_path(path)?;
    reject_links(&path)?;
    ensure!(
        fs::symlink_metadata(&path)?.is_dir(),
        "OCI layout root is not a directory"
    );
    let marker = strict_json(&read_bounded(&path.join("oci-layout"), MAX_METADATA_BYTES)?)?;
    ensure!(
        marker.get("imageLayoutVersion").and_then(Value::as_str) == Some("1.0.0"),
        "unsupported OCI image layout version"
    );
    let index: Index = serde_json::from_value(strict_json(&read_bounded(
        &path.join("index.json"),
        MAX_METADATA_BYTES,
    )?)?)
    .context("invalid OCI index schema")?;
    ensure!(
        index.schema_version == 2
            && index
                .media_type
                .as_deref()
                .is_none_or(|m| m == OCI_INDEX_MEDIA_TYPE),
        "unsupported OCI index schema or media type"
    );
    ensure!(
        !index.manifests.is_empty() && index.manifests.len() <= MAX_DOCUMENTS,
        "invalid OCI index descriptor count"
    );
    let mut seen = BTreeSet::new();
    let mut selected = None;
    for descriptor in &index.manifests {
        descriptor.validate(OCI_MANIFEST_MEDIA_TYPE, MAX_METADATA_BYTES)?;
        ensure!(
            seen.insert(&descriptor.digest),
            "duplicate OCI index descriptor"
        );
        if descriptor.digest == manifest_digest {
            selected = Some(descriptor);
        }
    }
    let selected =
        selected.context("selected immutable manifest digest is absent from OCI index")?;
    let manifest_bytes = read_bounded(&blob_path(&path, manifest_digest)?, MAX_METADATA_BYTES)?;
    verify_bytes(selected, &manifest_bytes)?;
    let manifest = parse_manifest(&manifest_bytes)?;
    let requirements = manifest_requirements(&manifest)?;
    let mut blobs = BTreeMap::new();
    for (key, limit) in requirements {
        blobs.insert(key.clone(), read_bounded(&blob_path(&path, &key)?, limit)?);
    }
    validate_raw(manifest_digest, manifest_bytes, blobs)
}

/// Atomically publish a complete new directory, refusing to replace any entry.
/// Filesystem owners must not concurrently replace ancestor directories.
pub fn write_layout(path: &Path, bundle: &ValidatedBundle) -> Result<()> {
    let path = absolute_path(path)?;
    let parent = path
        .parent()
        .context("OCI layout destination has no parent")?;
    ensure!(path.file_name().is_some(), "invalid OCI layout destination");
    reject_links(parent)?;
    ensure!(
        fs::symlink_metadata(parent)?.is_dir(),
        "OCI layout parent is not a directory"
    );
    match fs::symlink_metadata(&path) {
        Ok(_) => bail!("OCI layout destination already exists"),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    let staging = tempfile::Builder::new()
        .prefix(".packweir-oci-")
        .tempdir_in(parent)?;
    let root = staging.path();
    fs::create_dir(root.join("blobs"))?;
    fs::create_dir(root.join("blobs/sha256"))?;
    for (key, bytes) in &bundle.blobs {
        write_new(&blob_path(root, key)?, bytes)?;
    }
    write_new(
        &blob_path(root, bundle.manifest_digest())?,
        bundle.manifest_bytes(),
    )?;
    write_new(
        &root.join("oci-layout"),
        b"{\"imageLayoutVersion\":\"1.0.0\"}",
    )?;
    let mut descriptor = Descriptor::new(OCI_MANIFEST_MEDIA_TYPE, bundle.manifest_bytes());
    descriptor.artifact_type = Some(ARTIFACT_TYPE.into());
    descriptor.annotations.insert(
        "org.opencontainers.image.ref.name".into(),
        "packweir".into(),
    );
    let index = Index {
        schema_version: 2,
        media_type: Some(OCI_INDEX_MEDIA_TYPE.into()),
        manifests: vec![descriptor],
        artifact_type: None,
        annotations: BTreeMap::new(),
    };
    write_new(&root.join("index.json"), &serde_json::to_vec(&index)?)?;
    // Validate what was written before it becomes visible at the destination.
    read_layout(root, bundle.manifest_digest())?;
    rename_new(root, &path).context("publishing new OCI layout directory")?;
    Ok(())
}

fn blob_path(root: &Path, key: &str) -> Result<PathBuf> {
    validate_digest(key)?;
    Ok(root.join("blobs").join("sha256").join(&key[7..]))
}

fn absolute_path(path: &Path) -> Result<PathBuf> {
    ensure!(!path.as_os_str().is_empty(), "empty OCI layout path");
    ensure!(
        !path.components().any(|c| matches!(c, Component::ParentDir)),
        "OCI layout path must not contain parent traversal"
    );
    Ok(if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    })
}

fn reject_metadata(metadata: &fs::Metadata) -> Result<()> {
    ensure!(
        !metadata.file_type().is_symlink(),
        "OCI path contains a symbolic link"
    );
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        ensure!(
            metadata.file_attributes() & 0x400 == 0,
            "OCI path contains a reparse point"
        );
    }
    Ok(())
}

fn reject_links(path: &Path) -> Result<()> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        // Windows drive prefixes are not complete absolute paths until RootDir.
        if matches!(component, Component::Prefix(_)) {
            continue;
        }
        reject_metadata(
            &fs::symlink_metadata(&current)
                .with_context(|| format!("checking OCI path {}", current.display()))?,
        )?;
    }
    Ok(())
}

fn read_bounded(path: &Path, limit: usize) -> Result<Vec<u8>> {
    reject_links(path)?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(0x00200000); // FILE_FLAG_OPEN_REPARSE_POINT
    }
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(0x20000 | 0x800); // O_NOFOLLOW | O_NONBLOCK
    }
    let file = options
        .open(path)
        .with_context(|| format!("opening OCI file {}", path.display()))?;
    let metadata = file.metadata()?;
    reject_metadata(&metadata)?;
    ensure!(metadata.is_file(), "OCI content is not a regular file");
    ensure!(metadata.len() <= limit as u64, "OCI file exceeds limit");
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(limit as u64 + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= limit, "OCI file exceeds limit");
    Ok(bytes)
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    reject_links(path.parent().context("OCI file has no parent")?)?;
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn rename_new(from: &Path, to: &Path) -> Result<()> {
    use std::{ffi::CString, os::unix::ffi::OsStrExt};
    unsafe extern "C" {
        fn renameat2(
            olddirfd: i32,
            oldpath: *const std::ffi::c_char,
            newdirfd: i32,
            newpath: *const std::ffi::c_char,
            flags: u32,
        ) -> i32;
    }
    let from = CString::new(from.as_os_str().as_bytes())?;
    let to = CString::new(to.as_os_str().as_bytes())?;
    // RENAME_NOREPLACE is atomic and also refuses existing empty directories.
    let result = unsafe { renameat2(-100, from.as_ptr(), -100, to.as_ptr(), 1) };
    if result != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

#[cfg(windows)]
fn rename_new(from: &Path, to: &Path) -> Result<()> {
    fs::rename(from, to).map_err(Into::into)
}

#[cfg(not(any(windows, target_os = "linux")))]
fn rename_new(_from: &Path, _to: &Path) -> Result<()> {
    bail!("atomic no-replace OCI layout publication is unsupported on this platform")
}

fn unique_blob_map<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<BTreeMap<String, EncodedBlob>, D::Error> {
    struct UniqueMap;
    impl<'de> Visitor<'de> for UniqueMap {
        type Value = BTreeMap<String, EncodedBlob>;
        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.write_str("a blob map with unique digest keys")
        }
        fn visit_map<M: MapAccess<'de>>(
            self,
            mut map: M,
        ) -> std::result::Result<Self::Value, M::Error> {
            let mut result = BTreeMap::new();
            while let Some((key, value)) = map.next_entry()? {
                if result.insert(key, value).is_some() {
                    return Err(de::Error::custom("duplicate OCI blob map key"));
                }
                if result.len() > MAX_DOCUMENTS + 2 {
                    return Err(de::Error::custom("too many OCI blobs"));
                }
            }
            Ok(result)
        }
    }
    deserializer.deserialize_map(UniqueMap)
}

/// serde_json::Value normally collapses repeated keys; evidence must reject them.
pub(crate) fn strict_json(bytes: &[u8]) -> Result<Value> {
    struct UniqueValue(Value);
    impl<'de> Deserialize<'de> for UniqueValue {
        fn deserialize<D: Deserializer<'de>>(
            deserializer: D,
        ) -> std::result::Result<Self, D::Error> {
            struct UniqueVisitor;
            impl<'de> Visitor<'de> for UniqueVisitor {
                type Value = UniqueValue;
                fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                    f.write_str("JSON without duplicate object keys")
                }
                fn visit_bool<E: de::Error>(self, v: bool) -> std::result::Result<Self::Value, E> {
                    Ok(UniqueValue(Value::Bool(v)))
                }
                fn visit_i64<E: de::Error>(self, v: i64) -> std::result::Result<Self::Value, E> {
                    Ok(UniqueValue(v.into()))
                }
                fn visit_u64<E: de::Error>(self, v: u64) -> std::result::Result<Self::Value, E> {
                    Ok(UniqueValue(v.into()))
                }
                fn visit_f64<E: de::Error>(self, v: f64) -> std::result::Result<Self::Value, E> {
                    serde_json::Number::from_f64(v)
                        .map(|v| UniqueValue(Value::Number(v)))
                        .ok_or_else(|| E::custom("invalid JSON number"))
                }
                fn visit_str<E: de::Error>(self, v: &str) -> std::result::Result<Self::Value, E> {
                    Ok(UniqueValue(Value::String(v.into())))
                }
                fn visit_string<E: de::Error>(
                    self,
                    v: String,
                ) -> std::result::Result<Self::Value, E> {
                    Ok(UniqueValue(Value::String(v)))
                }
                fn visit_none<E: de::Error>(self) -> std::result::Result<Self::Value, E> {
                    Ok(UniqueValue(Value::Null))
                }
                fn visit_unit<E: de::Error>(self) -> std::result::Result<Self::Value, E> {
                    Ok(UniqueValue(Value::Null))
                }
                fn visit_seq<A: SeqAccess<'de>>(
                    self,
                    mut seq: A,
                ) -> std::result::Result<Self::Value, A::Error> {
                    let mut values = Vec::new();
                    while let Some(value) = seq.next_element::<UniqueValue>()? {
                        values.push(value.0);
                    }
                    Ok(UniqueValue(Value::Array(values)))
                }
                fn visit_map<M: MapAccess<'de>>(
                    self,
                    mut map: M,
                ) -> std::result::Result<Self::Value, M::Error> {
                    let mut values = serde_json::Map::new();
                    while let Some((key, value)) = map.next_entry::<String, UniqueValue>()? {
                        if values.insert(key, value.0).is_some() {
                            return Err(de::Error::custom("duplicate JSON object key"));
                        }
                    }
                    Ok(UniqueValue(Value::Object(values)))
                }
            }
            deserializer.deserialize_any(UniqueVisitor)
        }
    }
    Ok(serde_json::from_slice::<UniqueValue>(bytes)?.0)
}
