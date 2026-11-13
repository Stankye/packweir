pub use crate::bounds::safe_path;
use crate::model::{FileRecord, Inventory, sha256};
use anyhow::{Result, bail, ensure};
use flate2::read::MultiGzDecoder;
use std::{
    collections::{BTreeMap, HashSet},
    io::{Cursor, Read},
};

#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub expanded_bytes: u64,
    pub files: usize,
    pub depth: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            expanded_bytes: 512 * 1024 * 1024,
            files: 10_000,
            depth: 3,
        }
    }
}
struct Inspector {
    limits: Limits,
    used: u64,
    records: Vec<FileRecord>,
    seen: HashSet<String>,
    binary_inputs: Option<BTreeMap<String, Vec<u8>>>,
    binary_kinds: std::collections::BTreeSet<String>,
    binary_bytes: usize,
}

pub fn inspect(name: &str, bytes: &[u8], limits: Limits) -> Result<Inventory> {
    Ok(inspect_inner(name, bytes, limits, None)?.0)
}

/// Recover the exact native-file bytes with the same bounded archive parser used
/// by inventory. These bytes stay internal to analysis; they are not documents,
/// package registrations, or an assertion that transformed content is trusted.
pub fn inspect_binary_inputs(
    name: &str,
    bytes: &[u8],
    limits: Limits,
) -> Result<(Inventory, BTreeMap<String, Vec<u8>>)> {
    let kinds = ["elf", "pe", "wasm", "mach_o_or_java"].map(str::to_owned);
    inspect_analysis_inputs(name, bytes, limits, &kinds)
}

pub fn inspect_analysis_inputs(
    name: &str,
    bytes: &[u8],
    limits: Limits,
    kinds: &[String],
) -> Result<(Inventory, BTreeMap<String, Vec<u8>>)> {
    ensure!(
        !kinds.is_empty()
            && kinds.len() <= 5
            && kinds
                .iter()
                .all(|kind| is_native_candidate(kind) || kind == "binary"),
        "invalid analysis input kinds"
    );
    inspect_inner(name, bytes, limits, Some(kinds))
}

fn inspect_inner(
    name: &str,
    bytes: &[u8],
    limits: Limits,
    capture_binary_inputs: Option<&[String]>,
) -> Result<(Inventory, BTreeMap<String, Vec<u8>>)> {
    let mut inspector = Inspector {
        limits,
        used: 0,
        records: vec![],
        seen: HashSet::new(),
        binary_inputs: capture_binary_inputs.map(|_| BTreeMap::new()),
        binary_kinds: capture_binary_inputs
            .unwrap_or_default()
            .iter()
            .cloned()
            .collect(),
        binary_bytes: 0,
    };
    inspector.visit(name, bytes, 0)?;
    let inventory = Inventory {
        subject: sha256(bytes),
        files: inspector.records,
        warnings: vec![],
        coverage:
            "bounded file inventory; dependency and native-library identification are not complete"
                .into(),
    };
    Ok((inventory, inspector.binary_inputs.unwrap_or_default()))
}

pub fn is_native_candidate(kind: &str) -> bool {
    matches!(kind, "elf" | "pe" | "wasm" | "mach_o_or_java")
}

impl Inspector {
    fn record(&mut self, path: &str, bytes: &[u8]) -> Result<()> {
        ensure!(
            self.records.len() < self.limits.files,
            "file-count limit exceeded"
        );
        ensure!(
            self.seen.insert(path.into()),
            "duplicate archive path: {path}"
        );
        let digest = sha256(bytes);
        let file_kind = kind(bytes);
        if let Some(inputs) = &mut self.binary_inputs
            && self.binary_kinds.contains(file_kind)
            && !inputs.contains_key(&digest)
        {
            ensure!(
                bytes.len() <= 16 * 1024 * 1024,
                "native analysis input exceeds 16 MiB"
            );
            self.binary_bytes = self
                .binary_bytes
                .checked_add(bytes.len())
                .ok_or_else(|| anyhow::anyhow!("native analysis byte count overflow"))?;
            ensure!(
                self.binary_bytes <= 64 * 1024 * 1024 && inputs.len() < 256,
                "native analysis inputs exceed 64 MiB or 256 distinct files"
            );
            inputs.insert(digest.clone(), bytes.to_vec());
        }
        self.records.push(FileRecord {
            path: path.into(),
            sha256: digest,
            size: bytes.len() as u64,
            kind: file_kind.into(),
        });
        Ok(())
    }
    fn bounded_read(&mut self, reader: impl Read) -> Result<Vec<u8>> {
        let remaining = self.limits.expanded_bytes.saturating_sub(self.used);
        let mut bytes = vec![];
        reader
            .take(remaining.saturating_add(1))
            .read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() as u64 <= remaining,
            "expanded-byte limit exceeded"
        );
        self.used += bytes.len() as u64;
        Ok(bytes)
    }
    fn visit(&mut self, path: &str, bytes: &[u8], depth: usize) -> Result<()> {
        ensure!(safe_path(path), "unsafe archive path: {path}");
        self.record(path, bytes)?;
        let zip = bytes.starts_with(b"PK\x03\x04") || bytes.starts_with(b"PK\x05\x06");
        let gzip = bytes.starts_with(&[0x1f, 0x8b]);
        let tar = path.ends_with(".tar") || looks_like_tar(bytes);
        let unsupported = bytes.starts_with(b"BZh")
            || bytes.starts_with(b"\xfd7zXZ\0")
            || bytes.starts_with(b"7z\xbc\xaf\x27\x1c")
            || bytes.starts_with(b"Rar!")
            || bytes.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]);
        ensure!(
            !unsupported,
            "unsupported archive compression; safety inspection incomplete"
        );
        if !(zip || gzip || tar) {
            return Ok(());
        }
        ensure!(depth < self.limits.depth, "archive nesting limit exceeded");
        if zip {
            let mut archive = zip::ZipArchive::new(Cursor::new(bytes))?;
            ensure!(
                archive.len() <= self.limits.files,
                "archive file-count limit exceeded"
            );
            // Consumers must not see different filenames or payload metadata than the inspector.
            archive.validate_header_consistency()?;
            for i in 0..archive.len() {
                let mut entry = archive.by_index(i)?;
                let name = entry.name()?;
                ensure!(safe_path(&name), "unsafe ZIP path");
                ensure!(
                    entry.unix_mode().is_none_or(|m| m & 0o170000 != 0o120000),
                    "ZIP symlink rejected"
                );
                if entry.is_dir() {
                    continue;
                }
                let nested = format!("{path}!/{name}");
                let content = self.bounded_read(&mut entry)?;
                self.visit(&nested, &content, depth + 1)?;
            }
        } else if gzip {
            let content = self.bounded_read(MultiGzDecoder::new(bytes))?;
            let nested = if path.ends_with(".tgz") || path.ends_with(".crate") {
                format!("{path}!/payload.tar")
            } else {
                format!(
                    "{path}!/{}",
                    path.rsplit('/')
                        .next()
                        .unwrap_or("payload")
                        .trim_end_matches(".gz")
                )
            };
            self.visit(&nested, &content, depth + 1)?;
        } else if tar {
            let mut archive = tar::Archive::new(Cursor::new(bytes));
            archive.set_ignore_zeros(true);
            for (index, entry) in archive.entries()?.enumerate() {
                ensure!(
                    index < self.limits.files,
                    "archive entry-count limit exceeded"
                );
                let mut entry = entry?;
                let entry_path = entry.path()?.to_string_lossy().into_owned();
                ensure!(safe_path(&entry_path), "unsafe TAR path");
                if entry.header().entry_type().is_dir() {
                    continue;
                }
                if !entry.header().entry_type().is_file() {
                    bail!("TAR links and special files rejected");
                }
                let nested = format!("{path}!/{entry_path}");
                let content = self.bounded_read(&mut entry)?;
                self.visit(&nested, &content, depth + 1)?;
            }
        }
        Ok(())
    }
}

// V7 archives have no ustar magic, and decoded files need not retain a .tar
// suffix. Match the same unsigned header checksum used by tar::Archive. Leading
// zero records are traversed because inspection uses set_ignore_zeros(true).
fn looks_like_tar(bytes: &[u8]) -> bool {
    if bytes.len() > 262 && &bytes[257..262] == b"ustar" {
        return true;
    }
    for block in bytes.as_chunks::<512>().0 {
        if block.iter().all(|byte| *byte == 0) {
            continue;
        }
        let header = tar::Header::from_byte_slice(block);
        let checksum: u32 = block
            .iter()
            .enumerate()
            .map(|(index, byte)| {
                if (148..156).contains(&index) {
                    u32::from(b' ')
                } else {
                    u32::from(*byte)
                }
            })
            .sum();
        return header.cksum().is_ok_and(|expected| expected == checksum);
    }
    false
}

pub fn kind(bytes: &[u8]) -> &'static str {
    if bytes.starts_with(b"\x7fELF") {
        "elf"
    } else if bytes.starts_with(b"MZ") {
        "pe"
    } else if bytes.starts_with(b"\0asm") {
        "wasm"
    } else if bytes.len() >= 4
        && [
            [0xfe, 0xed, 0xfa, 0xce],
            [0xfe, 0xed, 0xfa, 0xcf],
            [0xce, 0xfa, 0xed, 0xfe],
            [0xcf, 0xfa, 0xed, 0xfe],
            [0xca, 0xfe, 0xba, 0xbe],
        ]
        .iter()
        .any(|m| bytes.starts_with(m))
    {
        "mach_o_or_java"
    } else if bytes.starts_with(b"PK") {
        "zip"
    } else if bytes.starts_with(&[0x1f, 0x8b]) {
        "gzip"
    } else if std::str::from_utf8(bytes).is_ok() {
        "text"
    } else {
        "binary"
    }
}

pub fn cyclonedx(inventory: &Inventory) -> serde_json::Value {
    serde_json::json!({"bomFormat":"CycloneDX", "specVersion":"1.6", "version":1,
        "serialNumber":format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        "metadata":{"timestamp":chrono::Utc::now().to_rfc3339(), "component":{"type":"file", "name":inventory.subject,
            "hashes":[{"alg":"SHA-256","content":inventory.subject}]},
            "properties":[{"name":"packweir:inventory-origin","value":"artifact-observed"},
                {"name":"packweir:coverage","value":inventory.coverage}]},
        "components":inventory.files.iter().map(|f| serde_json::json!({"type":"file", "name":f.path,
            "bom-ref":format!("{}:{}", f.sha256, f.path), "hashes":[{"alg":"SHA-256","content":f.sha256}]})).collect::<Vec<_>>()})
}

pub fn spdx(inventory: &Inventory) -> serde_json::Value {
    serde_json::json!({"spdxVersion":"SPDX-2.3", "dataLicense":"CC0-1.0", "SPDXID":"SPDXRef-DOCUMENT",
        "name":format!("Packweir observed inventory {}", inventory.subject),
        "documentNamespace":format!("https://packweir.invalid/spdx/{}", uuid::Uuid::new_v4()),
        "creationInfo":{"creators":[format!("Tool: packweir-{}", env!("CARGO_PKG_VERSION"))],"created":chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string()},
        "comment":inventory.coverage,
        "files":inventory.files.iter().enumerate().map(|(i,f)| serde_json::json!({"SPDXID":format!("SPDXRef-File-{i}"),
            "fileName":f.path, "checksums":[{"algorithm":"SHA256","checksumValue":f.sha256}],
            "licenseConcluded":"NOASSERTION", "copyrightText":"NOASSERTION"})).collect::<Vec<_>>(),
        "relationships":inventory.files.iter().enumerate().map(|(i,_)| serde_json::json!({"spdxElementId":"SPDXRef-DOCUMENT",
            "relationshipType":"DESCRIBES", "relatedSpdxElement":format!("SPDXRef-File-{i}")})).collect::<Vec<_>>()})
}

/// Validate supported envelope shape, retaining the original. This does not assert semantic completeness.
pub fn sbom_format(document: &serde_json::Value) -> Result<&'static str> {
    if document.get("bomFormat").and_then(|v| v.as_str()) == Some("CycloneDX") {
        ensure!(
            document["specVersion"] == "1.6" && document["version"].as_u64().is_some(),
            "supported CycloneDX version is 1.6"
        );
        Ok("cyclonedx")
    } else {
        ensure!(
            document["spdxVersion"] == "SPDX-2.3"
                && document["SPDXID"] == "SPDXRef-DOCUMENT"
                && document["documentNamespace"].is_string(),
            "supported SPDX version is 2.3"
        );
        Ok("spdx")
    }
}
