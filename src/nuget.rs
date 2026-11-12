//! Canonical NuGet coordinates and bounded inspection of original `.nupkg` bytes.
//!
//! Coordinate declarations and the presence of `.signature.p7s` are not publisher
//! authentication. Inspection never extracts files or executes package content.
//! Input and expanded ZIP content are each limited to 512 MiB and 10,000 entries;
//! the original UTF-8 nuspec is limited to 1 MiB, 10,000 elements, and 32 levels.
use crate::{identity::PackageIdentity, model::Ecosystem};
use anyhow::{Result, bail, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use quick_xml::{Reader, events::Event};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::{
    cmp::Ordering,
    collections::{BTreeMap, BTreeSet},
    io::{Cursor, Read},
};

const MAX_NUSPEC_BYTES: u64 = 1024 * 1024;
const MAX_PACKAGE_BYTES: usize = 512 * 1024 * 1024;
const MAX_EXPANDED_BYTES: u64 = 512 * 1024 * 1024;
const MAX_ENTRIES: usize = 10_000;

/// The ASCII subset of NuGet's package-ID grammar, with its 100-character bound.
/// Underscores are word characters, rather than dot/dash separators.
pub fn canonical_name(name: &str) -> Result<String> {
    ensure!(
        !name.is_empty()
            && name.len() <= 100
            && name.split(['.', '-']).all(|part| !part.is_empty()
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')),
        "invalid NuGet package ID"
    );
    Ok(name.to_ascii_lowercase())
}

fn labels(value: &str, prerelease: bool) -> Result<()> {
    ensure!(
        value.split('.').all(|part| !part.is_empty()
            && part
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            && (!prerelease
                || part.len() == 1
                || !part.starts_with('0')
                || !part.bytes().all(|byte| byte.is_ascii_digit()))),
        "invalid NuGet version label"
    );
    Ok(())
}

/// Normalize the immutable identity NuGet uses during restore: one to four
/// numeric parts, at least three in the result, no zero revision or build
/// metadata, and case-insensitive prerelease labels. Numeric parts use the same
/// nonnegative Int32 range as NuGetVersion/System.Version.
pub fn normalize_version(version: &str) -> Result<String> {
    ensure!(
        !version.is_empty()
            && version.len() <= 256
            && version
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b".-+".contains(&byte)),
        "invalid NuGet version"
    );
    let (without_metadata, metadata) = version
        .split_once('+')
        .map_or((version, None), |(version, metadata)| {
            (version, Some(metadata))
        });
    if let Some(metadata) = metadata {
        labels(metadata, false)?;
    }
    let (core, prerelease) = without_metadata
        .split_once('-')
        .map_or((without_metadata, None), |(core, prerelease)| {
            (core, Some(prerelease))
        });
    if let Some(prerelease) = prerelease {
        labels(prerelease, true)?;
    }
    let parts: Vec<_> = core.split('.').collect();
    ensure!(
        (1..=4).contains(&parts.len()),
        "invalid NuGet numeric version"
    );
    let mut numbers = [0u32; 4];
    for (index, part) in parts.iter().enumerate() {
        ensure!(
            !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()),
            "invalid NuGet numeric version"
        );
        // Parsing the significant digits allows arbitrarily padded zeroes up to
        // the overall bound without changing NuGet's numeric identity.
        let significant = part.trim_start_matches('0');
        numbers[index] = if significant.is_empty() {
            0
        } else {
            significant.parse()?
        };
        ensure!(
            numbers[index] <= i32::MAX as u32,
            "NuGet numeric version is too large"
        );
    }
    let mut normalized = format!("{}.{}.{}", numbers[0], numbers[1], numbers[2]);
    if numbers[3] != 0 {
        normalized.push_str(&format!(".{}", numbers[3]));
    }
    if let Some(prerelease) = prerelease {
        normalized.push('-');
        normalized.push_str(&prerelease.to_ascii_lowercase());
    }
    Ok(normalized)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Coordinate {
    pub name: String,
    pub version: String,
}

impl Coordinate {
    pub fn new(name: &str, version: &str) -> Result<Self> {
        Ok(Self {
            name: canonical_name(name)?,
            version: normalize_version(version)?,
        })
    }

    pub fn package(&self) -> PackageIdentity {
        let mut package =
            crate::identity::from_coordinates(Ecosystem::Nuget, &self.name, &self.version)
                .expect("validated NuGet coordinate");
        package.basis = "hosted_coordinates_declared".into();
        package
    }

    pub fn filename(&self) -> String {
        format!("{}.{}.nupkg", self.name, self.version)
    }

    /// Relative to the advertised PackageBaseAddress resource.
    pub fn package_path(&self) -> String {
        format!("{}/{}/{}", self.name, self.version, self.filename())
    }

    pub fn nuspec_path(&self) -> String {
        format!("{}/{}/{}.nuspec", self.name, self.version, self.name)
    }

    pub fn hash_path(&self) -> String {
        format!("{}.sha512", self.package_path())
    }
}

fn canonical_coordinate(coordinate: &Coordinate) -> Result<()> {
    ensure!(
        Coordinate::new(&coordinate.name, &coordinate.version)? == *coordinate,
        "noncanonical NuGet coordinate"
    );
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadPath {
    Versions { name: String },
    Package { coordinate: Coordinate },
    Nuspec { coordinate: Coordinate },
    Sha512 { coordinate: Coordinate },
}

/// Flat-container paths have one canonical spelling, including casing and the
/// normalized version. URL escaping is rejected before namespace dispatch.
pub fn parse_read_path(path: &str) -> Result<ReadPath> {
    ensure!(
        !path.is_empty()
            && path.len() <= 1024
            && path.bytes().all(|byte| byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || b"/._-".contains(&byte)),
        "invalid NuGet path"
    );
    let parts: Vec<_> = path.split('/').collect();
    if parts.len() == 2 && parts[1] == "index.json" {
        let name = canonical_name(parts[0])?;
        ensure!(name == parts[0], "noncanonical NuGet ID path");
        return Ok(ReadPath::Versions { name });
    }
    ensure!(parts.len() == 3, "invalid NuGet flat-container path");
    let coordinate = Coordinate::new(parts[0], parts[1])?;
    ensure!(
        coordinate.name == parts[0] && coordinate.version == parts[1],
        "noncanonical NuGet coordinate path"
    );
    if path == coordinate.package_path() {
        Ok(ReadPath::Package { coordinate })
    } else if path == coordinate.nuspec_path() {
        Ok(ReadPath::Nuspec { coordinate })
    } else if path == coordinate.hash_path() {
        Ok(ReadPath::Sha512 { coordinate })
    } else {
        bail!("NuGet filename does not match coordinate")
    }
}

/// NuGet's hash sidecar is base64 of the raw SHA-512 digest, not hexadecimal.
pub fn checksum(bytes: &[u8]) -> String {
    STANDARD.encode(sha2::Sha512::digest(bytes))
}

fn version_order(left: &str, right: &str) -> Ordering {
    let split = |value: &str| {
        let (core, pre) = value.split_once('-').unwrap_or((value, ""));
        let mut numbers = [0u32; 4];
        for (index, part) in core.split('.').enumerate() {
            numbers[index] = part.parse().expect("normalized version");
        }
        (numbers, pre.to_owned())
    };
    let (left_numbers, left_pre) = split(left);
    let (right_numbers, right_pre) = split(right);
    let order = left_numbers.cmp(&right_numbers);
    if order != Ordering::Equal {
        return order;
    }
    match (left_pre.is_empty(), right_pre.is_empty()) {
        (true, false) => Ordering::Greater,
        (false, true) => Ordering::Less,
        _ => {
            for (left, right) in left_pre.split('.').zip(right_pre.split('.')) {
                let order = match (left.parse::<i32>(), right.parse::<i32>()) {
                    (Ok(left), Ok(right)) => left.cmp(&right),
                    (Ok(_), Err(_)) => Ordering::Less,
                    (Err(_), Ok(_)) => Ordering::Greater,
                    _ => left.cmp(right),
                };
                if order != Ordering::Equal {
                    return order;
                }
            }
            left_pre
                .split('.')
                .count()
                .cmp(&right_pre.split('.').count())
        }
    }
}

pub fn versions_json(versions: &[String]) -> serde_json::Value {
    let unique: BTreeSet<_> = versions
        .iter()
        .filter_map(|value| normalize_version(value).ok())
        .collect();
    let mut versions: Vec<_> = unique.into_iter().collect();
    versions.sort_by(|left, right| version_order(left, right));
    serde_json::json!({ "versions": versions })
}

/// Only resources implemented by the caller are advertised. Publish should be a
/// release-specific staging URL, never an unscoped overwrite endpoint.
pub fn service_index(flat_base: Option<&str>, publish: Option<&str>) -> serde_json::Value {
    let mut resources = Vec::new();
    if let Some(flat_base) = flat_base {
        resources.push(serde_json::json!({
            "@id": flat_base, "@type": "PackageBaseAddress/3.0.0"
        }));
    }
    if let Some(publish) = publish {
        resources.push(serde_json::json!({ "@id": publish, "@type": "PackagePublish/2.0.0" }));
    }
    serde_json::json!({ "version": "3.0.0", "resources": resources })
}

fn valid_xml_character(character: char) -> bool {
    (!character.is_control() || matches!(character, '\n' | '\r' | '\t'))
        && matches!(character as u32, 0x9 | 0xA | 0xD | 0x20..=0xD7FF | 0xE000..=0xFFFD | 0x10000..=0x10FFFF)
}

fn xml_name(name: &str) -> bool {
    name.bytes()
        .next()
        .is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_')
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(&byte))
}

fn coordinate_text(stack: &[String]) -> bool {
    stack.len() == 3 && stack[1] == "metadata" && ["id", "version"].contains(&stack[2].as_str())
}

/// Read only direct package/metadata/id and version declarations. Other nuspec
/// declarations, including dependency ranges and build assets, remain original.
pub fn nuspec_coordinate(bytes: &[u8]) -> Result<Coordinate> {
    ensure!(
        !bytes.is_empty() && bytes.len() as u64 <= MAX_NUSPEC_BYTES,
        "nuspec must be between 1 byte and 1 MiB"
    );
    let xml = std::str::from_utf8(bytes)?;
    ensure!(
        xml.chars().all(valid_xml_character),
        "invalid nuspec XML character"
    );
    let mut reader = Reader::from_str(xml);
    reader.config_mut().check_end_names = true;
    reader.config_mut().check_comments = true;
    let mut stack = Vec::<String>::new();
    let mut values = BTreeMap::<String, String>::new();
    let mut roots = 0;
    let mut metadata = 0;
    let mut elements = 0;
    let mut declared = false;
    let mut declaration_allowed = true;
    loop {
        match reader.read_event()? {
            event @ (Event::Start(_) | Event::Empty(_)) => {
                let empty = matches!(event, Event::Empty(_));
                let element = match event {
                    Event::Start(element) | Event::Empty(element) => element,
                    _ => unreachable!(),
                };
                let name = std::str::from_utf8(element.name().as_ref())?.to_owned();
                ensure!(xml_name(&name), "invalid or prefixed nuspec element");
                elements += 1;
                ensure!(
                    elements <= MAX_ENTRIES && stack.len() < 32,
                    "nuspec structure exceeds limits"
                );
                if stack.is_empty() {
                    roots += 1;
                    ensure!(
                        roots == 1 && name == "package",
                        "nuspec requires one package root"
                    );
                }
                ensure!(
                    !coordinate_text(&stack),
                    "nuspec coordinates must be direct text"
                );
                if name == "metadata" {
                    metadata += 1;
                    ensure!(
                        stack.len() == 1 && metadata == 1,
                        "nuspec requires one direct metadata element"
                    );
                }
                for attribute in element.attributes() {
                    let attribute = attribute?;
                    ensure!(
                        !attribute.value.contains(&b'<'),
                        "unescaped less-than sign in nuspec XML attribute"
                    );
                    let key = std::str::from_utf8(attribute.key.as_ref())?;
                    let value = attribute.unescape_value()?;
                    ensure!(
                        value.chars().all(valid_xml_character),
                        "invalid nuspec XML attribute character"
                    );
                    match key {
                        "xmlns" => ensure!(
                            stack.is_empty()
                                && [
                                    "http://schemas.microsoft.com/packaging/2010/07/nuspec.xsd",
                                    "http://schemas.microsoft.com/packaging/2011/08/nuspec.xsd",
                                    "http://schemas.microsoft.com/packaging/2011/10/nuspec.xsd",
                                    "http://schemas.microsoft.com/packaging/2012/06/nuspec.xsd",
                                    "http://schemas.microsoft.com/packaging/2013/01/nuspec.xsd",
                                    "http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd",
                                ]
                                .contains(&value.as_ref()),
                            "unsupported nuspec namespace"
                        ),
                        "xmlns:xsi" => ensure!(
                            stack.is_empty()
                                && value == "http://www.w3.org/2001/XMLSchema-instance",
                            "unsupported nuspec namespace binding"
                        ),
                        _ => ensure!(xml_name(key), "prefixed nuspec attributes are unsupported"),
                    }
                }
                if stack.len() == 2
                    && stack[1] == "metadata"
                    && ["id", "version"].contains(&name.as_str())
                {
                    ensure!(
                        values.insert(name.clone(), String::new()).is_none(),
                        "duplicate nuspec coordinate field"
                    );
                }
                if !empty {
                    stack.push(name);
                }
            }
            Event::End(_) => {
                ensure!(stack.pop().is_some(), "invalid nuspec end tag");
            }
            Event::Text(text) => {
                let raw_text: &[u8] = text.as_ref();
                ensure!(
                    !raw_text.windows(3).any(|bytes| bytes == b"]]>"),
                    "CDATA terminator outside nuspec CDATA"
                );
                let text = text.xml_content()?;
                if stack.is_empty() {
                    declaration_allowed = false;
                    ensure!(text.trim().is_empty(), "text outside nuspec root");
                }
                if coordinate_text(&stack) {
                    let value = values
                        .get_mut(&stack[2])
                        .expect("observed coordinate field");
                    value.push_str(&text);
                    ensure!(value.len() <= 256, "nuspec coordinate field is too long");
                }
            }
            Event::GeneralRef(reference) => {
                ensure!(
                    !stack.is_empty() && reference.len() <= 16,
                    "invalid nuspec character reference"
                );
                let character = if let Some(character) = reference.resolve_char_ref()? {
                    character
                } else {
                    match reference.decode()?.as_ref() {
                        "amp" => '&',
                        "lt" => '<',
                        "gt" => '>',
                        "quot" => '"',
                        "apos" => '\'',
                        _ => bail!("custom nuspec entities are unsupported"),
                    }
                };
                ensure!(
                    valid_xml_character(character),
                    "invalid nuspec XML character reference"
                );
                if coordinate_text(&stack) {
                    let value = values
                        .get_mut(&stack[2])
                        .expect("observed coordinate field");
                    value.push(character);
                    ensure!(value.len() <= 256, "nuspec coordinate field is too long");
                }
            }
            Event::Decl(declaration) => {
                ensure!(
                    roots == 0 && !declared && declaration_allowed,
                    "XML declaration must precede nuspec root and occur once"
                );
                declared = true;
                ensure!(
                    declaration.version()?.as_ref() == b"1.0",
                    "nuspec requires XML 1.0"
                );
                if let Some(encoding) = declaration.encoding() {
                    ensure!(
                        encoding?.eq_ignore_ascii_case(b"UTF-8"),
                        "nuspec must use UTF-8"
                    );
                }
            }
            Event::Comment(_) => {
                declaration_allowed = false;
                ensure!(
                    !coordinate_text(&stack),
                    "comments within nuspec coordinates are unsupported"
                );
            }
            Event::CData(text) => {
                ensure!(
                    !stack.is_empty() && !coordinate_text(&stack),
                    "CDATA within nuspec coordinates is unsupported"
                );
                ensure!(
                    text.decode()?.chars().all(valid_xml_character),
                    "invalid nuspec CDATA character"
                );
            }
            Event::DocType(_) | Event::PI(_) => {
                bail!("nuspec DTDs and processing instructions are unsupported")
            }
            Event::Eof => break,
        }
    }
    ensure!(
        roots == 1 && metadata == 1 && stack.is_empty(),
        "incomplete nuspec"
    );
    Coordinate::new(
        values
            .get("id")
            .ok_or_else(|| anyhow::anyhow!("nuspec requires direct id"))?
            .trim(),
        values
            .get("version")
            .ok_or_else(|| anyhow::anyhow!("nuspec requires direct version"))?
            .trim(),
    )
}

pub fn validate_nuspec(bytes: &[u8], coordinate: &Coordinate) -> Result<()> {
    canonical_coordinate(coordinate)?;
    ensure!(
        nuspec_coordinate(bytes)? == *coordinate,
        "nuspec does not match staged NuGet coordinate"
    );
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedPackage {
    pub coordinate: Coordinate,
    /// Exact original manifest bytes, suitable for the flat-container endpoint.
    pub nuspec: Vec<u8>,
}

fn archive_path(path: &str, is_dir: bool) -> Result<String> {
    ensure!(
        !path.is_empty() && path.len() <= 1024,
        "invalid NuGet archive path length"
    );
    // NuGet unescapes archive paths during extraction. Check that interpretation
    // and use it for duplicate detection, while retaining all original bytes.
    let decoded = percent_encoding::percent_decode_str(path).decode_utf8()?;
    ensure!(
        !decoded
            .chars()
            .any(|character| character.is_control() || "\\:%?*\"<>|".contains(character)),
        "unsafe NuGet archive path"
    );
    let normalized = if is_dir {
        decoded.strip_suffix('/').unwrap_or(&decoded)
    } else {
        &decoded
    };
    ensure!(
        normalized.split('/').all(|part| !part.is_empty()
            && part != "."
            && part != ".."
            && !part.ends_with(['.', ' '])),
        "noncanonical NuGet archive path"
    );
    for part in normalized.split('/') {
        let stem = part.split('.').next().unwrap_or("").to_ascii_uppercase();
        ensure!(
            !["CON", "PRN", "AUX", "NUL"].contains(&stem.as_str())
                && !(stem.len() == 4
                    && (stem.starts_with("COM") || stem.starts_with("LPT"))
                    && matches!(stem.as_bytes()[3], b'1'..=b'9')),
            "reserved NuGet archive path"
        );
    }
    Ok(normalized.to_lowercase())
}

struct DescriptorLocation {
    header: u64,
    data_end: u64,
    crc32: u32,
    compressed: u64,
    expanded: u64,
    has_descriptor: bool,
}

/// Fixed-size descriptor fields supplement the library's local/central checks.
/// Try both layouts independently: a CRC may itself equal the optional magic.
fn descriptor_matches(bytes: &[u8], entry: &DescriptorLocation) -> bool {
    for offset in [0usize, 4] {
        if offset == 4 && !bytes.starts_with(b"PK\x07\x08") {
            continue;
        }
        for width in [4usize, 8] {
            let length = offset + 4 + 2 * width;
            let Some(fields) = bytes.get(offset..length) else {
                continue;
            };
            let crc = u32::from_le_bytes(fields[..4].try_into().expect("four CRC bytes"));
            let number = |start| {
                if width == 4 {
                    u32::from_le_bytes(
                        fields[start..start + 4]
                            .try_into()
                            .expect("four size bytes"),
                    ) as u64
                } else {
                    u64::from_le_bytes(
                        fields[start..start + 8]
                            .try_into()
                            .expect("eight size bytes"),
                    )
                }
            };
            if (crc, number(4), number(4 + width))
                == (entry.crc32, entry.compressed, entry.expanded)
            {
                return true;
            }
        }
    }
    false
}

fn validate_descriptors(
    bytes: &[u8],
    entries: &mut [DescriptorLocation],
    central_start: u64,
) -> Result<()> {
    entries.sort_unstable_by_key(|entry| entry.header);
    for (index, entry) in entries.iter().enumerate() {
        if !entry.has_descriptor {
            continue;
        }
        let next_header = entries
            .get(index + 1)
            .map_or(central_start, |entry| entry.header);
        ensure!(
            entry.data_end <= next_header && next_header <= bytes.len() as u64,
            "NuGet ZIP data descriptor overlaps another header"
        );
        let gap = &bytes[usize::try_from(entry.data_end)?..usize::try_from(next_header)?];
        // The largest possible descriptor is 24 bytes. Trailing gap bytes remain
        // subject to the library's unlisted-local-header scan.
        ensure!(
            descriptor_matches(&gap[..gap.len().min(24)], entry),
            "NuGet ZIP data descriptor disagrees with central directory"
        );
    }
    Ok(())
}

/// Inspect every ZIP entry under hard bounds and return the original nuspec.
/// Signature-shaped files are opaque content; no trusted-signature claim is made.
pub fn inspect_package(bytes: &[u8]) -> Result<ValidatedPackage> {
    ensure!(
        !bytes.is_empty() && bytes.len() <= MAX_PACKAGE_BYTES,
        "NuGet package exceeds input limit"
    );
    ensure!(
        bytes.starts_with(b"PK\x03\x04"),
        "NuGet package must be a ZIP archive"
    );
    // Check the central entry count before the indexed reader allocates metadata
    // for every entry. The dependency is exactly pinned for this upstream API.
    {
        let mut directory = zip::unstable::read::ZipIterable::try_new(
            Cursor::new(bytes),
            zip::read::Config::default(),
        )?;
        ensure!(
            !directory.is_empty() && directory.len() <= MAX_ENTRIES,
            "NuGet archive entry-count limit exceeded"
        );
        // Fully check this candidate's central directory so the indexed reader
        // does not fall back to an earlier, unbounded EOCD candidate.
        for entry in directory.files()? {
            entry?;
        }
    }
    let mut archive = zip::ZipArchive::new(Cursor::new(bytes))?;
    ensure!(
        !archive.is_empty() && archive.len() <= MAX_ENTRIES,
        "NuGet archive entry-count limit exceeded"
    );
    archive.validate_header_consistency()?;
    ensure!(
        archive.offset() == 0,
        "NuGet archive may not have a prepended payload"
    );
    let mut paths = BTreeMap::<String, bool>::new();
    let mut descriptors = Vec::with_capacity(archive.len());
    let mut central_start = bytes.len() as u64;
    let mut expanded = 0u64;
    let mut manifest: Option<(String, Vec<u8>)> = None;
    for index in 0..archive.len() {
        let mut entry = archive.by_index(index)?;
        let name = entry.name()?.into_owned();
        central_start = central_start.min(entry.central_header_start());
        descriptors.push(DescriptorLocation {
            header: entry.header_start(),
            data_end: entry
                .data_start()
                .ok_or_else(|| anyhow::anyhow!("NuGet ZIP has no data offset"))?
                .checked_add(entry.compressed_size())
                .ok_or_else(|| anyhow::anyhow!("NuGet ZIP data offset overflow"))?,
            crc32: entry.crc32(),
            compressed: entry.compressed_size(),
            expanded: entry.size(),
            has_descriptor: entry.flags().is_using_data_descriptor(),
        });
        ensure!(
            entry
                .unix_mode()
                .is_none_or(|mode| matches!(mode & 0o170000, 0 | 0o040000 | 0o100000)),
            "NuGet ZIP links and special files are unsupported"
        );
        let directory = entry.is_dir();
        ensure!(
            !directory || entry.size() == 0,
            "NuGet ZIP directory has payload bytes"
        );
        let path = archive_path(&name, directory)?;
        ensure!(
            paths.insert(path.clone(), directory).is_none(),
            "duplicate NuGet archive path"
        );
        for (position, _) in path.match_indices('/') {
            ensure!(
                paths
                    .get(&path[..position])
                    .is_none_or(|directory| *directory),
                "NuGet archive file/directory collision"
            );
        }
        if !directory {
            let prefix = format!("{path}/");
            ensure!(
                paths
                    .range(prefix.clone()..)
                    .next()
                    .is_none_or(|(name, _)| !name.starts_with(&prefix)),
                "NuGet archive file/directory collision"
            );
        }
        ensure!(
            entry.size() <= MAX_EXPANDED_BYTES - expanded,
            "NuGet archive expanded-byte limit exceeded"
        );
        let root_nuspec = !path.contains('/') && path.ends_with(".nuspec");
        if root_nuspec {
            ensure!(
                !directory && manifest.is_none() && !name.contains('%'),
                "NuGet package requires exactly one root nuspec"
            );
            ensure!(entry.size() <= MAX_NUSPEC_BYTES, "nuspec exceeds 1 MiB");
        }
        let limit = if root_nuspec {
            MAX_NUSPEC_BYTES
        } else {
            MAX_EXPANDED_BYTES - expanded
        };
        let mut content = Vec::new();
        // Reading to EOF verifies the decompressor/CRC, including files that are
        // not the manifest. Discarding content avoids executing or extracting it.
        let used = if root_nuspec {
            entry.by_ref().take(limit + 1).read_to_end(&mut content)? as u64
        } else {
            std::io::copy(&mut entry.by_ref().take(limit + 1), &mut std::io::sink())?
        };
        ensure!(
            used <= limit && used == entry.size(),
            "NuGet ZIP entry size mismatch or expanded-byte limit exceeded"
        );
        expanded += used;
        if root_nuspec {
            manifest = Some((path, content));
        }
    }
    validate_descriptors(bytes, &mut descriptors, central_start)?;
    let (path, nuspec) = manifest
        .ok_or_else(|| anyhow::anyhow!("NuGet package requires exactly one root nuspec"))?;
    let coordinate = nuspec_coordinate(&nuspec)?;
    ensure!(
        path == format!("{}.nuspec", coordinate.name),
        "root nuspec filename does not match package ID"
    );
    Ok(ValidatedPackage { coordinate, nuspec })
}

pub fn validate_package(bytes: &[u8], coordinate: &Coordinate) -> Result<ValidatedPackage> {
    canonical_coordinate(coordinate)?;
    let package = inspect_package(bytes)?;
    ensure!(
        package.coordinate == *coordinate,
        "NuGet package does not match staged coordinate"
    );
    Ok(package)
}
