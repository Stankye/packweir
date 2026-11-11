//! Canonical, immutable Maven release coordinates and bounded publication inputs.
use crate::{identity::PackageIdentity, model::Ecosystem};
use anyhow::{Result, bail, ensure};
use quick_xml::{Reader, events::Event};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Coordinate {
    pub name: String,
    pub group: String,
    pub artifact: String,
    pub version: String,
}

fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
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
        && !value.contains("..")
}

fn name_parts(name: &str) -> Result<(&str, &str)> {
    let (group, artifact) = name
        .split_once(':')
        .ok_or_else(|| anyhow::anyhow!("Maven name must be group:artifact"))?;
    ensure!(
        group.len() <= 192 && group.split('.').all(identifier) && identifier(artifact),
        "invalid Maven name"
    );
    Ok((group, artifact))
}

impl Coordinate {
    pub fn new(name: &str, version: &str) -> Result<Self> {
        let (group, artifact) = name_parts(name)?;
        ensure!(identifier(version), "invalid Maven release version");
        ensure!(
            !version.to_ascii_uppercase().ends_with("SNAPSHOT")
                && !["LATEST", "RELEASE"].contains(&version.to_ascii_uppercase().as_str()),
            "only explicit immutable Maven release versions are supported"
        );
        Ok(Self {
            name: name.into(),
            group: group.into(),
            artifact: artifact.into(),
            version: version.into(),
        })
    }

    pub fn package(&self) -> PackageIdentity {
        let mut package =
            crate::identity::from_coordinates(Ecosystem::Maven, &self.name, &self.version)
                .expect("validated Maven coordinate");
        package.basis = "hosted_coordinates_declared".into();
        package
    }

    pub fn artifact_root(&self) -> String {
        format!("{}/{}", self.group.replace('.', "/"), self.artifact)
    }

    pub fn artifact_prefix(&self) -> String {
        format!(
            "{}/{}/{}-{}",
            self.artifact_root(),
            self.version,
            self.artifact,
            self.version
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChecksumAlgorithm {
    Md5,
    Sha1,
    Sha256,
    Sha512,
}

impl ChecksumAlgorithm {
    pub fn suffix(self) -> &'static str {
        match self {
            Self::Md5 => "md5",
            Self::Sha1 => "sha1",
            Self::Sha256 => "sha256",
            Self::Sha512 => "sha512",
        }
    }
    fn from_suffix(value: &str) -> Option<Self> {
        match value {
            "md5" => Some(Self::Md5),
            "sha1" => Some(Self::Sha1),
            "sha256" => Some(Self::Sha256),
            "sha512" => Some(Self::Sha512),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UploadKind {
    Artifact {
        filename: String,
        content_type: String,
    },
    Checksum {
        base_path: String,
        algorithm: ChecksumAlgorithm,
    },
    IgnoredMetadata,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadPath {
    Artifact {
        coordinate: Coordinate,
    },
    Checksum {
        coordinate: Coordinate,
        base_path: String,
        algorithm: ChecksumAlgorithm,
    },
    Metadata {
        name: String,
        algorithm: Option<ChecksumAlgorithm>,
    },
}

pub fn validate_path(path: &str) -> Result<()> {
    ensure!(
        !path.is_empty()
            && path.len() <= 1024
            && path
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"/._-".contains(&b)),
        "invalid Maven path"
    );
    ensure!(
        path.split('/')
            .all(|part| !part.is_empty() && part != "." && part != ".." && !part.contains("..")),
        "noncanonical Maven path"
    );
    Ok(())
}

fn sidecar(path: &str) -> (&str, Option<ChecksumAlgorithm>) {
    if let Some((base, suffix)) = path.rsplit_once('.')
        && let Some(algorithm) = ChecksumAlgorithm::from_suffix(suffix)
    {
        (base, Some(algorithm))
    } else {
        (path, None)
    }
}

pub fn classify_upload(coordinate: &Coordinate, path: &str) -> Result<UploadKind> {
    // Do not trust deserialized public fields without validating their relationship.
    ensure!(
        Coordinate::new(&coordinate.name, &coordinate.version)? == *coordinate,
        "inconsistent Maven coordinate"
    );
    validate_path(path)?;
    let (base, algorithm) = sidecar(path);
    if base == format!("{}/maven-metadata.xml", coordinate.artifact_root()) {
        return Ok(UploadKind::IgnoredMetadata);
    }
    let prefix = coordinate.artifact_prefix();
    let remainder = base
        .strip_prefix(&prefix)
        .ok_or_else(|| anyhow::anyhow!("upload does not match staged Maven coordinate"))?;
    let extension = if let Some(extension) = remainder.strip_prefix('.') {
        extension
    } else if let Some(classified) = remainder.strip_prefix('-') {
        let (classifier, extension) = classified
            .split_once('.')
            .ok_or_else(|| anyhow::anyhow!("Maven classifier requires extension"))?;
        ensure!(identifier(classifier), "invalid Maven classifier");
        extension
    } else {
        bail!("invalid Maven artifact filename")
    };
    ensure!(
        !extension.is_empty()
            && extension.len() <= 64
            && extension.split('.').all(|part| !part.is_empty()
                && part.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')),
        "invalid Maven extension"
    );
    ensure!(
        !extension
            .split('.')
            .any(|part| ChecksumAlgorithm::from_suffix(part).is_some()),
        "nested checksum sidecars are unsupported"
    );
    if let Some(algorithm) = algorithm {
        return Ok(UploadKind::Checksum {
            base_path: base.into(),
            algorithm,
        });
    }
    let content_type = match extension {
        "pom" => "application/xml",
        "jar" => "application/java-archive",
        "module" => "application/json",
        _ => "application/octet-stream",
    };
    Ok(UploadKind::Artifact {
        filename: base.rsplit('/').next().expect("nonempty path").into(),
        content_type: content_type.into(),
    })
}

pub fn parse_read_path(path: &str) -> Result<ReadPath> {
    validate_path(path)?;
    let (base, algorithm) = sidecar(path);
    let parts: Vec<_> = base.split('/').collect();
    if parts.last() == Some(&"maven-metadata.xml") {
        ensure!(
            parts.len() >= 3,
            "Maven metadata requires group and artifact"
        );
        let name = format!(
            "{}:{}",
            parts[..parts.len() - 2].join("."),
            parts[parts.len() - 2]
        );
        let (group, artifact) = name_parts(&name)?;
        ensure!(
            base == format!("{}/{artifact}/maven-metadata.xml", group.replace('.', "/")),
            "noncanonical Maven metadata path"
        );
        return Ok(ReadPath::Metadata { name, algorithm });
    }
    ensure!(
        parts.len() >= 4,
        "Maven artifact requires group, artifact and version"
    );
    let name = format!(
        "{}:{}",
        parts[..parts.len() - 3].join("."),
        parts[parts.len() - 3]
    );
    let coordinate = Coordinate::new(&name, parts[parts.len() - 2])?;
    match classify_upload(&coordinate, path)? {
        UploadKind::Artifact { .. } => Ok(ReadPath::Artifact { coordinate }),
        UploadKind::Checksum {
            base_path,
            algorithm,
        } => Ok(ReadPath::Checksum {
            coordinate,
            base_path,
            algorithm,
        }),
        UploadKind::IgnoredMetadata => unreachable!("metadata handled above"),
    }
}

pub fn checksum(bytes: &[u8], algorithm: ChecksumAlgorithm) -> String {
    match algorithm {
        ChecksumAlgorithm::Md5 => hex::encode(md5::Md5::digest(bytes)),
        ChecksumAlgorithm::Sha1 => hex::encode(sha1::Sha1::digest(bytes)),
        ChecksumAlgorithm::Sha256 => hex::encode(sha2::Sha256::digest(bytes)),
        ChecksumAlgorithm::Sha512 => hex::encode(sha2::Sha512::digest(bytes)),
    }
}

pub fn validate_checksum(
    uploaded: &[u8],
    expected: &str,
    algorithm: ChecksumAlgorithm,
) -> Result<()> {
    ensure!(uploaded.len() <= 256, "Maven checksum is too large");
    let supplied = std::str::from_utf8(uploaded)?.trim();
    let length = match algorithm {
        ChecksumAlgorithm::Md5 => 32,
        ChecksumAlgorithm::Sha1 => 40,
        ChecksumAlgorithm::Sha256 => 64,
        ChecksumAlgorithm::Sha512 => 128,
    };
    ensure!(
        expected.len() == length
            && expected.bytes().all(|b| b.is_ascii_hexdigit())
            && supplied.len() == length
            && supplied.bytes().all(|b| b.is_ascii_hexdigit())
            && supplied.eq_ignore_ascii_case(expected),
        "Maven checksum mismatch"
    );
    Ok(())
}

fn valid_xml_character(character: char) -> bool {
    (!character.is_control() || matches!(character, '\n' | '\r' | '\t'))
        && matches!(character as u32, 0x9 | 0xA | 0xD | 0x20..=0xD7FF | 0xE000..=0xFFFD | 0x10000..=0x10FFFF)
}

fn pom_values(bytes: &[u8], coordinate: &Coordinate) -> Result<BTreeMap<String, String>> {
    ensure!(
        Coordinate::new(&coordinate.name, &coordinate.version)? == *coordinate,
        "inconsistent Maven coordinate"
    );
    ensure!(
        !bytes.is_empty() && bytes.len() <= 1024 * 1024,
        "POM must be between 1 byte and 1 MiB"
    );
    let xml = std::str::from_utf8(bytes)?;
    ensure!(
        xml.chars().all(valid_xml_character),
        "invalid POM XML character"
    );
    let mut reader = Reader::from_str(xml);
    reader.config_mut().check_end_names = true;
    let mut stack = Vec::<String>::new();
    let mut values = BTreeMap::<String, String>::new();
    let mut roots = 0;
    let mut elements = 0;
    let mut declared = false;
    let observed = [
        "modelVersion",
        "groupId",
        "artifactId",
        "version",
        "packaging",
    ];
    loop {
        match reader.read_event()? {
            event @ (Event::Start(_) | Event::Empty(_)) => {
                let empty = matches!(event, Event::Empty(_));
                let element = match event {
                    Event::Start(element) | Event::Empty(element) => element,
                    _ => unreachable!(),
                };
                let name = std::str::from_utf8(element.name().as_ref())?.to_owned();
                ensure!(
                    !name.contains(':') && !name.is_empty(),
                    "prefixed POM elements are unsupported"
                );
                elements += 1;
                ensure!(
                    elements <= 10_000 && stack.len() < 32,
                    "POM structure exceeds limits"
                );
                if stack.is_empty() {
                    roots += 1;
                    ensure!(
                        roots == 1 && name == "project",
                        "POM requires one project root"
                    );
                }
                if stack.len() == 2 && observed.contains(&stack[1].as_str()) {
                    bail!("POM coordinates must be direct text");
                }
                for attribute in element.attributes() {
                    let attribute = attribute?;
                    let key = std::str::from_utf8(attribute.key.as_ref())?;
                    let value = attribute.unescape_value()?;
                    ensure!(
                        value.chars().all(valid_xml_character),
                        "invalid POM XML attribute character"
                    );
                    if key == "xmlns" {
                        ensure!(
                            stack.is_empty() && value == "http://maven.apache.org/POM/4.0.0",
                            "unsupported POM namespace"
                        );
                    } else {
                        ensure!(
                            !key.starts_with("xmlns:")
                                || (stack.is_empty()
                                    && key == "xmlns:xsi"
                                    && value == "http://www.w3.org/2001/XMLSchema-instance"),
                            "unsupported POM namespace binding"
                        );
                    }
                }
                if stack.len() == 1 && observed.contains(&name.as_str()) {
                    ensure!(
                        values.insert(name.clone(), String::new()).is_none(),
                        "duplicate POM coordinate field"
                    );
                }
                if !empty {
                    stack.push(name);
                }
            }
            Event::End(_) => {
                ensure!(stack.pop().is_some(), "invalid POM end tag");
            }
            Event::Text(text) => {
                let text = text.xml_content()?;
                if stack.is_empty() {
                    ensure!(text.trim().is_empty(), "text outside POM root");
                }
                if stack.len() == 2
                    && let Some(value) = values.get_mut(&stack[1])
                {
                    value.push_str(&text);
                    ensure!(value.len() <= 256, "POM coordinate too long");
                }
            }
            Event::Decl(declaration) => {
                ensure!(
                    roots == 0 && !declared,
                    "XML declaration must precede POM root and occur once"
                );
                declared = true;
                ensure!(
                    declaration.version()?.as_ref() == b"1.0",
                    "POM requires XML 1.0"
                );
                if let Some(encoding) = declaration.encoding() {
                    ensure!(
                        encoding?.eq_ignore_ascii_case(b"UTF-8"),
                        "POM must use UTF-8"
                    );
                }
            }
            Event::Comment(_) => {
                ensure!(
                    stack.len() != 2 || !observed.contains(&stack[1].as_str()),
                    "comments within POM coordinates are unsupported"
                );
            }
            Event::GeneralRef(reference) => {
                ensure!(
                    !stack.is_empty() && reference.len() <= 16,
                    "invalid POM character reference"
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
                        _ => bail!("custom POM entities are unsupported"),
                    }
                };
                ensure!(
                    valid_xml_character(character),
                    "invalid POM XML character reference"
                );
                if stack.len() == 2
                    && let Some(value) = values.get_mut(&stack[1])
                {
                    value.push(character);
                    ensure!(value.len() <= 256, "POM coordinate too long");
                }
            }
            Event::DocType(_) | Event::PI(_) | Event::CData(_) => {
                bail!("POM DTDs, processing instructions and CDATA are unsupported")
            }
            Event::Eof => break,
        }
    }
    ensure!(roots == 1 && stack.is_empty(), "incomplete POM");
    for (field, expected) in [
        ("modelVersion", "4.0.0"),
        ("groupId", coordinate.group.as_str()),
        ("artifactId", coordinate.artifact.as_str()),
        ("version", coordinate.version.as_str()),
    ] {
        ensure!(
            values
                .get(field)
                .is_some_and(|value| value.trim() == expected),
            "POM {field} must directly match staged coordinate"
        );
    }
    ensure!(
        values.get("packaging").is_none_or(|value| [
            "jar",
            "pom",
            "war",
            "ear",
            "aar",
            "maven-plugin",
            "bundle"
        ]
        .contains(&value.trim())),
        "unsupported POM packaging"
    );
    Ok(values)
}

pub fn validate_pom(bytes: &[u8], coordinate: &Coordinate) -> Result<()> {
    pom_values(bytes, coordinate).map(|_| ())
}

/// The unclassified primary file that must accompany this POM before release.
pub fn required_primary(bytes: &[u8], coordinate: &Coordinate) -> Result<Option<String>> {
    let values = pom_values(bytes, coordinate)?;
    let packaging = values
        .get("packaging")
        .map(|value| value.trim())
        .unwrap_or("jar");
    let extension = match packaging {
        "pom" => return Ok(None),
        "jar" | "maven-plugin" | "bundle" => "jar",
        "war" => "war",
        "ear" => "ear",
        "aar" => "aar",
        _ => bail!("unsupported POM packaging"),
    };
    Ok(Some(format!(
        "{}.{extension}",
        coordinate.artifact_prefix()
    )))
}

fn escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

pub fn metadata_xml(name: &str, versions: &[String]) -> Vec<u8> {
    let (group, artifact) = name.split_once(':').unwrap_or((name, ""));
    let versions: BTreeSet<_> = versions.iter().collect();
    let mut xml = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<metadata><groupId>{}</groupId><artifactId>{}</artifactId><versioning><versions>",
        escape(group),
        escape(artifact)
    );
    for version in versions {
        xml.push_str(&format!("<version>{}</version>", escape(version)));
    }
    xml.push_str("</versions></versioning></metadata>\n");
    xml.into_bytes()
}
