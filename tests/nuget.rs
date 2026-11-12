use packweir::nuget::{
    Coordinate, ReadPath, canonical_name, checksum, inspect_package, normalize_version,
    nuspec_coordinate, parse_read_path, service_index, validate_nuspec, validate_package,
    versions_json,
};
use std::io::{Cursor, Read, Write};

fn manifest(name: &str, version: &str, body: &str) -> Vec<u8> {
    format!("<?xml version=\"1.0\" encoding=\"utf-8\"?><package xmlns=\"http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd\"><metadata><id>{name}</id><version>{version}</version><authors>Fixture</authors><description>Local fixture</description>{body}</metadata></package>").into_bytes()
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = !0u32;
    for byte in bytes {
        crc ^= *byte as u32;
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xedb88320u32.wrapping_mul(crc & 1));
        }
    }
    !crc
}

// Construct stored ZIPs directly so deliberately duplicate and hidden local
// entries remain available to the adversarial tests (ZIP writers forbid them).
fn archive_visible(entries: &[(&str, &[u8])], visible: &[usize]) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut offsets = Vec::new();
    for (name, content) in entries {
        offsets.push(bytes.len() as u32);
        bytes.extend_from_slice(b"PK\x03\x04");
        for field in [20u16, 0, 0, 0, 0] {
            bytes.extend_from_slice(&field.to_le_bytes());
        }
        for field in [crc32(content), content.len() as u32, content.len() as u32] {
            bytes.extend_from_slice(&field.to_le_bytes());
        }
        bytes.extend_from_slice(&(name.len() as u16).to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(name.as_bytes());
        bytes.extend_from_slice(content);
    }
    let directory = bytes.len() as u32;
    for index in visible {
        let (name, content) = entries[*index];
        bytes.extend_from_slice(b"PK\x01\x02");
        for field in [20u16, 20, 0, 0, 0, 0] {
            bytes.extend_from_slice(&field.to_le_bytes());
        }
        for field in [crc32(content), content.len() as u32, content.len() as u32] {
            bytes.extend_from_slice(&field.to_le_bytes());
        }
        for field in [name.len() as u16, 0, 0, 0, 0] {
            bytes.extend_from_slice(&field.to_le_bytes());
        }
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&offsets[*index].to_le_bytes());
        bytes.extend_from_slice(name.as_bytes());
    }
    let directory_size = bytes.len() as u32 - directory;
    bytes.extend_from_slice(b"PK\x05\x06");
    for field in [0u16, 0, visible.len() as u16, visible.len() as u16] {
        bytes.extend_from_slice(&field.to_le_bytes());
    }
    bytes.extend_from_slice(&directory_size.to_le_bytes());
    bytes.extend_from_slice(&directory.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes
}

fn archive(entries: &[(&str, &[u8])]) -> Vec<u8> {
    archive_visible(entries, &(0..entries.len()).collect::<Vec<_>>())
}

fn coordinate() -> Coordinate {
    Coordinate::new("Dev.Packweir.Fixture", "1.0.0").unwrap()
}

fn with_last_descriptor(
    entries: &[(&str, &[u8])],
    wide: bool,
    signature: bool,
) -> (Vec<u8>, usize) {
    let mut bytes = archive(entries);
    let central = entries
        .iter()
        .map(|(name, content)| 30 + name.len() + content.len())
        .sum::<usize>();
    let last_local = entries[..entries.len() - 1]
        .iter()
        .map(|(name, content)| 30 + name.len() + content.len())
        .sum::<usize>();
    let last_central = central
        + entries[..entries.len() - 1]
            .iter()
            .map(|(name, _)| 46 + name.len())
            .sum::<usize>();
    let content = entries.last().unwrap().1;
    let mut descriptor = Vec::new();
    if signature {
        descriptor.extend_from_slice(b"PK\x07\x08");
    }
    descriptor.extend_from_slice(&crc32(content).to_le_bytes());
    for _ in 0..2 {
        if wide {
            descriptor.extend_from_slice(&(content.len() as u64).to_le_bytes());
        } else {
            descriptor.extend_from_slice(&(content.len() as u32).to_le_bytes());
        }
    }
    bytes[last_local + 6] = 8;
    bytes[last_local + 14..last_local + 26].fill(0);
    bytes[last_central + 8] = 8;
    bytes.splice(central..central, descriptor.iter().copied());
    let eocd = bytes.len() - 22;
    bytes[eocd + 16..eocd + 20]
        .copy_from_slice(&((central + descriptor.len()) as u32).to_le_bytes());
    (bytes, central)
}

fn four_bytes_with_crc(target: u32) -> [u8; 4] {
    let zero = crc32(&[0; 4]);
    let mut basis = [(0u32, 0u32); 32];
    for bit in 0..32 {
        let mut value = crc32(&(1u32 << bit).to_le_bytes()) ^ zero;
        let mut combination = 1u32 << bit;
        for pivot in (0..32).rev() {
            if value & (1u32 << pivot) == 0 {
                continue;
            }
            if basis[pivot].0 == 0 {
                basis[pivot] = (value, combination);
                break;
            }
            value ^= basis[pivot].0;
            combination ^= basis[pivot].1;
        }
    }
    let mut remaining = target ^ zero;
    let mut answer = 0u32;
    for pivot in (0..32).rev() {
        if remaining & (1u32 << pivot) != 0 {
            remaining ^= basis[pivot].0;
            answer ^= basis[pivot].1;
        }
    }
    assert_eq!(remaining, 0);
    let bytes = answer.to_le_bytes();
    assert_eq!(crc32(&bytes), target);
    bytes
}

#[test]
fn immutable_coordinates_coalesce_nuget_aliases_and_create_declared_identity() {
    let expected = coordinate();
    for name in [
        "dev.packweir.fixture",
        "DEV.PACKWEIR.FIXTURE",
        "Dev.Packweir.Fixture",
    ] {
        for version in [
            "1",
            "1.0",
            "1.0.0",
            "1.0.0.0",
            "01.00.000.0",
            "1.0.0+original.build",
        ] {
            assert_eq!(
                Coordinate::new(name, version).unwrap(),
                expected,
                "{name} {version}"
            );
        }
    }
    assert_eq!(
        normalize_version("001.02.003.004-RC.2+build.0001").unwrap(),
        "1.2.3.4-rc.2"
    );
    assert_eq!(
        normalize_version("1.0-ALPHA").unwrap(),
        normalize_version("1-alpha+different").unwrap()
    );
    assert_ne!(
        Coordinate::new(&expected.name, "1.0.0.1").unwrap(),
        expected
    );
    assert_ne!(
        Coordinate::new(&expected.name, "1.0.0-rc.1").unwrap(),
        expected
    );
    let package = expected.package();
    assert_eq!(package.name, "dev.packweir.fixture");
    assert_eq!(package.version, "1.0.0");
    assert_eq!(package.purl, "pkg:nuget/dev.packweir.fixture@1.0.0");
    assert_eq!(package.basis, "hosted_coordinates_declared");
    assert!(package.is_canonical());
    for name in [
        "_",
        "_fixture",
        "fixture_",
        "fixture__part",
        "fixture.Part-2",
    ] {
        assert!(canonical_name(name).is_ok(), "{name}");
    }
    assert!(canonical_name(&"a".repeat(100)).is_ok());
}

#[test]
fn invalid_dynamic_ambiguous_and_overflow_coordinates_are_rejected() {
    for name in [
        "", "x/y", "../x", "a..b", "a.-b", "a--b", "-a", "a.", "a ", " a", "x%2ey", "é", "x\0y",
        "x:y",
    ] {
        assert!(Coordinate::new(name, "1.0.0").is_err(), "{name:?}");
    }
    assert!(canonical_name(&"a".repeat(101)).is_err());
    for version in [
        "",
        "latest",
        "[1,2)",
        "1.*",
        "v1.0",
        "1.",
        "1..0",
        "1.2.3.4.5",
        "1.0/extra",
        "1.0%2bbuild",
        " 1.0",
        "1.0 ",
        "1_0",
        "1.0-",
        "1.0+",
        "1.0-a..b",
        "1.0+a..b",
        "1.0+a+b",
        "1.0-01",
        "1.0-rc.01",
        "2147483648",
        "1.2.3.4294967296",
        "1.0-ä",
        "1.0\n",
    ] {
        assert!(normalize_version(version).is_err(), "{version:?}");
    }
    assert_eq!(
        normalize_version("2147483647.0.0.0").unwrap(),
        "2147483647.0.0"
    );
    assert!(normalize_version(&format!("1.0-{}", "a".repeat(256))).is_err());
}

#[test]
fn flat_container_paths_bind_exactly_to_lowercase_normalized_coordinates() {
    let coordinate = coordinate();
    assert_eq!(coordinate.filename(), "dev.packweir.fixture.1.0.0.nupkg");
    assert_eq!(
        parse_read_path(&coordinate.package_path()).unwrap(),
        ReadPath::Package {
            coordinate: coordinate.clone()
        }
    );
    assert_eq!(
        parse_read_path(&coordinate.nuspec_path()).unwrap(),
        ReadPath::Nuspec {
            coordinate: coordinate.clone()
        }
    );
    assert_eq!(
        parse_read_path(&coordinate.hash_path()).unwrap(),
        ReadPath::Sha512 {
            coordinate: coordinate.clone()
        }
    );
    assert_eq!(
        parse_read_path("dev.packweir.fixture/index.json").unwrap(),
        ReadPath::Versions {
            name: coordinate.name.clone()
        }
    );
    let prerelease = Coordinate::new("Fixture", "1.2.3.4-RC.2+build").unwrap();
    assert_eq!(
        parse_read_path(&prerelease.package_path()).unwrap(),
        ReadPath::Package {
            coordinate: prerelease
        }
    );
    for path in [
        "/fixture/index.json",
        "fixture//index.json",
        "fixture/../index.json",
        "fixture/./index.json",
        "Fixture/index.json",
        "fixture/1/fixture.1.nupkg",
        "fixture/1.0.0.0/fixture.1.0.0.0.nupkg",
        "fixture/1.0.0+build/fixture.1.0.0+build.nupkg",
        "fixture/1.0.0/other.1.0.0.nupkg",
        "fixture/1.0.0/fixture.nuspec/extra",
        "fixture\\index.json",
        "fixture%2fother/index.json",
        "fixture/index.json?x",
        "fixture/index.json#x",
        "flatcontainer/fixture/index.json",
        "fixture/1.0.0/fixture.1.0.0.nupkg.sha512.sha512",
    ] {
        assert!(parse_read_path(path).is_err(), "{path}");
    }
}

#[test]
fn direct_manifest_identity_accepts_declared_aliases_and_preserves_dependency_semantics() {
    let coordinate = coordinate();
    let bytes = manifest(
        "Dev.Packweir.Fixture",
        "01.0.0.0+original",
        "<dependencies><group targetFramework=\"net8.0\"><dependency id=\"Other.Package\" version=\"[1.0,2.0)\" exclude=\"Build,Analyzers\" /></group></dependencies><developmentDependency>true</developmentDependency><readme>README.md</readme>",
    );
    assert_eq!(nuspec_coordinate(&bytes).unwrap(), coordinate);
    validate_nuspec(&bytes, &coordinate).unwrap();
    let package = archive(&[
        ("Dev.Packweir.Fixture.nuspec", &bytes),
        ("lib/net8.0/_._", b""),
        ("README.md", b"fixture"),
    ]);
    let original = package.clone();
    let inspected = validate_package(&package, &coordinate).unwrap();
    assert_eq!(inspected.nuspec, bytes);
    assert_eq!(package, original);
    assert!(validate_package(&package, &Coordinate::new(&coordinate.name, "2").unwrap()).is_err());
    for namespace in [
        "2010/07", "2011/08", "2011/10", "2012/06", "2013/01", "2013/05",
    ] {
        let xml = String::from_utf8(bytes.clone())
            .unwrap()
            .replace("2013/05", namespace);
        validate_nuspec(xml.as_bytes(), &coordinate).unwrap();
    }
    let no_namespace = String::from_utf8(bytes).unwrap().replace(
        " xmlns=\"http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd\"",
        "",
    );
    validate_nuspec(no_namespace.as_bytes(), &coordinate).unwrap();
}

#[test]
fn unsigned_and_signature_shaped_packages_keep_their_original_bytes_and_hashes() {
    let nuspec = manifest("Dev.Packweir.Fixture", "1", "");
    let unsigned = archive(&[
        ("Dev.Packweir.Fixture.nuspec", &nuspec),
        ("build/fixture.targets", b"<Project />"),
    ]);
    let signed = archive(&[
        ("Dev.Packweir.Fixture.nuspec", &nuspec),
        ("build/fixture.targets", b"<Project />"),
        (
            ".signature.p7s",
            b"opaque signature bytes; no trust asserted",
        ),
    ]);
    for bytes in [&unsigned, &signed] {
        let before = bytes.clone();
        let observed = inspect_package(bytes).unwrap();
        assert_eq!(observed.coordinate, coordinate());
        assert_eq!(observed.nuspec, nuspec);
        assert_eq!(*bytes, before);
    }
    assert_ne!(checksum(&unsigned), checksum(&signed));
    assert_eq!(
        checksum(b"abc"),
        "3a81oZNherrMQXNJriBBMRLm+k6JqX6iCp7u5ktV05ohkpkqJ0/BqDa6PCOj/uu9RU1EI2Q86A4qmslPpUyknw=="
    );
    assert_eq!(checksum(b"abc").len(), 88);
}

#[test]
fn native_dotnet_signed_fixture_is_inspected_without_rewriting_or_signature_trust_claims() {
    // SDK 10.0.403 pack/sign fixture, signed by an ephemeral local test author.
    // Only public package bytes are retained. This test performs no cryptographic
    // signature verification and makes no assertion about certificate trust.
    let bytes = include_bytes!("fixtures/nuget/native-signed.nupkg");
    let observed = inspect_package(bytes).unwrap();
    assert_eq!(
        observed.coordinate,
        Coordinate::new("Packweir.Private.Fixture", "1").unwrap()
    );
    let mut archive = zip::ZipArchive::new(Cursor::new(bytes)).unwrap();
    let mut original_nuspec = Vec::new();
    archive
        .by_name("Packweir.Private.Fixture.nuspec")
        .unwrap()
        .read_to_end(&mut original_nuspec)
        .unwrap();
    assert_eq!(observed.nuspec, original_nuspec);
    let mut signature = Vec::new();
    archive
        .by_name(".signature.p7s")
        .unwrap()
        .read_to_end(&mut signature)
        .unwrap();
    assert!(!signature.is_empty());
    validate_package(bytes, &observed.coordinate).unwrap();
}

#[test]
fn nuspec_rejects_ambiguous_structure_namespaces_entities_and_invalid_characters() {
    let original = String::from_utf8(manifest("Dev.Packweir.Fixture", "1.0.0", "")).unwrap();
    for xml in [
        original.replace("<id>Dev.Packweir.Fixture</id>", "<id>Other</id>"),
        original.replace("<version>1.0.0</version>", "<version>2</version>"),
        original
            .replace("<id>", "<id><nested>")
            .replace("</id>", "</nested></id>"),
        original.replace("<id>", "<Id>").replace("</id>", "</Id>"),
        original.replace(
            "<id>Dev.Packweir.Fixture</id>",
            "<id>Dev.Packweir.Fixture</id><id>Dev.Packweir.Fixture</id>",
        ),
        original.replace(
            "</metadata>",
            "</metadata><metadata><id>Other</id><version>1</version></metadata>",
        ),
        original
            .replace("<metadata>", "<nested><metadata>")
            .replace("</metadata>", "</metadata></nested>"),
        original.replace("2013/05/nuspec.xsd", "foreign/nuspec.xsd"),
        original.replace("<id>", "<id xmlns=\"http://attacker.invalid\">"),
        original
            .replace("<id>", "<x:id xmlns:x=\"http://attacker.invalid\">")
            .replace("</id>", "</x:id>"),
        original.replace(
            "Dev.Packweir.Fixture</id>",
            "Dev.<!--comment-->Packweir.Fixture</id>",
        ),
        original.replace(
            "Dev.Packweir.Fixture</id>",
            "<![CDATA[Dev.Packweir.Fixture]]></id>",
        ),
        original.replace("</id>", "</different>"),
        original.replace("</package>", ""),
        original
            .replace("UTF-8", "UTF-16")
            .replace("utf-8", "UTF-16"),
        format!("{original}{original}"),
        format!("<!DOCTYPE package SYSTEM \"http://attacker.invalid/nuspec.dtd\">{original}"),
        original.replace(
            "<metadata>",
            "<?fetch url='http://attacker.invalid'?><metadata>",
        ),
        original.replace("<description>", "<description><!--invalid--comment-->"),
        original.replace("<description>", "<description attr=\"one\" attr=\"two\">"),
        original.replace("<description>", "<description attr=\"<invalid\">"),
        original.replace("<description>", "<description>]]>"),
        format!("\n{original}"),
        format!("<!--before declaration-->{original}"),
    ] {
        assert!(
            validate_nuspec(xml.as_bytes(), &coordinate()).is_err(),
            "{xml}"
        );
    }
    for reference in [
        "&#0;",
        "&#1;",
        "&#x85;",
        "&#xD800;",
        "&#xFFFE;",
        "&#x110000;",
        "&#999999999999999999999999;",
        "&custom;",
        "&AMP;",
    ] {
        let xml = String::from_utf8(manifest(
            "Dev.Packweir.Fixture",
            "1",
            &format!("<tags>{reference}</tags>"),
        ))
        .unwrap();
        assert!(
            validate_nuspec(xml.as_bytes(), &coordinate()).is_err(),
            "{reference}"
        );
        let xml = String::from_utf8(manifest(
            "Dev.Packweir.Fixture",
            "1",
            &format!("<repository url=\"{reference}\" />"),
        ))
        .unwrap();
        assert!(
            validate_nuspec(xml.as_bytes(), &coordinate()).is_err(),
            "attribute {reference}"
        );
    }
    for character in ['\u{1}', '\u{85}', '\u{FFFE}'] {
        let xml = manifest(
            "Dev.Packweir.Fixture",
            "1",
            &format!("<tags>{character}</tags>"),
        );
        assert!(validate_nuspec(&xml, &coordinate()).is_err());
    }
    let entities = manifest(
        "Dev.&#80;ackweir.Fixture",
        "1",
        "<tags>&amp; &lt; &gt; &quot; &apos; &#x1F600;</tags><description><![CDATA[literal <text>]]></description>",
    );
    validate_nuspec(&entities, &coordinate()).unwrap();
    assert!(validate_nuspec(&vec![b' '; 1024 * 1024 + 1], &coordinate()).is_err());
    assert!(
        validate_nuspec(
            &manifest("Dev.Packweir.Fixture", "1", &"<x/>".repeat(10_001)),
            &coordinate()
        )
        .is_err()
    );
    assert!(
        validate_nuspec(
            &manifest(
                "Dev.Packweir.Fixture",
                "1",
                &format!("{}{}", "<x>".repeat(40), "</x>".repeat(40))
            ),
            &coordinate()
        )
        .is_err()
    );
}

#[test]
fn archive_manifest_is_unique_at_root_and_matches_its_filename() {
    let nuspec = manifest("Dev.Packweir.Fixture", "1", "");
    for entries in [
        vec![("lib/Dev.Packweir.Fixture.nuspec", nuspec.as_slice())],
        vec![("Other.nuspec", nuspec.as_slice())],
        vec![
            ("Dev.Packweir.Fixture.nuspec", nuspec.as_slice()),
            ("Other.nuspec", nuspec.as_slice()),
        ],
        vec![
            ("Dev.Packweir.Fixture.nuspec", nuspec.as_slice()),
            ("Dev.Packweir.Fixture.nuspec", nuspec.as_slice()),
        ],
        vec![
            ("Dev.Packweir.Fixture.nuspec", nuspec.as_slice()),
            ("dev.packweir.fixture.NUSPEC", nuspec.as_slice()),
        ],
        vec![("%44ev.Packweir.Fixture.nuspec", nuspec.as_slice())],
    ] {
        assert!(inspect_package(&archive(&entries)).is_err(), "{entries:?}");
    }
    assert!(inspect_package(b"not a ZIP").is_err());
    assert!(inspect_package(&archive(&[])).is_err());
}

#[test]
fn archive_rejects_traversal_links_duplicate_and_extraction_alias_paths() {
    let nuspec = manifest("Dev.Packweir.Fixture", "1", "");
    for path in [
        "../x",
        "lib/../../x",
        "/root/x",
        "C:/root/x",
        "lib\\x",
        "lib//x",
        "lib/./x",
        "lib/x.",
        "lib/x ",
        "lib/%2e%2e/x",
        "lib/%252e%252e/x",
        "lib/%2fx",
        "lib/%5cx",
        "lib/a\0b",
        "lib/CON.txt",
        "lib/NUL",
        "lib/Lpt9",
        "lib/x:stream",
    ] {
        assert!(
            inspect_package(&archive(&[
                ("Dev.Packweir.Fixture.nuspec", &nuspec),
                (path, b"x")
            ]))
            .is_err(),
            "{path:?}"
        );
    }
    for entries in [
        vec![
            ("lib/a.dll", b"a".as_slice()),
            ("LIB/A.dll", b"b".as_slice()),
        ],
        vec![
            ("lib/a.txt", b"a".as_slice()),
            ("lib/%61.txt", b"b".as_slice()),
        ],
        vec![
            ("lib/dir", b"a".as_slice()),
            ("lib/dir/file", b"b".as_slice()),
        ],
        vec![
            ("lib/dir/file", b"a".as_slice()),
            ("lib/dir", b"b".as_slice()),
        ],
    ] {
        let mut entries = entries;
        entries.push(("Dev.Packweir.Fixture.nuspec", nuspec.as_slice()));
        assert!(inspect_package(&archive(&entries)).is_err());
    }
    let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
    writer
        .start_file(
            "Dev.Packweir.Fixture.nuspec",
            zip::write::SimpleFileOptions::default(),
        )
        .unwrap();
    writer.write_all(&nuspec).unwrap();
    writer
        .add_symlink(
            "lib/link",
            "../../outside",
            zip::write::SimpleFileOptions::default(),
        )
        .unwrap();
    assert!(inspect_package(&writer.finish().unwrap().into_inner()).is_err());
    let safe = archive(&[
        ("Dev.Packweir.Fixture.nuspec", &nuspec),
        ("contentFiles/any/any/hello%20world.txt", b"safe"),
    ]);
    inspect_package(&safe).unwrap();
}

#[test]
fn zip_local_and_central_headers_cannot_hide_or_rename_content() {
    let nuspec = manifest("Dev.Packweir.Fixture", "1", "");
    let entries = [
        ("Dev.Packweir.Fixture.nuspec", nuspec.as_slice()),
        ("evil.exe", b"payload".as_slice()),
    ];
    for visible in [&[0usize][..], &[1usize][..]] {
        let hidden = archive_visible(&entries, visible);
        assert!(
            inspect_package(&hidden).is_err(),
            "unlisted local entry {visible:?}"
        );
        assert!(
            packweir::inventory::inspect(
                "fixture.nupkg",
                &hidden,
                packweir::inventory::Limits::default()
            )
            .is_err(),
            "shared archive inventory must reject unlisted local entry {visible:?}"
        );
    }
    let original = archive(&entries);
    let central: Vec<_> = original
        .windows(4)
        .enumerate()
        .filter_map(|(index, magic)| (magic == b"PK\x01\x02").then_some(index))
        .collect();
    let mut renamed = original.clone();
    renamed[central[1] + 46..central[1] + 54].copy_from_slice(b"safe.txt");
    assert!(inspect_package(&renamed).is_err());
    let mut changed_method = original.clone();
    changed_method[8] = 8;
    assert!(inspect_package(&changed_method).is_err());
    let mut changed_size = original.clone();
    changed_size[22..26].copy_from_slice(&((512u32 * 1024 * 1024) + 1).to_le_bytes());
    changed_size[central[0] + 24..central[0] + 28]
        .copy_from_slice(&((512u32 * 1024 * 1024) + 1).to_le_bytes());
    assert!(
        inspect_package(&changed_size)
            .unwrap_err()
            .to_string()
            .contains("expanded-byte limit")
    );
    let mut corrupt = original;
    corrupt[30 + entries[0].0.len()] ^= 1;
    assert!(inspect_package(&corrupt).is_err());
}

#[test]
fn deflated_packages_and_consistent_streaming_data_descriptors_are_supported() {
    let nuspec = manifest("Dev.Packweir.Fixture", "1", "");
    let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
    writer
        .start_file(
            "Dev.Packweir.Fixture.nuspec",
            zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Deflated),
        )
        .unwrap();
    writer.write_all(&nuspec).unwrap();
    writer
        .start_file(
            "lib/net8.0/fixture.dll",
            zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Deflated),
        )
        .unwrap();
    writer.write_all(&[b'A'; 4096]).unwrap();
    inspect_package(&writer.finish().unwrap().into_inner()).unwrap();
    for wide in [false, true] {
        for signature in [false, true] {
            let (bytes, central) =
                with_last_descriptor(&[("Dev.Packweir.Fixture.nuspec", &nuspec)], wide, signature);
            inspect_package(&bytes).unwrap();
            for relative_offset in [0usize, 4, if wide { 12 } else { 8 }] {
                let mut corrupt = bytes.clone();
                corrupt[central + usize::from(signature) * 4 + relative_offset] ^= 1;
                assert!(
                    inspect_package(&corrupt).is_err(),
                    "descriptor width={wide} signature={signature} field={relative_offset}"
                );
            }
            let magic_crc = four_bytes_with_crc(u32::from_le_bytes(*b"PK\x07\x08"));
            let (ambiguous, _) = with_last_descriptor(
                &[
                    ("Dev.Packweir.Fixture.nuspec", &nuspec),
                    ("content/ambiguous.bin", &magic_crc),
                ],
                wide,
                signature,
            );
            inspect_package(&ambiguous).unwrap();
        }
    }
}

#[test]
fn oversized_entry_count_and_manifest_are_rejected_before_content_inspection() {
    let names: Vec<_> = (0..10_001)
        .map(|index| format!("content/{index}.txt"))
        .collect();
    let entries: Vec<_> = names
        .iter()
        .map(|name| (name.as_str(), b"".as_slice()))
        .collect();
    assert!(
        inspect_package(&archive(&entries))
            .unwrap_err()
            .to_string()
            .contains("entry-count limit")
    );
    let oversized = vec![b' '; 1024 * 1024 + 1];
    assert!(
        inspect_package(&archive(&[("Dev.Packweir.Fixture.nuspec", &oversized)]))
            .unwrap_err()
            .to_string()
            .contains("nuspec exceeds")
    );
}

#[test]
fn service_resources_and_version_lists_expose_only_the_requested_protocol_surface() {
    let flat = "https://gateway.invalid/repo/fixture/flatcontainer/";
    let publish = "https://gateway.invalid/api/releases/id/nuget/package";
    let public = service_index(Some(flat), None);
    assert_eq!(public["version"], "3.0.0");
    assert_eq!(public["resources"].as_array().unwrap().len(), 1);
    assert_eq!(public["resources"][0]["@id"], flat);
    assert_eq!(public["resources"][0]["@type"], "PackageBaseAddress/3.0.0");
    let stage = service_index(None, Some(publish));
    assert_eq!(stage["resources"].as_array().unwrap().len(), 1);
    assert_eq!(stage["resources"][0]["@type"], "PackagePublish/2.0.0");
    assert_eq!(stage["resources"][0]["@id"], publish);
    assert_eq!(
        service_index(Some(flat), Some(publish))["resources"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    let versions = [
        "1.0",
        "1.0.0+metadata",
        "2.0.0",
        "1.0.0-RC.10",
        "1.0.0-rc.2",
        "1.0.0.1",
        "10.0",
        "2.0.0.0",
    ]
    .map(str::to_string);
    assert_eq!(
        versions_json(&versions),
        serde_json::json!({"versions":["1.0.0-rc.2", "1.0.0-rc.10", "1.0.0", "1.0.0.1", "2.0.0", "10.0.0"]})
    );
}

#[test]
fn public_deserialized_coordinates_are_revalidated_at_trust_boundaries() {
    let nuspec = manifest("Dev.Packweir.Fixture", "1", "");
    let bytes = archive(&[("Dev.Packweir.Fixture.nuspec", &nuspec)]);
    for invalid in [
        Coordinate {
            name: "Dev.Packweir.Fixture".into(),
            version: "1.0.0".into(),
        },
        Coordinate {
            name: coordinate().name,
            version: "1".into(),
        },
    ] {
        assert!(validate_package(&bytes, &invalid).is_err());
        assert!(validate_nuspec(&nuspec, &invalid).is_err());
    }
}
