use packweir::maven::{
    ChecksumAlgorithm, Coordinate, ReadPath, UploadKind, checksum, classify_upload, metadata_xml,
    parse_read_path, required_primary, validate_checksum, validate_path, validate_pom,
};

fn coordinate() -> Coordinate {
    Coordinate::new("dev.packweir:fixture", "1.0.0").unwrap()
}

fn pom(body: &str) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><project xmlns=\"http://maven.apache.org/POM/4.0.0\"><modelVersion>4.0.0</modelVersion><groupId>dev.packweir</groupId><artifactId>fixture</artifactId><version>1.0.0</version>{body}</project>"
    )
}

#[test]
fn canonical_release_coordinates_create_scoped_declared_identity() {
    let coordinate = coordinate();
    assert_eq!(coordinate.artifact_root(), "dev/packweir/fixture");
    assert_eq!(
        coordinate.artifact_prefix(),
        "dev/packweir/fixture/1.0.0/fixture-1.0.0"
    );
    let package = coordinate.package();
    assert_eq!(package.name, "dev.packweir:fixture");
    assert_eq!(package.purl, "pkg:maven/dev.packweir/fixture@1.0.0");
    assert_eq!(package.basis, "hosted_coordinates_declared");
    assert!(package.is_canonical());
    for version in ["1.0.0", "1.0-RC1", "2026.11", "1.0_final"] {
        assert!(
            Coordinate::new("Org.Example:Some.Artifact", version).is_ok(),
            "{version}"
        );
    }
}

#[test]
fn ambiguous_dynamic_snapshot_and_noncanonical_coordinates_are_rejected() {
    for name in [
        "dev.packweir",
        ":fixture",
        "dev:fixture:extra",
        "dev..packweir:fixture",
        ".dev:fixture",
        "dev.:fixture",
        "dev:../fixture",
        "dev:fixture/evil",
        "dev:fixture%2fother",
        " dev:fixture",
        "dev:fixture ",
        "dev:fixture..other",
    ] {
        assert!(Coordinate::new(name, "1.0.0").is_err(), "{name}");
    }
    for version in [
        "",
        "1.0-SNAPSHOT",
        "1.0-snapshot",
        "[1,2)",
        "1.+",
        "LATEST",
        "release",
        "../1",
        "1%2e0",
        "1.0?x",
        "1.0#x",
        "1.0/extra",
        " 1.0",
        "1.0.",
        "1..0",
        "${revision}",
    ] {
        assert!(
            Coordinate::new("dev.packweir:fixture", version).is_err(),
            "{version}"
        );
    }
}

#[test]
fn artifact_classifiers_and_multicomponent_extensions_bind_to_exact_coordinate() {
    let coordinate = coordinate();
    for (suffix, content_type) in [
        (".jar", "application/java-archive"),
        (".pom", "application/xml"),
        (".module", "application/json"),
        ("-sources.jar", "application/java-archive"),
        ("-linux_x86-64.tar.gz", "application/octet-stream"),
    ] {
        let path = format!("{}{suffix}", coordinate.artifact_prefix());
        assert_eq!(
            classify_upload(&coordinate, &path).unwrap(),
            UploadKind::Artifact {
                filename: format!("fixture-1.0.0{suffix}"),
                content_type: content_type.into()
            }
        );
        assert_eq!(
            parse_read_path(&path).unwrap(),
            ReadPath::Artifact {
                coordinate: coordinate.clone()
            }
        );
    }
    for path in [
        "dev/other/fixture/1.0.0/fixture-1.0.0.jar",
        "dev/packweir/fixture/1.0.1/fixture-1.0.1.jar",
        "dev/packweir/fixture/1.0.0/fixture-1.0.0evil.jar",
        "dev/packweir/fixture/1.0.0/fixture-1.0.0",
        "dev/packweir/fixture/1.0.0/fixture-1.0.0-.jar",
        "dev/packweir/fixture/1.0.0/fixture-1.0.0.jar.sha1.sha256",
    ] {
        assert!(classify_upload(&coordinate, path).is_err(), "{path}");
    }
}

#[test]
fn paths_are_canonical_before_coordinates_or_namespace_routing() {
    for path in [
        "/dev/packweir/fixture/1.0.0/fixture-1.0.0.jar",
        "dev//packweir/fixture/1.0.0/fixture-1.0.0.jar",
        "dev/./packweir/fixture/1.0.0/fixture-1.0.0.jar",
        "dev/../packweir/fixture/1.0.0/fixture-1.0.0.jar",
        "dev\\packweir\\fixture.jar",
        "dev/%70ackweir/fixture/1.0.0/fixture-1.0.0.jar",
        "dev/packweir/fixture/1.0.0/fixture-1.0.0.jar?download=1",
        "dev/packweir/fixture/1.0.0/fixture-1.0.0.jar#x",
        "dev/packweir/fixture/1.0.0/fixture-1.0.0.jar/",
        "dev/packweir/fixture/1.0.0/fixture-1.0.0.jar\0",
    ] {
        assert!(validate_path(path).is_err(), "{path:?}");
        assert!(parse_read_path(path).is_err(), "{path:?}");
    }
    assert!(parse_read_path("dev.packweir/private/hosted-fixture/maven-metadata.xml").is_err());
}

#[test]
fn checksum_and_metadata_paths_cannot_escape_staged_coordinate() {
    let coordinate = coordinate();
    let base = format!("{}.jar", coordinate.artifact_prefix());
    for algorithm in [
        ChecksumAlgorithm::Md5,
        ChecksumAlgorithm::Sha1,
        ChecksumAlgorithm::Sha256,
        ChecksumAlgorithm::Sha512,
    ] {
        let path = format!("{base}.{}", algorithm.suffix());
        assert_eq!(
            classify_upload(&coordinate, &path).unwrap(),
            UploadKind::Checksum {
                base_path: base.clone(),
                algorithm
            }
        );
        assert_eq!(
            parse_read_path(&path).unwrap(),
            ReadPath::Checksum {
                coordinate: coordinate.clone(),
                base_path: base.clone(),
                algorithm
            }
        );
        let metadata = format!(
            "{}/maven-metadata.xml.{}",
            coordinate.artifact_root(),
            algorithm.suffix()
        );
        assert_eq!(
            classify_upload(&coordinate, &metadata).unwrap(),
            UploadKind::IgnoredMetadata
        );
        assert_eq!(
            parse_read_path(&metadata).unwrap(),
            ReadPath::Metadata {
                name: coordinate.name.clone(),
                algorithm: Some(algorithm)
            }
        );
    }
    assert_eq!(
        classify_upload(&coordinate, "dev/packweir/fixture/maven-metadata.xml").unwrap(),
        UploadKind::IgnoredMetadata
    );
    for path in [
        "dev/packweir/maven-metadata.xml",
        "dev/packweir/fixture/1.0.0/maven-metadata.xml",
        "dev/packweir/other/maven-metadata.xml",
        "dev/packweir/fixture/maven-metadata.xml.sha1.sha256",
    ] {
        assert!(classify_upload(&coordinate, path).is_err(), "{path}");
    }
}

#[test]
fn deserialized_coordinate_fields_cannot_disagree() {
    let mut coordinate = coordinate();
    coordinate.group = "other".into();
    assert!(classify_upload(&coordinate, "other/fixture/1.0.0/fixture-1.0.0.jar").is_err());
    assert!(validate_pom(pom("").as_bytes(), &coordinate).is_err());
}

#[test]
fn checksum_text_is_exact_bounded_and_never_an_artifact_hash_claim() {
    for (algorithm, expected) in [
        (ChecksumAlgorithm::Md5, "900150983cd24fb0d6963f7d28e17f72"),
        (
            ChecksumAlgorithm::Sha1,
            "a9993e364706816aba3e25717850c26c9cd0d89d",
        ),
        (
            ChecksumAlgorithm::Sha256,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        ),
        (
            ChecksumAlgorithm::Sha512,
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
        ),
    ] {
        assert_eq!(checksum(b"abc", algorithm), expected);
        assert!(
            validate_checksum(
                format!("{}\n", expected.to_ascii_uppercase()).as_bytes(),
                expected,
                algorithm
            )
            .is_ok()
        );
        assert!(
            validate_checksum(
                checksum(b"other", algorithm).as_bytes(),
                expected,
                algorithm
            )
            .is_err()
        );
        assert!(
            validate_checksum(
                format!("{expected}  file.jar").as_bytes(),
                expected,
                algorithm
            )
            .is_err()
        );
        assert!(validate_checksum(&[b'0'; 257], expected, algorithm).is_err());
    }
}

#[test]
fn pom_coordinates_are_direct_explicit_and_support_normal_gradle_xml() {
    let coordinate = coordinate();
    assert!(validate_pom(pom("").as_bytes(), &coordinate).is_ok());
    assert!(validate_pom(pom("<packaging>jar</packaging><description>Local fixture</description><dependencies><dependency><groupId>other</groupId><artifactId>different</artifactId><version>2</version></dependency></dependencies>").as_bytes(), &coordinate).is_ok());
    assert!(validate_pom(pom("<packaging>pom</packaging>").as_bytes(), &coordinate).is_ok());
    assert!(
        validate_pom(
            pom("<packaging>unsupported-handler</packaging>").as_bytes(),
            &coordinate
        )
        .is_err()
    );
    for (from, to) in [
        (
            "<groupId>dev.packweir</groupId>",
            "<parent><groupId>dev.packweir</groupId></parent>",
        ),
        (
            "<artifactId>fixture</artifactId>",
            "<artifactId>different</artifactId>",
        ),
        ("<version>1.0.0</version>", "<version>${revision}</version>"),
        (
            "<modelVersion>4.0.0</modelVersion>",
            "<modelVersion>3.0.0</modelVersion>",
        ),
    ] {
        assert!(
            validate_pom(pom("").replace(from, to).as_bytes(), &coordinate).is_err(),
            "{to}"
        );
    }
    assert!(validate_pom(pom("<version>1.0.0</version>").as_bytes(), &coordinate).is_err());
}

#[test]
fn partial_publications_require_the_unclassified_packaging_primary() {
    let coordinate = coordinate();
    for (packaging, extension) in [
        ("", Some("jar")),
        ("jar", Some("jar")),
        ("pom", None),
        ("maven-plugin", Some("jar")),
        ("bundle", Some("jar")),
        ("war", Some("war")),
        ("ear", Some("ear")),
        ("aar", Some("aar")),
    ] {
        let xml = pom(&if packaging.is_empty() {
            String::new()
        } else {
            format!("<packaging>{packaging}</packaging>")
        });
        let expected =
            extension.map(|extension| format!("{}.{extension}", coordinate.artifact_prefix()));
        assert_eq!(
            required_primary(xml.as_bytes(), &coordinate).unwrap(),
            expected
        );
    }
    assert!(
        required_primary(
            pom("<packaging>custom-handler</packaging>").as_bytes(),
            &coordinate
        )
        .is_err()
    );
    assert!(
        required_primary(
            pom("")
                .replace("<version>1.0.0</version>", "<version>2.0</version>")
                .as_bytes(),
            &coordinate
        )
        .is_err()
    );
}

#[test]
fn pom_rejects_entities_external_resources_malformed_and_overbounded_xml() {
    let coordinate = coordinate();
    for xml in [
        format!(
            "<!DOCTYPE project SYSTEM \"http://attacker.invalid/pom.dtd\">{}",
            pom("")
        ),
        format!(
            "<!DOCTYPE project [<!ENTITY a SYSTEM \"file:///etc/passwd\">]>{}",
            pom("").replace("fixture</artifactId>", "&a;</artifactId>")
        ),
        pom("<description>&undefined;</description>"),
        pom("").replace(
            "<groupId>dev.packweir</groupId>",
            "<groupId><name>dev.packweir</name></groupId>",
        ),
        pom("").replace(
            "<groupId>dev.packweir</groupId>",
            "<groupId>dev.<!--x-->packweir</groupId>",
        ),
        pom("<![CDATA[something]]>"),
        pom("<?instruction fetch='http://attacker.invalid'?>"),
        pom("").replace("</artifactId>", "</different>"),
        format!("{}{}", pom(""), pom("")),
        pom("").replace("</project>", ""),
        pom("").replace(
            "http://maven.apache.org/POM/4.0.0",
            "http://attacker.invalid/POM",
        ),
        pom("").replace("<groupId>", "<groupId xmlns='http://attacker.invalid'>"),
    ] {
        assert!(validate_pom(xml.as_bytes(), &coordinate).is_err(), "{xml}");
    }
    assert!(validate_pom(&vec![b' '; 1024 * 1024 + 1], &coordinate).is_err());
    assert!(
        validate_pom(
            pom(&format!("{}{}", "<x>".repeat(40), "</x>".repeat(40))).as_bytes(),
            &coordinate
        )
        .is_err()
    );
    assert!(validate_pom(pom(&"<x/>".repeat(10_001)).as_bytes(), &coordinate).is_err());
}

#[test]
fn pom_accepts_only_predefined_entities_and_valid_numeric_characters() {
    let coordinate = coordinate();
    let escaped = pom(
        "<description>Names &amp; licenses &lt;and&gt; &quot;quotes&quot; &apos;apostrophes&apos; &#x1F600;</description><licenses><license><url>https://example.invalid/license?a=1&amp;b=2</url></license></licenses>",
    );
    assert!(validate_pom(escaped.as_bytes(), &coordinate).is_ok());
    let coordinate_refs = pom("")
        .replace("dev.packweir</groupId>", "dev.&#112;ackweir</groupId>")
        .replace("fixture</artifactId>", "f&#x69;xture</artifactId>");
    assert!(validate_pom(coordinate_refs.as_bytes(), &coordinate).is_ok());
    assert!(
        validate_pom(
            coordinate_refs.replace("&#112;", "&#113;").as_bytes(),
            &coordinate
        )
        .is_err()
    );
    for reference in [
        "&#0;",
        "&#1;",
        "&#x1F;",
        "&#x85;",
        "&#xD800;",
        "&#xFFFE;",
        "&#xFFFF;",
        "&#x110000;",
        "&#9999999999999999999999;",
        "&#xZZ;",
        "&unknown;",
        "&AMP;",
    ] {
        assert!(
            validate_pom(
                pom(&format!("<description>{reference}</description>")).as_bytes(),
                &coordinate
            )
            .is_err(),
            "{reference}"
        );
        assert!(
            validate_pom(
                pom(&format!("<description value=\"{reference}\"/>")).as_bytes(),
                &coordinate
            )
            .is_err(),
            "attribute {reference}"
        );
    }
    for character in ['\u{1}', '\u{85}', '\u{FFFE}', '\u{FFFF}'] {
        assert!(
            validate_pom(
                pom(&format!("<description>{character}</description>")).as_bytes(),
                &coordinate
            )
            .is_err()
        );
    }
}

#[test]
fn metadata_is_deterministic_deduplicated_and_xml_escaped() {
    let first = metadata_xml(
        "dev.packweir:fixture",
        &["2.0".into(), "1.0".into(), "2.0".into()],
    );
    assert_eq!(
        first,
        metadata_xml("dev.packweir:fixture", &["1.0".into(), "2.0".into()])
    );
    let text = String::from_utf8(first).unwrap();
    assert_eq!(text.matches("<version>2.0</version>").count(), 1);
    assert!(!text.contains("<latest>") && !text.contains("<release>"));
    let escaped = String::from_utf8(metadata_xml("x<&:y\"", &["1&<>'\"".into()])).unwrap();
    assert!(
        escaped.contains("x&lt;&amp;")
            && escaped.contains("y&quot;")
            && escaped.contains("1&amp;&lt;&gt;&apos;&quot;")
    );
}
