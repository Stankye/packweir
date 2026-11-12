//! Explicit qualification against the pinned upstream ORAS executable and product CLI.
use packweir::{model::sha256, oci};
use serde_json::{Value, json};
use std::{path::Path, process::Command};

fn invoke(program: &Path, directory: &Path, args: &[&str]) -> Vec<u8> {
    let result = Command::new(program)
        .current_dir(directory)
        .args(args)
        .env_remove("DATABASE_URL")
        .env_remove("PACKWEIR_ADMIN_TOKEN")
        .output()
        .expect("run real qualification executable");
    assert!(
        result.status.success(),
        "{program:?} {args:?} failed: {}{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
    result.stdout
}

fn validate(cli: &Path, directory: &Path, layout: &str, digest: &str) -> Value {
    let report: Value = serde_json::from_slice(&invoke(
        cli,
        directory,
        &[
            "--config",
            "deliberately-absent.toml",
            "evidence",
            "validate",
            "--layout",
            layout,
            "--manifest",
            digest,
        ],
    ))
    .expect("CLI validation prints a JSON report without configuration or database");
    assert_eq!(report["manifest_digest"], digest);
    assert_eq!(report["verified"], false);
    assert_eq!(report["trust_status"], "unverified");
    assert_eq!(report["approval_effect"], "none");
    report
}

#[test]
#[ignore = "requires the real pinned ORAS executable; tests/oras/run.py provisions and isolates it"]
fn real_oras_roundtrip_and_cli_qualification() {
    let oras = std::env::var_os("PACKWEIR_TEST_ORAS").expect("PACKWEIR_TEST_ORAS is required");
    let oras = Path::new(&oras);
    let cli_override = std::env::var_os("PACKWEIR_TEST_CLI");
    let cli = cli_override
        .as_deref()
        .map(Path::new)
        .unwrap_or_else(|| Path::new(env!("CARGO_BIN_EXE_packweir")));
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    let version = String::from_utf8(invoke(oras, root, &["version"])).unwrap();
    assert!(
        version
            .lines()
            .any(|line| line.contains("Version:") && line.contains("1.3.6"))
    );
    assert!(version.contains("9b1fc815f6b7fba743f08b9b5c5846639cc11d3c"));

    // Whitespace, Unicode, and noncanonical key order are deliberately significant.
    let documents = vec![
        b"{ \"z\": 1, \"a\": \"raw document bytes\" }\n".to_vec(),
        "[ {\"label\":\"caf\u{e9}\", \"verdict\": \"pass\"} ]\n"
            .as_bytes()
            .to_vec(),
    ];
    let subject = sha256(b"fixed harmless package fixture, not an OCI manifest");
    let bundle = oci::build_bundle(
        &subject,
        json!({"instance":"qualification","repository":"fixture"}),
        json!({"configuration":"fixture","context_revision":0}),
        documents.clone(),
    )
    .unwrap();
    oci::write_layout(&root.join("export"), &bundle).unwrap();
    let digest = bundle.manifest_digest();
    let export_reference = format!("export@{digest}");
    let fetched = invoke(
        oras,
        root,
        &["manifest", "fetch", "--oci-layout", &export_reference],
    );
    assert_eq!(
        fetched,
        bundle.manifest_bytes(),
        "ORAS fetched the exact exported root manifest"
    );
    let manifest: Value = serde_json::from_slice(&fetched).unwrap();
    assert_eq!(manifest["artifactType"], oci::ARTIFACT_TYPE);
    assert!(
        manifest.get("subject").is_none(),
        "raw package digests are envelope subjects"
    );
    for (index, descriptor) in manifest["layers"].as_array().unwrap().iter().enumerate() {
        let blob_digest = descriptor["digest"].as_str().unwrap();
        let reference = format!("export@{blob_digest}");
        let filename = format!("fetched-{index}.json");
        invoke(
            oras,
            root,
            &[
                "blob",
                "fetch",
                "--oci-layout",
                &reference,
                "--output",
                &filename,
            ],
        );
        assert_eq!(
            std::fs::read(root.join(filename)).unwrap(),
            bundle.blobs()[blob_digest]
        );
    }
    invoke(
        oras,
        root,
        &[
            "cp",
            "--from-oci-layout",
            "--to-oci-layout",
            &export_reference,
            "copied:roundtrip",
        ],
    );
    let roundtrip = oci::read_layout(&root.join("copied"), digest).unwrap();
    assert_eq!(roundtrip.manifest_digest(), digest);
    assert_eq!(roundtrip.manifest_bytes(), bundle.manifest_bytes());
    for (index, expected) in documents.iter().enumerate() {
        assert_eq!(roundtrip.document_bytes(index).unwrap(), expected);
    }
    let export_cli = validate(cli, root, "export", digest);
    let copied_cli = validate(cli, root, "copied", digest);

    // ORAS, rather than the Packweir layout writer, authors this root manifest.
    std::fs::write(
        root.join("envelope.json"),
        serde_json::to_vec(bundle.envelope()).unwrap(),
    )
    .unwrap();
    for (index, bytes) in documents.iter().enumerate() {
        std::fs::write(root.join(format!("document-{index}.json")), bytes).unwrap();
    }
    let envelope_arg = format!("envelope.json:{}", oci::ENVELOPE_MEDIA_TYPE);
    let document_args: Vec<_> = (0..documents.len())
        .map(|index| format!("document-{index}.json:{}", oci::DOCUMENT_MEDIA_TYPE))
        .collect();
    let mut push_args = vec![
        "push",
        "--oci-layout",
        "independent:fixture",
        "--artifact-type",
        oci::ARTIFACT_TYPE,
        "--annotation",
        "org.opencontainers.image.created=2026-01-01T00:00:00Z",
        &envelope_arg,
    ];
    push_args.extend(document_args.iter().map(String::as_str));
    invoke(oras, root, &push_args);
    let independent_digest = String::from_utf8(invoke(
        oras,
        root,
        &["resolve", "--oci-layout", "independent:fixture"],
    ))
    .unwrap()
    .trim()
    .to_owned();
    let independent = oci::read_layout(&root.join("independent"), &independent_digest).unwrap();
    assert_eq!(independent.envelope().subject, subject);
    for (index, expected) in documents.iter().enumerate() {
        assert_eq!(independent.document_bytes(index).unwrap(), expected);
    }
    let independent_cli = validate(cli, root, "independent", &independent_digest);

    // A changed layer must be rejected by both the reader and the product command.
    let document_digest = &independent.envelope().documents[0].digest;
    let blob = root
        .join("independent/blobs/sha256")
        .join(document_digest.strip_prefix("sha256:").unwrap());
    // ORAS stores immutable blob files read-only; replace this disposable fixture.
    std::fs::remove_file(&blob).unwrap();
    std::fs::write(blob, b"{\"forged\":true}").unwrap();
    assert!(oci::read_layout(&root.join("independent"), &independent_digest).is_err());
    let rejected = Command::new(cli)
        .current_dir(root)
        .env_remove("DATABASE_URL")
        .args([
            "--config",
            "deliberately-absent.toml",
            "evidence",
            "validate",
            "--layout",
            "independent",
            "--manifest",
            &independent_digest,
        ])
        .output()
        .unwrap();
    assert!(
        !rejected.status.success(),
        "CLI must reject tampered document bytes"
    );
    let proof = json!({
        "qualified":true,"oras_version":version,"subject":subject,
        "export_manifest_digest":digest,"copied_manifest_digest":roundtrip.manifest_digest(),
        "independent_manifest_digest":independent_digest,
        "document_sha256":documents.iter().map(|bytes|sha256(bytes)).collect::<Vec<_>>(),
        "cases":["oras_fetch_exact_manifest","oras_fetch_exact_blobs","oras_copy_preserves_root_digest",
                 "packweir_reads_copied_exact_documents","oras_push_independent_bundle",
                 "cli_validate_configless_export","cli_validate_configless_copy",
                 "cli_validate_configless_oras_push","cli_rejects_tampered_document"],
        "cli_reports":{"export":export_cli,"copied":copied_cli,"independent":independent_cli}
    });
    println!("PACKWEIR_ORAS_PROOF={proof}");
}
