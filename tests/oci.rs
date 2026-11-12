use packweir::oci::{self, EncodedBlob, Transfer, ValidatedBundle};
use serde_json::{Value, json};
use std::{fs, path::Path};

fn subject() -> String {
    "a".repeat(64)
}

fn bundle() -> ValidatedBundle {
    oci::build_bundle(
        &subject(),
        json!({"service":"external"}),
        json!({"claims":true}),
        vec![
            b"{ \"signed\": [1, 2], \"unicode\": \"\xc3\xa9\" }\r\n".to_vec(),
            b"[ {\"second\":true} ]\n".to_vec(),
        ],
    )
    .unwrap()
}

fn manifest_value(transfer: &Transfer) -> Value {
    serde_json::from_slice(&transfer.manifest.decode(oci::MAX_METADATA_BYTES).unwrap()).unwrap()
}

fn replace_manifest(transfer: &mut Transfer, manifest: Value) {
    let bytes = serde_json::to_vec(&manifest).unwrap();
    transfer.manifest_digest = oci::digest(&bytes);
    transfer.manifest = EncodedBlob::encode(&bytes);
}

fn change_manifest(f: impl FnOnce(&mut Value)) -> Transfer {
    let mut transfer = bundle().transfer();
    let mut manifest = manifest_value(&transfer);
    f(&mut manifest);
    replace_manifest(&mut transfer, manifest);
    transfer
}

fn change_envelope(f: impl FnOnce(&mut Value)) -> Transfer {
    let mut transfer = bundle().transfer();
    let mut manifest = manifest_value(&transfer);
    let previous_digest = manifest["layers"][0]["digest"].as_str().unwrap().to_owned();
    let mut envelope: Value = serde_json::from_slice(
        &transfer.blobs[&previous_digest]
            .decode(oci::MAX_METADATA_BYTES)
            .unwrap(),
    )
    .unwrap();
    f(&mut envelope);
    let bytes = serde_json::to_vec(&envelope).unwrap();
    let next_digest = oci::digest(&bytes);
    transfer.blobs.remove(&previous_digest);
    transfer
        .blobs
        .insert(next_digest.clone(), EncodedBlob::encode(&bytes));
    manifest["layers"][0]["digest"] = json!(next_digest);
    manifest["layers"][0]["size"] = json!(bytes.len());
    replace_manifest(&mut transfer, manifest);
    transfer
}

#[test]
fn typed_artifact_roundtrips_raw_json_without_package_manifest_subject() {
    let bundle = bundle();
    let manifest = manifest_value(&bundle.transfer());
    assert_eq!(manifest["artifactType"], oci::ARTIFACT_TYPE);
    assert!(manifest.get("subject").is_none());
    assert_eq!(manifest["config"]["digest"], oci::EMPTY_CONFIG_DIGEST);
    assert_eq!(manifest["layers"][0]["mediaType"], oci::ENVELOPE_MEDIA_TYPE);
    assert_eq!(bundle.envelope().subject, subject());
    let wire = serde_json::to_vec(&bundle.transfer()).unwrap();
    let parsed = oci::parse_transfer(&wire).unwrap();
    assert_eq!(parsed.manifest_digest(), bundle.manifest_digest());
    assert_eq!(parsed.manifest_bytes(), bundle.manifest_bytes());
    assert_eq!(parsed.document_bytes(0), bundle.document_bytes(0));
    assert_eq!(parsed.document_bytes(1), bundle.document_bytes(1));
    assert!(parsed.document_bytes(2).is_none());
    assert!(serde_json::from_slice::<Value>(&wire).unwrap()["manifest"].is_string());
}

#[test]
fn layout_requires_explicit_immutable_digest_and_never_overwrites() {
    let temp = tempfile::tempdir().unwrap();
    let output = temp.path().join("layout");
    let bundle = bundle();
    oci::write_layout(&output, &bundle).unwrap();
    let parsed = oci::read_layout(&output, bundle.manifest_digest()).unwrap();
    assert_eq!(parsed.blobs(), bundle.blobs());
    assert!(oci::read_layout(&output, "packweir").is_err());
    assert!(oci::read_layout(&output, &format!("sha256:{}", "b".repeat(64))).is_err());
    let before = fs::read(output.join("index.json")).unwrap();
    assert!(oci::write_layout(&output, &bundle).is_err());
    assert_eq!(fs::read(output.join("index.json")).unwrap(), before);
    let empty = temp.path().join("empty");
    fs::create_dir(&empty).unwrap();
    assert!(oci::write_layout(&empty, &bundle).is_err());
    assert_eq!(fs::read_dir(&empty).unwrap().count(), 0);
    assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 2);
}

#[test]
fn annotations_and_embedded_empty_config_are_opaque_and_preserved() {
    let transfer = change_manifest(|manifest| {
        manifest["annotations"] =
            json!({"org.opencontainers.image.created":"2026-11-11T00:00:00Z"});
        manifest["layers"][1]["annotations"] =
            json!({"org.opencontainers.image.title":"../../never-follow-this.json"});
        manifest["config"]["data"] = json!("e30=");
    });
    let bytes = transfer.manifest.decode(oci::MAX_METADATA_BYTES).unwrap();
    let bundle = oci::validate_transfer(transfer).unwrap();
    let temp = tempfile::tempdir().unwrap();
    let output = temp.path().join("layout");
    oci::write_layout(&output, &bundle).unwrap();
    assert_eq!(
        oci::read_layout(&output, bundle.manifest_digest())
            .unwrap()
            .manifest_bytes(),
        bytes
    );
}

#[test]
fn tampering_false_sizes_missing_and_extra_blobs_fail_closed() {
    let original = bundle();
    let mut transfer = original.transfer();
    transfer.manifest_digest = format!("sha256:{}", "b".repeat(64));
    assert!(oci::validate_transfer(transfer).is_err());
    let mut transfer = original.transfer();
    let key = original.envelope().documents[0].digest.clone();
    transfer
        .blobs
        .insert(key.clone(), EncodedBlob::encode(b"{\"tampered\":true}"));
    assert!(oci::validate_transfer(transfer).is_err());
    let mut transfer = original.transfer();
    transfer.blobs.remove(&key);
    assert!(oci::validate_transfer(transfer).is_err());
    let mut transfer = original.transfer();
    transfer
        .blobs
        .insert(oci::digest(b"extra"), EncodedBlob::encode(b"extra"));
    assert!(oci::validate_transfer(transfer).is_err());
    assert!(
        oci::validate_transfer(change_manifest(|m| m["layers"][1]["size"] = json!(1))).is_err()
    );
    assert!(oci::validate_transfer(change_manifest(|m| m["config"]["size"] = json!(0))).is_err());
}

#[test]
fn envelope_descriptor_mismatches_and_invalid_subjects_fail_closed() {
    assert!(
        oci::validate_transfer(change_envelope(|e| e["documents"][0]["size"] = json!(1))).is_err()
    );
    assert!(
        oci::validate_transfer(change_envelope(
            |e| e["documents"][0]["digest"] = json!(format!("sha256:{}", "b".repeat(64)))
        ))
        .is_err()
    );
    assert!(
        oci::validate_transfer(change_envelope(
            |e| e["subject"] = json!(format!("sha256:{}", subject()))
        ))
        .is_err()
    );
    assert!(oci::validate_transfer(change_envelope(|e| e["schema_version"] = json!(2))).is_err());
    assert!(
        oci::validate_transfer(change_envelope(|e| e["source"] = json!("not-an-object"))).is_err()
    );
    assert!(oci::validate_transfer(change_envelope(|e| e["snapshot"] = json!([]))).is_err());
    assert!(
        oci::validate_transfer(change_envelope(|e| e["documents"]
            .as_array_mut()
            .unwrap()
            .pop()
            .map(|_| ())
            .unwrap()))
        .is_err()
    );
    for invalid in [
        "a".repeat(63),
        "A".repeat(64),
        format!("../{}", subject()),
        "g".repeat(64),
    ] {
        assert!(oci::validate_subject(&invalid).is_err());
    }
}

#[test]
fn unsupported_media_relationships_external_urls_and_embedded_mismatch_fail() {
    for pointer in [
        "/mediaType",
        "/artifactType",
        "/config/mediaType",
        "/layers/0/mediaType",
        "/layers/1/mediaType",
    ] {
        assert!(
            oci::validate_transfer(change_manifest(
                |m| *m.pointer_mut(pointer).unwrap() = json!("application/unsupported")
            ))
            .is_err(),
            "{pointer}"
        );
    }
    assert!(
        oci::validate_transfer(change_manifest(
            |m| m["layers"][1]["mediaType"] = json!("application/vnd.oci.image.layer.v1.tar+gzip")
        ))
        .is_err()
    );
    assert!(
        oci::validate_transfer(change_manifest(
            |m| m["subject"] = json!({"digest":format!("sha256:{}", subject())})
        ))
        .is_err()
    );
    assert!(oci::validate_transfer(change_manifest(|m| m["subject"] = Value::Null)).is_err());
    assert!(
        oci::validate_transfer(change_manifest(
            |m| m["layers"][1]["urls"] = json!(["https://example.invalid/blob"])
        ))
        .is_err()
    );
    assert!(
        oci::validate_transfer(change_manifest(|m| m["config"]["data"] = json!("W10="))).is_err()
    );
    assert!(
        oci::validate_transfer(change_manifest(
            |m| m["layers"][1]["digest"] = json!("sha512:bad")
        ))
        .is_err()
    );
}

#[test]
fn duplicate_layers_envelope_references_and_json_keys_are_rejected() {
    assert!(
        oci::validate_transfer(change_manifest(|m| m["layers"][2] = m["layers"][1].clone()))
            .is_err()
    );
    assert!(
        oci::validate_transfer(change_envelope(
            |e| e["documents"][1] = e["documents"][0].clone()
        ))
        .is_err()
    );
    assert!(
        oci::build_bundle(
            &subject(),
            json!({}),
            json!({}),
            vec![b"{}".to_vec(), b"{}".to_vec()]
        )
        .is_err()
    );
    assert!(
        oci::build_bundle(
            &subject(),
            json!({}),
            json!({}),
            vec![b"{\"a\":1,\"a\":2}".to_vec()]
        )
        .is_err()
    );
    assert!(
        oci::build_bundle(
            &subject(),
            json!({}),
            json!({}),
            vec![b"{\"nested\":{\"a\":1,\"a\":2}}".to_vec()]
        )
        .is_err()
    );
    let original = bundle().transfer();
    let encoded_manifest = serde_json::to_string(&original.manifest).unwrap();
    let key = original.blobs.keys().next().unwrap();
    let encoded_blob = serde_json::to_string(&original.blobs[key]).unwrap();
    let wire = format!(
        "{{\"manifest_digest\":\"{}\",\"manifest\":{},\"blobs\":{{\"{}\":{},\"{}\":{}}}}}",
        original.manifest_digest, encoded_manifest, key, encoded_blob, key, encoded_blob
    );
    assert!(oci::parse_transfer(wire.as_bytes()).is_err());
    assert!(serde_json::from_str::<Transfer>(&wire).is_err());
    let mut transfer = original;
    let raw = transfer.manifest.decode(oci::MAX_METADATA_BYTES).unwrap();
    let duplicate = format!(
        "{{\"schemaVersion\":2,{}",
        &String::from_utf8(raw).unwrap()[1..]
    );
    transfer.manifest_digest = oci::digest(duplicate.as_bytes());
    transfer.manifest = EncodedBlob::encode(duplicate.as_bytes());
    assert!(oci::validate_transfer(transfer).is_err());
}

#[test]
fn bounded_metadata_documents_counts_and_base64_are_rejected_before_use() {
    assert!(EncodedBlob("AAAA".into()).decode(2).is_err());
    assert!(EncodedBlob("e30".into()).decode(3).is_err());
    assert!(EncodedBlob("e30=\n".into()).decode(3).is_err());
    assert!(
        oci::validate_transfer(change_manifest(
            |m| m["layers"][1]["size"] = json!(oci::MAX_DOCUMENT_BYTES + 1)
        ))
        .is_err()
    );
    assert!(
        oci::validate_transfer(change_manifest(
            |m| m["layers"][0]["size"] = json!(oci::MAX_METADATA_BYTES + 1)
        ))
        .is_err()
    );
    assert!(
        oci::build_bundle(
            &subject(),
            json!({"claim":"x".repeat(oci::MAX_METADATA_BYTES)}),
            json!({}),
            vec![]
        )
        .is_err()
    );
    assert!(
        oci::build_bundle(
            &subject(),
            json!({}),
            json!({}),
            vec![vec![b' '; oci::MAX_DOCUMENT_BYTES + 1]]
        )
        .is_err()
    );
    assert!(
        oci::build_bundle(
            &subject(),
            json!({}),
            json!({}),
            vec![vec![]; oci::MAX_DOCUMENTS + 1]
        )
        .is_err()
    );
    assert!(oci::build_bundle(&subject(), json!({}), json!({}), vec![b"true".to_vec()]).is_err());
}

#[test]
fn content_addressed_empty_document_is_allowed_without_duplicate_storage() {
    let bundle = oci::build_bundle(&subject(), json!({}), json!({}), vec![b"{}".to_vec()]).unwrap();
    assert_eq!(bundle.blobs().len(), 2);
    assert_eq!(bundle.document_bytes(0), Some(b"{}".as_slice()));
}

fn layout() -> (tempfile::TempDir, std::path::PathBuf, ValidatedBundle) {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("layout");
    let bundle = bundle();
    oci::write_layout(&path, &bundle).unwrap();
    (temp, path, bundle)
}

fn blob_path(root: &Path, digest: &str) -> std::path::PathBuf {
    root.join("blobs/sha256").join(&digest[7..])
}

#[test]
fn layout_missing_corrupted_and_nonregular_content_is_rejected() {
    let (_temp, path, bundle) = layout();
    let document = blob_path(&path, &bundle.envelope().documents[0].digest);
    fs::write(&document, b"{\"bad\":true}").unwrap();
    assert!(oci::read_layout(&path, bundle.manifest_digest()).is_err());
    fs::remove_file(&document).unwrap();
    assert!(oci::read_layout(&path, bundle.manifest_digest()).is_err());
    fs::create_dir(&document).unwrap();
    assert!(oci::read_layout(&path, bundle.manifest_digest()).is_err());
}

#[test]
fn index_sizes_duplicates_nested_indexes_and_versions_are_rejected() {
    for mutate in [
        (|i: &mut Value| i["manifests"][0]["size"] = json!(0)) as fn(&mut Value),
        |i| {
            let descriptor = i["manifests"][0].clone();
            i["manifests"].as_array_mut().unwrap().push(descriptor);
        },
        |i| i["manifests"][0]["mediaType"] = json!(oci::OCI_INDEX_MEDIA_TYPE),
        |i| i["schemaVersion"] = json!(1),
        |i| i["manifests"][0]["urls"] = json!(["https://example.invalid/root"]),
    ] {
        let (_temp, path, bundle) = layout();
        let mut index: Value =
            serde_json::from_slice(&fs::read(path.join("index.json")).unwrap()).unwrap();
        mutate(&mut index);
        fs::write(path.join("index.json"), serde_json::to_vec(&index).unwrap()).unwrap();
        assert!(oci::read_layout(&path, bundle.manifest_digest()).is_err());
    }
    let (_temp, path, bundle) = layout();
    fs::write(
        path.join("oci-layout"),
        b"{\"imageLayoutVersion\":\"1.1.1\"}",
    )
    .unwrap();
    assert!(oci::read_layout(&path, bundle.manifest_digest()).is_err());
}

#[test]
fn tags_are_not_a_digest_and_title_annotations_are_never_filesystem_paths() {
    let (_temp, path, bundle) = layout();
    let mut index: Value =
        serde_json::from_slice(&fs::read(path.join("index.json")).unwrap()).unwrap();
    index["manifests"][0]["annotations"]["org.opencontainers.image.ref.name"] =
        json!("../../outside");
    fs::write(path.join("index.json"), serde_json::to_vec(&index).unwrap()).unwrap();
    assert_eq!(
        oci::read_layout(&path, bundle.manifest_digest())
            .unwrap()
            .manifest_digest(),
        bundle.manifest_digest()
    );
    assert!(oci::read_layout(&path, "../../outside").is_err());
    assert!(oci::read_layout(&path.join("../layout"), bundle.manifest_digest()).is_err());
}

#[cfg(any(unix, windows))]
#[test]
fn symlinked_files_roots_and_ancestors_are_rejected() {
    #[cfg(unix)]
    fn link_dir(target: &Path, link: &Path) -> std::io::Result<()> {
        std::os::unix::fs::symlink(target, link)
    }
    #[cfg(windows)]
    fn link_dir(target: &Path, link: &Path) -> std::io::Result<()> {
        std::os::windows::fs::symlink_dir(target, link)
    }
    #[cfg(unix)]
    fn link_file(target: &Path, link: &Path) -> std::io::Result<()> {
        std::os::unix::fs::symlink(target, link)
    }
    #[cfg(windows)]
    fn link_file(target: &Path, link: &Path) -> std::io::Result<()> {
        std::os::windows::fs::symlink_file(target, link)
    }
    let (temp, path, bundle) = layout();
    let root_link = temp.path().join("linked");
    match link_dir(&path, &root_link) {
        Ok(()) => {}
        #[cfg(windows)]
        Err(e) if e.raw_os_error() == Some(1314) => {
            eprintln!("Windows symlink privilege unavailable; Linux CI exercises this case");
            return;
        }
        Err(e) => panic!("creating symlink: {e}"),
    }
    assert!(oci::read_layout(&root_link, bundle.manifest_digest()).is_err());
    assert!(oci::write_layout(&root_link.join("child"), &bundle).is_err());
    let content_path = blob_path(&path, &bundle.envelope().documents[0].digest);
    let external = temp.path().join("external-document");
    fs::rename(&content_path, &external).unwrap();
    link_file(&external, &content_path).unwrap();
    assert!(oci::read_layout(&path, bundle.manifest_digest()).is_err());
}
