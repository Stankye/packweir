//! Reconcile a remote file graph with the gateway's own bounded inventory.
//! A classifier or extraction service cannot silently omit locally observed bytes.
use crate::{
    model::{Inventory, Outcome, sha256},
    scanner::ScannerOutput,
};
use anyhow::{Result, ensure};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

pub struct LocalInventory {
    subject: String,
    files: BTreeMap<String, u64>,
    source_documents: BTreeSet<String>,
}

impl LocalInventory {
    /// Only engine-observed inventory documents contribute expected file bytes.
    pub fn from_bundle(subject: &str, size: usize, bundle: &Value) -> Result<Self> {
        crate::oci::validate_subject(subject)?;
        let documents = bundle["documents"]
            .as_array()
            .ok_or_else(|| anyhow::anyhow!("local inventory documents missing"))?;
        ensure!(
            documents.len() <= 256,
            "local inventory document limit exceeded"
        );
        let mut files = BTreeMap::new();
        let mut source_documents = BTreeSet::new();
        for document in documents
            .iter()
            .filter(|d| d["kind"] == "inventory" && d["origin"] == "artifact_observed")
        {
            let inventory: Inventory = serde_json::from_value(document["document"].clone())?;
            ensure!(
                inventory.subject == subject
                    && inventory.warnings.is_empty()
                    && !inventory.files.is_empty()
                    && inventory.files.len() <= 10_000,
                "local inventory subject or completeness differs"
            );
            let digest = document["blob_digest"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("local inventory digest missing"))?;
            crate::oci::validate_subject(digest)?;
            // The scanner bundle has already verified CAS raw bytes. Its parsed
            // representation can differ in whitespace; the raw digest stays its ID.
            source_documents.insert(digest.to_owned());
            for file in inventory.files {
                crate::oci::validate_subject(&file.sha256)?;
                ensure!(
                    file.size != 0 || file.sha256 == sha256(b""),
                    "zero-length local file digest differs"
                );
                if let Some(previous) = files.insert(file.sha256, file.size) {
                    ensure!(
                        previous == file.size,
                        "local inventories disagree about file size"
                    );
                }
            }
        }
        ensure!(
            !source_documents.is_empty() && files.get(subject).copied() == Some(size as u64),
            "complete engine inventory for original bytes required"
        );
        Ok(Self {
            subject: subject.into(),
            files,
            source_documents,
        })
    }

    pub fn reconcile(&self, output: &mut ScannerOutput, allow_empty_files: bool) -> Result<()> {
        ensure!(
            output.details["subject"].as_str() == Some(&self.subject),
            "remote inventory subject differs"
        );
        let remote = output.details["files"]
            .as_array()
            .ok_or_else(|| anyhow::anyhow!("normalized remote files missing"))?;
        let remote: BTreeSet<&str> = remote
            .iter()
            .map(|v| {
                v.as_str()
                    .ok_or_else(|| anyhow::anyhow!("invalid normalized remote digest"))
            })
            .collect::<Result<_>>()?;
        let empty = sha256(b"");
        let mut missing = Vec::new();
        let mut known_empty = Vec::new();
        for (digest, size) in &self.files {
            if remote.contains(digest.as_str()) {
                continue;
            }
            if allow_empty_files && *size == 0 && digest == &empty {
                known_empty.push(json!({"sha256":digest,"size":0,"status":"known_empty_content",
                    "basis":"engine_inventory_and_sha256_empty_content","remote_observation":false}));
            } else {
                missing.push(json!({"sha256":digest,"size":size}));
            }
        }
        let complete = missing.is_empty();
        output.details["local_inventory_reconciliation"] = json!({"subject":self.subject,
            "source_documents":self.source_documents,"unique_local_files":self.files.len(),
            "missing_files":missing,"known_empty_content":known_empty,"complete":complete});
        if !complete {
            output.outcome = Outcome::Inconclusive;
            output.details["coverage_complete"] = json!(false);
            let reasons = output.details["coverage_reasons"]
                .as_array_mut()
                .ok_or_else(|| anyhow::anyhow!("normalized coverage reasons missing"))?;
            reasons.push(json!(
                "remote analysis omitted files observed by the gateway inventory"
            ));
        }
        ensure!(
            serde_json::to_vec(&output.details)?.len() <= 4 * 1024 * 1024,
            "reconciled analysis report exceeds limit"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn input(extra: Vec<(&[u8], &str)>) -> (String, Value) {
        let subject = sha256(b"archive root");
        let mut files = vec![json!({"path":"root.zip","sha256":subject,"size":12,"kind":"zip"})];
        files.extend(extra.into_iter().map(|(bytes,path)|json!({"path":path,"sha256":sha256(bytes),"size":bytes.len(),"kind":"text"})));
        let inventory = json!({"subject":subject,"files":files,"warnings":[],"coverage":"bounded engine inspection"});
        let digest = sha256(&serde_json::to_vec(&inventory).unwrap());
        (
            subject,
            json!({"documents":[{"kind":"inventory","origin":"artifact_observed","blob_digest":digest,"document":inventory}]}),
        )
    }
    fn output(subject: &str, files: Vec<String>) -> ScannerOutput {
        ScannerOutput {
            outcome: Outcome::Pass,
            details: json!({"subject":subject,"files":files,"coverage_complete":true,"coverage_reasons":[]}),
            references: vec![],
            valid_until: None,
        }
    }
    #[test]
    fn local_nonempty_child_cannot_disappear_behind_remote_classification() {
        let (subject, bundle) = input(vec![(b"hidden child", "archive/child.bin")]);
        let inventory = LocalInventory::from_bundle(&subject, 12, &bundle).unwrap();
        let mut incomplete = output(&subject, vec![subject.clone()]);
        inventory.reconcile(&mut incomplete, true).unwrap();
        assert_eq!(incomplete.outcome, Outcome::Inconclusive);
        assert_eq!(
            incomplete.details["local_inventory_reconciliation"]["missing_files"][0]["sha256"],
            sha256(b"hidden child")
        );
        let mut complete = output(&subject, vec![subject.clone(), sha256(b"hidden child")]);
        inventory.reconcile(&mut complete, false).unwrap();
        assert_eq!(complete.outcome, Outcome::Pass);
    }
    #[test]
    fn zero_bytes_need_explicit_opt_in_and_never_fabricate_service_execution() {
        let (subject, bundle) = input(vec![(b"", "pkg/__init__.py")]);
        let inventory = LocalInventory::from_bundle(&subject, 12, &bundle).unwrap();
        let mut strict = output(&subject, vec![subject.clone()]);
        inventory.reconcile(&mut strict, false).unwrap();
        assert_eq!(strict.outcome, Outcome::Inconclusive);
        let mut acknowledged = output(&subject, vec![subject.clone()]);
        inventory.reconcile(&mut acknowledged, true).unwrap();
        assert_eq!(acknowledged.outcome, Outcome::Pass);
        let entry =
            &acknowledged.details["local_inventory_reconciliation"]["known_empty_content"][0];
        assert_eq!(entry["remote_observation"], false);
        assert_eq!(entry["status"], "known_empty_content");
    }
    #[test]
    fn duplicate_bytes_are_content_deduplicated_without_trusting_external_inventories() {
        let (subject, mut bundle) = input(vec![(b"same", "one"), (b"same", "two")]);
        let inventory = LocalInventory::from_bundle(&subject, 12, &bundle).unwrap();
        let mut result = output(&subject, vec![subject.clone(), sha256(b"same")]);
        inventory.reconcile(&mut result, false).unwrap();
        assert_eq!(
            result.details["local_inventory_reconciliation"]["unique_local_files"],
            2
        );
        bundle["documents"][0]["origin"] = json!("publisher_declared");
        assert!(LocalInventory::from_bundle(&subject, 12, &bundle).is_err());
    }
    #[test]
    fn malformed_incomplete_or_substituted_local_inventory_cannot_be_reused() {
        let (subject, bundle) = input(vec![(b"child", "child")]);
        for field in ["subject", "warnings", "files"] {
            let mut changed = bundle.clone();
            changed["documents"][0]["document"][field] = match field {
                "subject" => json!("0".repeat(64)),
                "warnings" => json!(["incomplete inspection"]),
                _ => json!([]),
            };
            assert!(LocalInventory::from_bundle(&subject, 12, &changed).is_err());
        }
        assert!(LocalInventory::from_bundle(&subject, 13, &bundle).is_err());
        let mut wrong_zero = bundle;
        wrong_zero["documents"][0]["document"]["files"][1]["size"] = json!(0);
        assert!(LocalInventory::from_bundle(&subject, 12, &wrong_zero).is_err());
    }
}
