use crate::{config::StorageConfig, model::sha256};
use anyhow::{Result, ensure};
use opendal::{Operator, services};

#[derive(Clone)]
pub struct BlobStore {
    operator: Operator,
}
impl BlobStore {
    pub async fn check(&self) -> Result<()> {
        self.operator.check().await?;
        Ok(())
    }
    pub fn new(config: &StorageConfig) -> Result<Self> {
        let operator = match config {
            StorageConfig::Fs { root } => {
                std::fs::create_dir_all(root)?;
                let absolute = std::fs::canonicalize(root)?;
                Operator::new(services::Fs::default().root(&absolute.to_string_lossy()))?.finish()
            }
            StorageConfig::S3 {
                bucket,
                region,
                endpoint,
                root,
            } => {
                let mut builder = services::S3::default()
                    .bucket(bucket)
                    .region(region)
                    .root(root);
                if let Some(endpoint) = endpoint {
                    builder = builder.endpoint(endpoint);
                }
                Operator::new(builder)?.finish()
            }
        };
        Ok(Self { operator })
    }
    pub async fn put(&self, bytes: Vec<u8>) -> Result<String> {
        let digest = sha256(&bytes);
        self.operator.write(&Self::key(&digest)?, bytes).await?;
        Ok(digest)
    }
    pub async fn read(&self, digest: &str) -> Result<Vec<u8>> {
        let bytes = self.operator.read(&Self::key(digest)?).await?.to_vec();
        ensure!(sha256(&bytes) == digest, "stored blob integrity failure");
        Ok(bytes)
    }
    pub async fn delete(&self, digest: &str) -> Result<()> {
        self.operator.delete(&Self::key(digest)?).await?;
        Ok(())
    }
    fn key(digest: &str) -> Result<String> {
        ensure!(
            digest.len() == 64
                && digest
                    .bytes()
                    .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
            "invalid SHA-256 digest"
        );
        Ok(format!("blobs/sha256/{}/{}", &digest[..2], digest))
    }
}
