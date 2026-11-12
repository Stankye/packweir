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
    /// Limit bytes fetched before allocating an administrative document response.
    /// A bounded range also protects against a blob growing after a metadata check.
    pub async fn read_bounded(&self, digest: &str, max_bytes: usize) -> Result<Vec<u8>> {
        let key = Self::key(digest)?;
        let size = self.operator.stat(&key).await?.content_length();
        ensure!(
            size <= u64::try_from(max_bytes)?,
            "stored blob exceeds size limit"
        );
        // OpenDAL's complete reader requires exact ranges; asking past EOF can
        // fail even for a valid short file. Never issue an unbounded read after
        // stat: a concurrent replacement could otherwise exceed the limit.
        let bytes = if size == 0 {
            Vec::new()
        } else {
            self.operator.read_with(&key).range(0..size).await?.to_vec()
        };
        ensure!(bytes.len() <= max_bytes, "stored blob exceeds size limit");
        ensure!(bytes.len() as u64 == size, "stored blob size changed");
        ensure!(sha256(&bytes) == digest, "stored blob integrity failure");
        ensure!(
            self.operator.stat(&key).await?.content_length() == size,
            "stored blob size changed"
        );
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
