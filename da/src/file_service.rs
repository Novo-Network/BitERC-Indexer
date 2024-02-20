use std::{fs, path::PathBuf};

use anyhow::Result;
use async_trait::async_trait;
use sha3::{Digest, Keccak256};

use crate::service::DAService;

pub struct FileService {
    storage_path: PathBuf,
}
impl FileService {
    pub fn new(storage_path: PathBuf) -> Result<Self> {
        if !storage_path.exists() {
            fs::create_dir_all(&storage_path)?;
        }
        Ok(Self { storage_path })
    }
}

#[async_trait]
impl DAService for FileService {
    async fn set_full_tx(&self, tx: &[u8]) -> Result<Vec<u8>> {
        let hash = Keccak256::digest(tx).to_vec();
        let key = hex::encode(&hash);
        let path = self.storage_path.join(key);
        let value = hex::encode(tx);

        fs::write(path, value)?;

        Ok(hash)
    }

    async fn get_tx(&self, hash: &[u8]) -> Result<Vec<u8>> {
        let key = hex::encode(hash);
        let path = self.storage_path.join(key);

        let content = if path.exists() {
            let file_content = fs::read_to_string(path)?;
            hex::decode(file_content)?
        } else {
            vec![]
        };

        Ok(content)
    }

    fn type_byte(&self) -> u8 {
        0x00
    }
}
