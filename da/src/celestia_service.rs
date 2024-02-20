use std::sync::Arc;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use celestia_rpc::{BlobClient, Client};
use celestia_types::{blob::SubmitOptions, consts::HASH_SIZE, nmt::Namespace, Blob, Commitment};

use crate::service::DAService;

pub struct CelestiaService {
    pub client: Arc<Client>,
    pub namespace: Namespace,
}

#[async_trait]
impl DAService for CelestiaService {
    async fn set_full_tx(&self, tx: &[u8]) -> Result<Vec<u8>> {
        let opts = SubmitOptions::default();
        let blob = Blob::new(self.namespace, tx.to_vec())?;
        let mut hash = blob.commitment.0.to_vec();
        let height = self.client.blob_submit(&[blob], opts).await?;
        hash.extend_from_slice(&height.to_be_bytes());
        Ok(hash)
    }

    async fn get_tx(&self, hash: &[u8]) -> Result<Vec<u8>> {
        if hash.len() < 40 {
            return Err(anyhow!("length error"));
        }
        let mut commitment: [u8; HASH_SIZE] = [0; HASH_SIZE];
        commitment.copy_from_slice(&hash[..HASH_SIZE]);
        let mut bytes: [u8; 8] = [0; 8];
        bytes.copy_from_slice(&hash[32..40]);
        let height = u64::from_be_bytes(bytes);
        let blob = self
            .client
            .blob_get(height, self.namespace, Commitment(commitment))
            .await?;
        blob.validate()?;
        Ok(blob.data)
    }

    fn type_byte(&self) -> u8 {
        0x02
    }
}
