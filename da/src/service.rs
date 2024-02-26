use std::collections::BTreeMap;

use anyhow::{anyhow, Result};
use async_trait::async_trait;

#[async_trait]
pub trait DAService: Sync + Send {
    async fn set_full_tx(&self, tx: &[u8]) -> Result<Vec<u8>>;

    async fn get_tx(&self, hash: &[u8]) -> Result<Vec<u8>>;

    fn type_byte(&self) -> u8;

    async fn set_tx(&self, tx: &[u8]) -> Result<Vec<u8>> {
        let hash = self.set_full_tx(tx).await?;

        let mut result = vec![self.type_byte()];

        result.extend_from_slice(&hash);

        Ok(result)
    }
}

pub struct DAServiceManager {
    service: BTreeMap<u8, Box<dyn DAService>>,
    default: u8,
}

impl DAServiceManager {
    pub fn new() -> Self {
        Self {
            service: Default::default(),
            default: 0,
        }
    }
    pub fn types(&self) -> Vec<u8> {
        self.service.keys().cloned().collect::<Vec<u8>>()
    }

    pub fn default_type(&self) -> u8 {
        self.default
    }

    pub fn add_service(&mut self, service: impl DAService + 'static) {
        self.service.insert(service.type_byte(), Box::new(service));
    }

    pub fn add_default_service(&mut self, service: impl DAService + 'static) {
        self.default = service.type_byte();
        self.add_service(service);
    }

    pub async fn get_tx(&self, hash: impl Into<Vec<u8>>) -> Result<Vec<u8>> {
        let hash = hash.into();

        let type_byte = hash
            .first()
            .ok_or(anyhow!("Data length wrong, no type byte"))?;

        let service = self
            .service
            .get(type_byte)
            .ok_or(anyhow!("No target da service support"))?;

        let tx = service.get_tx(&hash[1..]).await?;

        Ok(tx)
    }

    pub async fn set_tx(&self, tx: &[u8]) -> Result<Vec<u8>> {
        let service = self
            .service
            .get(&self.default)
            .ok_or(anyhow!("wrong service"))?;

        let hash = service.set_tx(tx).await?;
        Ok(hash)
    }
}
