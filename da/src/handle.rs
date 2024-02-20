use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::service::DAServiceManager;

pub struct DAHandle {
    pub service_mgr: Arc<DAServiceManager>,
}

impl DAHandle {
    pub async fn new(service_mgr: Arc<DAServiceManager>) -> Result<Self> {
        Ok(Self { service_mgr })
    }

    pub async fn set_da(&self, value: &str) -> RPCResult<Option<String>> {
        let data = hex::decode(value.strip_prefix("0x").unwrap_or(value))
            .map_err(|e| RPCError::internal_error(format!("{}", e)))?;

        let key = self
            .service_mgr
            .set_tx(&data)
            .await
            .map_err(|e| RPCError::internal_error(format!("{}", e)))?;

        if key.len() > 2 {
            Ok(Some(hex::encode(key)))
        } else {
            Ok(None)
        }
    }

    pub async fn get_da(&self, key: &str) -> RPCResult<Option<String>> {
        let data = hex::decode(key.strip_prefix("0x").unwrap_or(key))
            .map_err(|e| RPCError::internal_error(format!("{}", e)))?;

        let content = self
            .service_mgr
            .get_tx(data)
            .await
            .map_err(|e| RPCError::internal_error(format!("{}", e)))?;
        if content.is_empty() {
            Ok(None)
        } else {
            Ok(Some(hex::encode(content)))
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum DAHandleRequest {
    DAArray((String,)),
    SetDAObject { value: String },
    GetDAObject { key: String },
}

impl DAHandleRequest {
    pub fn into_set_da(self) -> RPCResult<String> {
        match self {
            Self::DAArray(s) => Ok(s.0),
            Self::SetDAObject { value } => Ok(value),
            _ => Err(RPCError::invalid_params()),
        }
    }

    pub fn into_get_da(self) -> RPCResult<String> {
        match self {
            Self::DAArray(s) => Ok(s.0),
            Self::GetDAObject { key } => Ok(key),
            _ => Err(RPCError::invalid_params()),
        }
    }
}

#[async_trait]
impl Handle for DAHandle {
    type Request = DAHandleRequest;
    type Response = String;

    async fn handle(
        &self,
        method: &str,
        req: Option<DAHandleRequest>,
    ) -> std::result::Result<Option<Self::Response>, RPCError> {
        match method {
            "da_setDA" => {
                let a = req.ok_or(RPCError::invalid_params())?.into_set_da()?;

                let r = self.set_da(&a).await?;

                Ok(r)
            }
            "da_getDA" => {
                let a = req.ok_or(RPCError::invalid_params())?.into_get_da()?;

                let r = self.get_da(&a).await?;

                Ok(r)
            }
            _ => Err(RPCError::unknown_method()),
        }
    }
}
