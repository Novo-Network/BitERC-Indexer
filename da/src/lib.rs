#![deny(warnings, unused_crate_dependencies)]

mod service;
pub use service::*;

mod file_service;
pub use file_service::*;

mod ipfs_service;
pub use ipfs_service::*;

mod celestia_service;
pub use celestia_service::*;

mod greenfield_servic;
pub use greenfield_servic::*;

use std::{path::PathBuf, sync::Arc};

use anyhow::{anyhow, Result};
use celestia_rpc::Client;
use celestia_types::nmt::Namespace;
use ipfs_api_backend_hyper::{IpfsClient, TryFromUri};

pub async fn create_da_mgr(
    file: bool,
    file_path: Option<&str>,
    ipfs: bool,
    ipfs_url: Option<&str>,
    celestia: bool,
    celestia_url: Option<&str>,
    celestia_token: Option<&str>,
    celestia_namespace_id: Option<&str>,
    greenfield: bool,
    greenfield_rpc_addr: Option<&str>,
    greenfield_chain_id: Option<&str>,
    greenfield_bucket: Option<&str>,
    greenfield_password_file: Option<&str>,
    default: &str,
) -> Result<DAServiceManager> {
    let flag = match default {
        "file" => {
            if file {
                0
            } else {
                return Err(anyhow!("file flag not enabled"));
            }
        }
        "ipfs" => {
            if ipfs {
                1
            } else {
                return Err(anyhow!("ipfs flag not enabled"));
            }
        }
        "celestia" => {
            if celestia {
                2
            } else {
                return Err(anyhow!("celestia flag not enabled"));
            }
        }
        "greenfield" => {
            if greenfield {
                3
            } else {
                return Err(anyhow!("celestia flag not enabled"));
            }
        }
        &_ => return Err(anyhow!("default can only be file ipfs celestia")),
    };

    let mut da_mgr = DAServiceManager::new();
    if file {
        let file_path = file_path.ok_or(anyhow!("file path can not be empty"))?;
        let file_service = FileService::new(PathBuf::from(&file_path))?;
        if 0 == flag {
            da_mgr.add_default_service(file_service);
        } else {
            da_mgr.add_service(file_service);
        }
    }

    if ipfs {
        let ipfs_url = ipfs_url.ok_or(anyhow!("ipfs url can not be empty"))?;
        let ipfs_service = IpfsService {
            ipfs: Arc::new(IpfsClient::from_str(&ipfs_url)?),
        };
        if 1 == flag {
            da_mgr.add_default_service(ipfs_service);
        } else {
            da_mgr.add_service(ipfs_service);
        }
    }

    if celestia {
        let celestia_url = celestia_url.ok_or(anyhow!("celestia url can not be empty"))?;
        let namespace_id = celestia_namespace_id
            .ok_or(anyhow!("namespace id can not be empty"))
            .and_then(|v| hex::decode(v).map_err(|e| anyhow!("{}", e)))
            .and_then(|v| {
                v.try_into()
                    .map_err(|_e| anyhow!("namespace try into error"))
            })?;
        let celestia_service = CelestiaService {
            client: Arc::new(Client::new(&celestia_url, celestia_token.as_deref()).await?),
            namespace: Namespace::const_v0(namespace_id),
        };
        if 2 == flag {
            da_mgr.add_default_service(celestia_service);
        } else {
            da_mgr.add_service(celestia_service);
        }
    }

    if greenfield {
        let rpc_addr =
            greenfield_rpc_addr.ok_or(anyhow!("greenfield rpc addr can not be empty"))?;
        let chain_id =
            greenfield_chain_id.ok_or(anyhow!("greenfield chain id can not be empty"))?;
        let bucket = greenfield_bucket.ok_or(anyhow!("greenfield bucket can not be empty"))?;
        let password_file =
            greenfield_password_file.ok_or(anyhow!("greenfield bucket can not be empty"))?;

        let greenfield_service = GreenfieldService::new(
            rpc_addr.into(),
            chain_id.into(),
            bucket.into(),
            password_file.into(),
        );
        if 3 == flag {
            da_mgr.add_default_service(greenfield_service);
        } else {
            da_mgr.add_service(greenfield_service);
        }
    }
    Ok(da_mgr)
}
