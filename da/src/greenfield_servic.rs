use std::{fs, process::Command};

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use sha3::{Digest, Keccak256};

use crate::service::DAService;

pub struct GreenfieldService {
    rpc_addr: String,
    chain_id: String,
    bucket: String,
    password_file: String,
}
impl GreenfieldService {
    pub fn new(rpc_addr: String, chain_id: String, bucket: String, password_file: String) -> Self {
        Self {
            rpc_addr,
            chain_id,
            bucket,
            password_file,
        }
    }
}

#[async_trait]
impl DAService for GreenfieldService {
    async fn set_full_tx(&self, tx: &[u8]) -> Result<Vec<u8>> {
        let hash = Keccak256::digest(tx).to_vec();
        if let Ok(content) = self.get_tx(&hash).await {
            if !content.is_empty() {
                return Ok(hash);
            }
        }
        let key = hex::encode(&hash);
        let value = hex::encode(tx);
        let file_name = format!("/tmp/{}", key);
        fs::write(&file_name, value)?;

        //gnfd-cmd --rpcAddr "https://gnfd-testnet-fullnode-tendermint-us.bnbchain.org:443" --chainId "greenfield_5600-1" object put   --visibility private ./test1.txt  gnfd://bucket123123123/test1.txt
        let mut cmd = Command::new("gnfd-cmd");
        cmd.arg("--rpcAddr")
            .arg(&self.rpc_addr)
            .arg("--chainId")
            .arg(&self.chain_id)
            .arg("--passwordfile")
            .arg(&self.password_file)
            .arg("object")
            .arg("put")
            .arg("--contentType")
            .arg("'text/plain'")
            .arg("--visibility")
            .arg("private")
            .arg(&file_name)
            .arg(format!("gnfd://{}/{}", self.bucket, key));
        let output = cmd.output()?;
        let show = String::from_utf8(output.stdout)?;
        if !output.status.success() {
            return Err(anyhow!(show));
        }
        println!("{}", show);
        let _ = fs::remove_file(file_name);
        Ok(hash)
    }

    async fn get_tx(&self, hash: &[u8]) -> Result<Vec<u8>> {
        let key = hex::encode(&hash);
        println!("get tx");
        let file_name = format!("/tmp/{}", key);

        //gnfd-cmd --rpcAddr "https://gnfd-testnet-fullnode-tendermint-us.bnbchain.org:443" --chainId "greenfield_5600-1" object get gnfd://bucket123123123/test1.txt ./test-copy.txt
        let mut cmd = Command::new("gnfd-cmd");
        cmd.arg("--rpcAddr")
            .arg(&self.rpc_addr)
            .arg("--chainId")
            .arg(&self.chain_id)
            .arg("--passwordfile")
            .arg(&self.password_file)
            .arg("object")
            .arg("get")
            .arg(format!("gnfd://{}/{}", self.bucket, key))
            .arg(file_name.clone());
        let output = cmd.output()?;
        let show = String::from_utf8(output.stdout)?;
        println!("{}", show);
        if !output.status.success() {
            return Err(anyhow!(show));
        }

        let file_content = fs::read_to_string(&file_name)?;
        let content = hex::decode(file_content)?;

        let _ = fs::remove_file(file_name);
        Ok(content)
    }

    fn type_byte(&self) -> u8 {
        0x03
    }
}
