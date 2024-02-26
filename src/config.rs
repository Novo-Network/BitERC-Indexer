use std::{fs::File, io::Read};

use ruc::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
pub struct Config {
    pub file: bool,
    pub file_path: Option<String>,
    pub ipfs: bool,
    pub ipfs_url: Option<String>,
    pub celestia: bool,
    pub celestia_url: Option<String>,
    pub celestia_token: Option<String>,
    pub celestia_namespace_id: Option<String>,
    pub greenfield: bool,
    pub greenfield_rpc_addr: Option<String>,
    pub greenfield_chain_id: Option<String>,
    pub greenfield_bucket: Option<String>,
    pub greenfield_password_file: Option<String>,
    pub default: String,

    pub btc_url: String,
    pub username: String,
    pub password: String,
    pub network: String,
    pub fee: u64,

    pub eth_url: String,
    pub chain_id: u32,
}

impl Config {
    pub fn new(path: &str) -> Result<Self> {
        let mut file = File::open(path).c(d!())?;

        let mut str = String::new();
        file.read_to_string(&mut str).c(d!())?;

        toml::from_str(&str).c(d!())
    }
}
