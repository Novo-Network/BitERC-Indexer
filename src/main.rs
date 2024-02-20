#![deny(warnings)]

mod evm_runtime;
mod fetcher_service;

use std::{path::PathBuf, sync::Arc, time::Duration};

use clap::Parser;
use da::{DAServiceManager, FileService};
use evm_runtime::EvmRuntime;
use fetcher_service::FetcherService;
use rt_evm_model::{
    traits::BlockStorage,
    types::{H160, U256},
};
use ruc::*;
use tokio::time::sleep;

#[derive(Debug, Parser)]
pub struct Args {
    #[clap(long)]
    btc_url: String,
    #[clap(long)]
    username: String,
    #[clap(long)]
    password: String,
    #[clap(long)]
    chain_id: u32,
    #[clap(long)]
    da_file_path: String,
    #[clap(long)]
    datadir: String,
    #[clap(long)]
    listen: String,
    #[clap(long)]
    http_port: u16,
    #[clap(long)]
    ws_port: u16,
}

impl Args {
    pub async fn execute(self) -> Result<()> {
        vsdb::vsdb_set_base_dir(&self.datadir).c(d!())?;
        let mut da_mgr = DAServiceManager::new();
        da_mgr.add_default_service(
            FileService::new(PathBuf::from(&self.da_file_path)).map_err(|e| eg!(e))?,
        );

        let http_endpoint = if 0 == self.http_port {
            None
        } else {
            Some(format!("{}:{}", self.listen, self.http_port))
        };

        let ws_endpoint = if 0 == self.ws_port {
            None
        } else {
            Some(format!("{}:{}", self.listen, self.ws_port))
        };
        let evm_rt = Arc::new(EvmRuntime::restore_or_create(self.chain_id as u64, &[])?);
        let start = evm_rt
            .copy_storage_handler()
            .get_latest_block_header()?
            .number;

        evm_rt
            .spawn_jsonrpc_server(
                "novolite-0.1.0",
                http_endpoint.as_deref(),
                ws_endpoint.as_deref(),
            )
            .await
            .c(d!())?;
        let mut fetcher = FetcherService::new(
            &self.btc_url,
            &self.username,
            &self.password,
            start + 1,
            U256::from(self.chain_id),
            Arc::new(da_mgr),
        )?;
        loop {
            if let Ok(Some(block)) = fetcher.get_block().await {
                let mut txs = vec![];

                for btc_tx in block.txdata.iter() {
                    if let Ok(evm_txs) = fetcher.decode_transaction(btc_tx).await {
                        if !evm_txs.is_empty() {
                            for i in evm_txs.iter() {
                                if let Ok(_) = evm_rt.check_signed_tx(i) {
                                    txs.push(i.clone());
                                }
                            }
                        }
                    }
                }
                let hdr = evm_rt
                    .generate_blockproducer(H160::default(), block.header.time as u64)
                    .c(d!())?;
                hdr.produce_block(txs).c(d!())?;
            } else {
                sleep(Duration::from_secs(1)).await;
            }
        }
    }
}

#[tokio::main]
async fn main() {
    env_logger::init();

    let args = Args::parse();

    args.execute().await.unwrap()
}
