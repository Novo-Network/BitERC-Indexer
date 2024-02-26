use std::sync::Arc;

use bitcoin::{
    hashes::Hash,
    opcodes::all::{OP_PUSHBYTES_40, OP_RETURN},
    Block, Transaction, TxOut,
};
use bitcoincore_rpc::RpcApi;
use da::DAServiceManager;
use rt_evm_model::{
    codec::{hex_encode, ProtocolCodec},
    types::{SignedTransaction, UnsignedTransaction, UnverifiedTransaction, H160, H256, U256},
};
use ruc::*;

use crate::{
    tx::{btc::BtcTransactionBuilder, SAT2WEI},
    vout_code::VoutCode,
};

pub struct FetcherService {
    height: u64,
    builder: BtcTransactionBuilder,
    chain_id: u32,
    da_mgr: Arc<DAServiceManager>,
}

impl FetcherService {
    pub async fn new(
        btc_url: &str,
        username: &str,
        password: &str,
        start: u64,
        chain_id: u32,
        da_mgr: Arc<DAServiceManager>,
    ) -> Result<Self> {
        let builder = BtcTransactionBuilder::new(btc_url, username, password).await?;
        let block_cnt = builder.client.get_block_count().c(d!())?;
        if start > block_cnt + 1 {
            return Err(eg!("The starting height is greater than the chain height"));
        }

        Ok(Self {
            height: start,
            builder,
            chain_id,
            da_mgr,
        })
    }
    pub async fn get_block(&mut self) -> Result<Option<Block>> {
        let block_cnt = self.builder.client.get_block_count().c(d!())?;
        if self.height > block_cnt {
            return Ok(None);
        }
        let hash = self.builder.client.get_block_hash(self.height).c(d!())?;
        let block = self.builder.client.get_block(&hash).c(d!())?;
        log::info!(
            "get {} block:{},{:#?}",
            self.height,
            block.block_hash(),
            block
        );

        self.height += 1;
        Ok(Some(block))
    }
    pub async fn decode_transaction(&self, btc_tx: &Transaction) -> Result<Vec<SignedTransaction>> {
        let source_hash = H256::from(btc_tx.txid().to_byte_array());

        let from = if let Some(txin) = btc_tx.input.first() {
            self.builder
                .get_eth_from_address(&txin.previous_output.txid, txin.previous_output.vout)
                .await?
        } else {
            return Err(eg!("input not found"));
        };

        let input_amount = btc_tx
            .input
            .iter()
            .map(|txin| {
                self.builder
                    .client
                    .get_raw_transaction(&txin.previous_output.txid, None)
                    .c(d!())
                    .and_then(|tx| {
                        tx.output
                            .get(txin.previous_output.vout as usize)
                            .map(|v| v.value)
                            .ok_or(eg!("utxo not fount {:?}", txin.previous_output))
                    })
            })
            .collect::<Result<Vec<_>>>()?
            .iter()
            .map(|v| v.to_sat())
            .sum::<u64>();
        let output_amuont = btc_tx
            .output
            .iter()
            .map(|txout| txout.value.to_sat())
            .sum::<u64>();
        let mut ret = vec![];
        if input_amount <= output_amuont {
            Ok(ret)
        } else if btc_tx.input.is_empty() {
            Ok(ret)
        } else {
            for (index, out) in btc_tx.output.iter().enumerate() {
                match self.decode_vout(out, source_hash, from).await {
                    Ok(tx) => {
                        if U256::from(input_amount - output_amuont)
                            >= (tx.transaction.unsigned.gas_limit() / U256::from(SAT2WEI))
                        {
                            ret.push(tx)
                        };
                    }
                    Err(e) => {
                        log::debug!("decode {} vout {} error:{}", btc_tx.txid(), index, e);
                    }
                }
            }
            Ok(ret)
        }
    }

    async fn decode_vout(
        &self,
        out: &TxOut,
        source_hash: H256,
        sender: H160,
    ) -> Result<SignedTransaction> {
        let code = out.script_pubkey.as_bytes();
        if code.len() != 42
            || Some(OP_RETURN) != code.first().cloned().map(From::from)
            || Some(OP_PUSHBYTES_40) != code.get(1).cloned().map(From::from)
        {
            return Err(eg!(
                "code.len():{},first:{:?},last:{:?}",
                code.len(),
                code.first(),
                code.last()
            ));
        }
        let vc = VoutCode::decode(&code[2..]).c(d!())?;
        log::debug!("decode_vout:{}:{:?}", hex_encode(code), vc);
        vc.check(self.chain_id, self.da_mgr.types()).c(d!())?;
        let da_hash = vc.da_hash();
        log::debug!("da hash:{}", hex_encode(&da_hash));
        let tx_data = self.da_mgr.get_tx(da_hash).await.map_err(|e| eg!(e))?;
        log::debug!("tx_data:{}", hex_encode(&tx_data));
        let mut transaction = UnverifiedTransaction::decode(&tx_data).map_err(|e| eg!(e))?;

        if let UnsignedTransaction::Deposit(ref mut tx) = transaction.unsigned {
            tx.source_hash = source_hash;
            tx.from = sender;
        };

        transaction.chain_id = self.chain_id.into();
        transaction.hash = transaction.get_hash();

        let tx = SignedTransaction {
            transaction,
            sender,
            public: None,
        };
        Ok(tx)
    }
}
