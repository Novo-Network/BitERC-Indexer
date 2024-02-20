use std::sync::Arc;

use bitcoin::{
    opcodes::all::{OP_PUSHBYTES_40, OP_RETURN},
    Block, Transaction,
};
use bitcoincore_rpc::{Auth, Client, RpcApi};
use da::DAServiceManager;
use ethers::{types::transaction::eip2718::TypedTransaction, utils::rlp::Rlp};
use rt_evm_model::types::{
    LegacyTransaction, SignatureComponents, SignedTransaction, TransactionAction,
    UnsignedTransaction, UnverifiedTransaction, U256,
};
use ruc::*;

pub const SAT2WEI: u64 = 10000000000;
pub struct FetcherService {
    height: u64,
    cli: Client,
    chain_id: U256,
    da_mgr: Arc<DAServiceManager>,
}

impl FetcherService {
    pub fn new(
        btc_url: &str,
        username: &str,
        password: &str,
        start: u64,
        chain_id: U256,
        da_mgr: Arc<DAServiceManager>,
    ) -> Result<Self> {
        let cli = Client::new(
            btc_url,
            Auth::UserPass(username.to_string(), password.to_string()),
        )
        .map_err(|e| eg!(e))?;
        let block_cnt = cli.get_block_count().c(d!())?;
        if start > block_cnt + 1 {
            return Err(eg!("The starting height is greater than the chain height"));
        }

        Ok(Self {
            height: start,
            cli,
            chain_id,
            da_mgr,
        })
    }
    pub async fn get_block(&mut self) -> Result<Option<Block>> {
        let block_cnt = self.cli.get_block_count().c(d!())?;
        if self.height > block_cnt {
            return Ok(None);
        }
        let hash = self.cli.get_block_hash(self.height).c(d!())?;
        let block = self.cli.get_block(&hash).c(d!())?;

        self.height += 1;
        Ok(Some(block))
    }
    pub async fn decode_transaction(&self, btc_tx: &Transaction) -> Result<Vec<SignedTransaction>> {
        let mut ret = vec![];
        let input_amount = btc_tx
            .input
            .iter()
            .map(|txin| {
                self.cli
                    .get_raw_transaction(&txin.previous_output.txid,None)// (&txin.previous_output.txid, txin.previous_output.vout, None)
                    .c(d!())
                    .and_then(|tx| {
                        tx.output.get(txin.previous_output.vout as usize)
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
        if input_amount <= output_amuont {
            Ok(ret)
        } else if btc_tx.input.is_empty() {
            Ok(ret)
        } else {
            for out in btc_tx.output.iter() {
                let code = out.script_pubkey.as_bytes();
                let chain_id = u32::from_be_bytes([code[2], code[3], code[4], code[5]]);
                if code.len() != 42
                    || Some(OP_RETURN) != code.first().cloned().map(From::from)
                    || Some(OP_PUSHBYTES_40) != code.get(1).cloned().map(From::from)
                    || self.chain_id.as_u32() != chain_id
                {
                    continue;
                }
                // type
                if 0 != code[6] && 1 != code[6] {
                    continue;
                }
                // da
                if !self.da_mgr.contains(code[7]) {
                    continue;
                }
                // version
                if 0 != code[8] {
                    continue;
                }
                // empty
                if 0 != code[9] {
                    continue;
                }
                if out.value.to_sat() != 0 {
                    continue;
                }
                let mut hash = vec![code[7]];
                hash.extend_from_slice(&code[10..]);
                let tx_data = self.da_mgr.get_tx(hash).await.map_err(|e| eg!(e))?;
                let (evm_tx, _sign) =
                    TypedTransaction::decode_signed(&Rlp::new(&tx_data)).c(d!())?;
                if U256::from(input_amount - output_amuont)
                    < (evm_tx.gas().c(d!())? / U256::from(SAT2WEI))
                {
                    continue;
                };
                let action = match evm_tx.to() {
                    Some(addr) => TransactionAction::Call(addr.as_address().cloned().c(d!())?),
                    None => TransactionAction::Create,
                };

                let transaction = UnverifiedTransaction {
                    unsigned: UnsignedTransaction::Legacy(LegacyTransaction {
                        nonce: evm_tx.nonce().cloned().c(d!())?,
                        gas_price: evm_tx.gas_price().c(d!())?,
                        gas_limit: evm_tx.gas().cloned().c(d!())?,
                        action,
                        value: evm_tx.value().cloned().c(d!())?,
                        data: match evm_tx.data().cloned() {
                            Some(v) => v.to_vec(),
                            None => Vec::new(),
                        },
                    }),
                    signature: Some(SignatureComponents::from(_sign.to_vec())),
                    chain_id: evm_tx.chain_id().c(d!())?.as_u64(),
                    hash: evm_tx.hash(&_sign),
                };

                let tx = SignedTransaction {
                    transaction: transaction.calc_hash(),
                    sender: evm_tx.from().cloned().c(d!())?,
                    public: None,
                };
                ret.push(tx);
                //ret.push(tx.transaction.try_into().map_err(|e| eg!(e))?);
                break;
            }
            Ok(ret)
        }
    }
}
