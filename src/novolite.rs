#![deny(warnings)]

use std::{path::PathBuf, process::Command, str::FromStr};

use bitcoin::{
    absolute::LockTime,
    opcodes::all::OP_RETURN,
    script::Builder,
    secp256k1::{All, Message, Secp256k1, SecretKey},
    sighash::SighashCache,
    transaction, Address, Amount, EcdsaSighashType, Network, OutPoint, PrivateKey, ScriptBuf,
    Sequence, Transaction, TxIn, TxOut, Txid, Witness,
};
use bitcoincore_rpc::{json, Auth, Client, RpcApi};
use clap::Parser;
use da::{DAServiceManager, FileService};
use ethers::{
    providers::{Http, Middleware, Provider},
    signers::{LocalWallet, Signer},
    types::{Bytes, TransactionRequest},
    utils::hex,
};
use rt_evm_model::types::{H160, U256};
use ruc::*;

#[derive(Debug, Parser)]
pub struct Args {
    /// The location of the cast command
    #[clap(long)]
    txid: String,
    #[clap(long)]
    vout: u32,
    /// btc url
    #[clap(long)]
    btc_url: String,
    #[clap(long)]
    username: String,
    #[clap(long)]
    password: String,
    /// btc private key
    #[clap(long)]
    private_key: String,
    /// eth web3 url
    #[clap(long)]
    eth_url: String,
    /// ipfs node
    #[clap(long)]
    da_path: String,
    /// btc fee
    #[clap(long)]
    btc_fee: u64,
    /// btc network
    #[clap(long)]
    btc_network: String,

    #[clap(long)]
    to: Option<H160>,

    #[clap(long)]
    value: U256,

    #[clap(long)]
    data: Option<String>,

    sig: Option<String>,

    args: Vec<String>,
}

impl Args {
    pub async fn execute(self) -> Result<()> {
        let mut da_mgr = DAServiceManager::new();
        da_mgr.add_default_service(
            FileService::new(PathBuf::from(&self.da_path)).map_err(|e| eg!(e))?,
        );

        let (eth_tx, fee, chain_id) = self.eth_tx().await?;
        let hash = da_mgr.set_tx(&eth_tx).await.map_err(|e| eg!(e))?;
        let mut code: [u8; 40] = [0; 40];
        let chain_id = chain_id.to_be_bytes();
        for i in 0..=3 {
            code[i] = chain_id[i];
        }
        code[5] = da_mgr.default_type();
        if hash.len() < 33 {
            return Err(eg!("set tx return error"));
        }
        for i in 8..40 {
            code[i] = hash[i - 7];
        }
        let txid = self.btc_tx(fee, &code)?;
        println!("bitcoin transaction: {}", txid);
        Ok(())
    }

    fn btc_tx(&self, fee: u64, hash: &[u8; 40]) -> Result<Txid> {
        let fee = Amount::from_sat(fee) + Amount::from_sat(2000);
        let sk = PrivateKey {
            compressed: true,
            network: Network::from_core_arg(&self.btc_network).c(d!())?,
            inner: SecretKey::from_str(
                &self
                    .private_key
                    .strip_prefix("0x")
                    .unwrap_or(&self.private_key),
            )
            .c(d!())?,
        };
        let client = Client::new(
            &self.btc_url,
            Auth::UserPass(self.username.clone(), self.password.clone()),
        )
        .c(d!())?;
        let secp: Secp256k1<All> = Secp256k1::new();
        let pk = sk.public_key(&secp);
        let addr = Address::p2wpkh(&pk, sk.network).c(d!())?;

        // get unspent
        // let mut unspents = client
        //     .list_unspent(None, None, Some(&[&addr]), Some(true), None)
        //     .c(d!())?;
        // unspents.sort_by(|a, b| a.amount.cmp(&b.amount));
        // let mut sum_amount = Amount::ZERO;
        let mut input = Vec::new();
        let mut sign_inputs = Vec::new();
        let mut sks = Vec::new();
        // for unspent in unspents.iter() {
        //     if Some(addr.clone()) != unspent.address.clone().map(|v| v.assume_checked())
        //         || !unspent.safe
        //     {
        //         continue;
        //     }
        //     let txin = TxIn {
        //         previous_output: OutPoint {
        //             txid: unspent.txid,
        //             vout: unspent.vout,
        //         },
        //         sequence: Sequence::MAX,
        //         script_sig: ScriptBuf::new(),
        //         witness: Witness::new(),
        //     };
        //     input.push(txin);
        //     sks.push(sk);
        //     let sign_input = json::SignRawTransactionInput {
        //         txid: unspent.txid,
        //         vout: unspent.vout,
        //         script_pub_key: unspent.script_pub_key.clone(),
        //         redeem_script: None,
        //         amount: Some(unspent.amount),
        //     };
        //     sign_inputs.push(sign_input);
        //     sum_amount += unspent.amount;
        //     if sum_amount > fee {
        //         break;
        //     }
        // }
        // if sum_amount <= fee {
        //     return Err(eg!("Insufficient balance"));
        // }

        let txid = Txid::from_str(&self.txid).c(d!())?;
        let unspent = client.get_tx_out(&txid, self.vout, None).c(d!())?.c(d!())?;
        log::info!("unspent:{:#?}", unspent);
        let sum_amount = unspent.value;
        let txin = TxIn {
            previous_output: OutPoint {
                txid,
                vout: self.vout,
            },
            sequence: Sequence::MAX,
            script_sig: ScriptBuf::new(),
            witness: Witness::new(),
        };
        input.push(txin);
        sks.push(sk);
        let sign_input = json::SignRawTransactionInput {
            txid,
            vout: self.vout,
            script_pub_key: unspent.script_pub_key.script().c(d!())?,
            redeem_script: None,
            amount: Some(unspent.value),
        };
        let script_pubkey = sign_input.script_pub_key.clone();
        sign_inputs.push(sign_input);

        // create transaction
        let mut unsigned_tx = Transaction {
            version: transaction::Version::ONE,
            lock_time: LockTime::ZERO,
            input,
            output: vec![
                TxOut {
                    value: Amount::from_sat(0),
                    script_pubkey: Builder::new()
                        .push_opcode(OP_RETURN)
                        .push_slice(hash)
                        .into_script(),
                },
                TxOut {
                    value: (sum_amount - fee),
                    script_pubkey: addr.script_pubkey(),
                },
            ],
        };
        let sighash_type = EcdsaSighashType::All;
        let mut sighasher = SighashCache::new(&mut unsigned_tx);
        let sighash = sighasher
            .p2wpkh_signature_hash(0, &script_pubkey, unspent.value, sighash_type)
            .c(d!())?;

        let secp = Secp256k1::new();
        // Sign the sighash using the secp256k1 library (exported by rust-bitcoin).
        let msg = Message::from(sighash);

        let signature = secp.sign_ecdsa(&msg, &sk.inner);

        // Update the witness stack.
        let signature = bitcoin::ecdsa::Signature {
            sig: signature,
            hash_ty: sighash_type,
        };

        *sighasher.witness_mut(0).unwrap() = Witness::p2wpkh(&signature, &pk.inner);

        // Get the signed transaction.
        let tx = sighasher.into_transaction().clone();
        log::info!("btc tx:{:#?}", tx);
        client.send_raw_transaction(&tx).c(d!())
    }

    async fn eth_tx(&self) -> Result<(Bytes, u64, u32)> {
        let provider = Provider::<Http>::try_from(&self.eth_url).c(d!())?;
        let chain_id = provider.get_chainid().await.c(d!())?.as_u64();
        let wallet = hex::decode(
            self.private_key
                .strip_prefix("0x")
                .unwrap_or(&self.private_key),
        )
        .c(d!())
        .and_then(|bytes| LocalWallet::from_bytes(&bytes).c(d!()))
        .map(|wallet| wallet.with_chain_id(chain_id))?;
        let mut tx = TransactionRequest::new().value(self.value);
        tx = tx.from(wallet.address());
        if let Some(to) = self.to.clone() {
            tx = tx.to(to);
        }
        if let Some(data) = self.data.clone() {
            tx = tx.data(hex::decode(data.strip_prefix("0x").unwrap_or(&data)).c(d!())?);
        } else {
            if let Some(sig) = &self.sig {
                let mut cast = Command::new("cast");
                cast.arg("calldata");
                cast.arg(sig);
                for it in self.args.iter() {
                    cast.arg(it);
                }
                let output = cast.output().c(d!())?;
                let calldata = String::from_utf8(output.stdout).c(d!())?;
                if !output.status.success() {
                    return Err(eg!(calldata));
                }
                println!("{}", calldata);
                tx = tx.data(
                    hex::decode(calldata.trim().strip_prefix("0x").unwrap_or(&calldata)).c(d!())?,
                );
            }
        }

        let mut tx = tx.clone().into();
        provider.fill_transaction(&mut tx, None).await.c(d!())?;
        let nonce = provider
            .get_transaction_count(wallet.address(), None)
            .await
            .c(d!())?;
        tx.set_nonce(nonce);
        log::info!("eth tx:{:#?}", tx);
        let signature = wallet.sign_transaction(&tx).await.c(d!())?;
        let sat2wei: u64 = 10000000000;
        Ok((
            tx.rlp_signed(&signature),
            (tx.gas().c(d!())?.checked_div(U256::from(sat2wei)))
                .c(d!())?
                .as_u64(),
            chain_id as u32,
        ))
    }
}

#[tokio::main]
async fn main() {
    env_logger::init();

    let args = Args::parse();

    args.execute().await.unwrap()
}
