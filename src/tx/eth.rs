use std::process::Command;

use ethers::{
    providers::{Http, Middleware, Provider},
    types::{
        transaction::{eip2718::TypedTransaction, optimism::DepositTransaction},
        Bytes, TransactionRequest, H160, H256, U256,
    },
    utils::hex,
};
use ruc::*;

use super::SAT2WEI;

#[allow(unused)]
pub struct EthTransactionBuilder {
    provider: Provider<Http>,
}

#[allow(unused)]
impl EthTransactionBuilder {
    pub async fn new(url: &str, sk: &str) -> Result<Self> {
        let provider = Provider::<Http>::try_from(url).c(d!())?;

        Ok(Self { provider })
    }
    pub async fn chain_id(&self) -> Result<u32> {
        Ok(self.provider.get_chainid().await.c(d!())?.as_u64() as u32)
    }
    pub async fn build_transaction(
        &self,
        from: H160,
        value: U256,
        to: Option<H160>,
        data: &[u8],
        sig: &str,
        args: Vec<String>,
    ) -> Result<(Bytes, u64)> {
        let mut tx = TransactionRequest::new().value(value.clone()).from(from);
        log::info!("eth from address: {:?}", from);
        if let Some(to) = to {
            tx = tx.to(to);
        }
        let data = if data.is_empty() {
            let mut cast = Command::new("cast");
            cast.arg("calldata");
            cast.arg(sig);
            for it in args {
                cast.arg(it);
            }
            let output = cast.output().c(d!())?;
            let calldata = String::from_utf8(output.stdout).c(d!())?;
            if !output.status.success() {
                return Err(eg!(calldata));
            }
            hex::decode(calldata.trim().strip_prefix("0x").unwrap_or(&calldata)).c(d!())?
        } else {
            data.to_vec()
        };
        let nonce = self
            .provider
            .get_transaction_count(from, None)
            .await
            .c(d!())?;
        let mut tx = tx.nonce(nonce).data(data);
        let mut tx = TypedTransaction::DepositTransaction(DepositTransaction {
            tx,
            source_hash: H256::default(),
            mint: if value.is_zero() { None } else { Some(value) },
            is_system_tx: false,
        });
        self.provider
            .fill_transaction(&mut tx, None)
            .await
            .c(d!())?;
        Ok((
            tx.rlp(),
            tx.gas()
                .c(d!())?
                .checked_div(U256::from(SAT2WEI))
                .c(d!())?
                .as_u64(),
        ))
    }
}
