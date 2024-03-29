#![deny(warnings, unused_crate_dependencies)]
#![cfg_attr(feature = "benchmark", allow(warnings))]
#![allow(clippy::uninlined_format_args, clippy::box_default)]

pub mod adapter;
mod precompiles;
mod utils;

use crate::precompiles::build_precompile_set;
pub use crate::{
    adapter::RTEvmExecutorAdapter,
    utils::{code_address, decode_revert_msg, logs_bloom, trie_root_indexed, trie_root_txs},
};
use evm::{
    executor::stack::{MemoryStackState, PrecompileFn, StackExecutor, StackSubstateMetadata},
    CreateScheme, ExitError, ExitReason,
};
use rt_evm_model::{
    traits::{ApplyBackend, Backend, Executor, ExecutorAdapter as Adapter},
    types::{
        data_gas_cost, Account, Config, ExecResp, Hasher, SignedTransaction, TransactionAction,
        TxResp, GAS_CALL_TRANSACTION, GAS_CREATE_TRANSACTION, H160, MIN_TRANSACTION_GAS_LIMIT,
        U256,
    },
};
use ruc::Result;
use std::collections::BTreeMap;

#[derive(Debug)]
pub struct PayFee {
    /// Source address.
    pub source: H160,
    /// Target address.
    /// Transfer value.
    pub value: U256,
}

#[derive(Default)]
pub struct RTEvmExecutor;

impl Executor for RTEvmExecutor {
    // Used for query data API, this function will not modify the world state.
    fn call<B: Backend>(
        &self,
        mut backend: &B,
        gas_limit: u64,
        from: Option<H160>,
        to: Option<H160>,
        value: U256,
        data: Vec<u8>,
    ) -> TxResp {
        let config = Config::london();
        let gas_price = backend.gas_price();
        let metadata = StackSubstateMetadata::new(gas_limit, &config);
        let state = MemoryStackState::new(metadata, &mut backend);
        let precompiles = build_precompile_set();
        let mut executor = StackExecutor::new_with_precompiles(state, &config, &precompiles);

        let base_gas = if to.is_some() {
            GAS_CALL_TRANSACTION + data_gas_cost(&data)
        } else {
            GAS_CREATE_TRANSACTION + GAS_CALL_TRANSACTION + data_gas_cost(&data)
        };

        let (exit, res) = if let Some(addr) = &to {
            executor.transact_call(
                from.unwrap_or_default(),
                *addr,
                value,
                data,
                gas_limit,
                Vec::new(),
            )
        } else {
            executor.transact_create(from.unwrap_or_default(), value, data, gas_limit, Vec::new())
        };

        let used_gas = executor.used_gas() + base_gas;

        TxResp {
            exit_reason: exit,
            ret: res,
            remain_gas: executor.gas(),
            gas_used: used_gas,
            fee_cost: gas_price
                .checked_mul(used_gas.into())
                .unwrap_or(U256::max_value()),
            logs: vec![],
            code_address: if to.is_none() {
                Some(
                    executor
                        .create_address(CreateScheme::Legacy {
                            caller: from.unwrap_or_default(),
                        })
                        .into(),
                )
            } else {
                None
            },
            removed: false,
        }
    }

    // Function execute returns exit_reason, ret_data and remain_gas.
    fn exec<B: Backend + ApplyBackend + Adapter>(
        &self,
        backend: &mut B,
        txs: &[SignedTransaction],
    ) -> Result<ExecResp> {
        let txs_len = txs.len();
        let mut res = Vec::with_capacity(txs_len);

        let mut tx_hashes = Vec::with_capacity(txs_len);
        let mut receipt_hashes = Vec::with_capacity(txs_len);

        let (mut gas, mut fee) = (0u64, U256::zero());
        let precompiles = build_precompile_set();
        let config = Config::london();

        for tx in txs.iter() {
            backend.set_gas_price(tx.transaction.unsigned.gas_price());
            backend.set_origin(tx.sender);

            let mut r = Self::evm_exec(backend, &config, &precompiles, tx);

            backend.commit();

            r.logs = backend.get_logs();
            gas += r.gas_used;
            fee = fee.checked_add(r.fee_cost).unwrap_or(U256::max_value());

            tx_hashes.push(tx.transaction.hash);
            receipt_hashes.push(Hasher::digest(&r.ret));

            res.push(r);
        }

        // Get the new root, the look-like `commit` is a noop here
        let new_state_root = backend.commit();

        let transaction_root = trie_root_indexed(&tx_hashes);
        let receipt_root = trie_root_indexed(&receipt_hashes);

        Ok(ExecResp {
            state_root: new_state_root,
            transaction_root,
            receipt_root,
            gas_used: gas,
            fee_used: fee, // sum(<gas in tx * gas price setted by tx> ...)
            txs_resp: res,
        })
    }

    fn get_account<B: Backend + Adapter>(&self, backend: &B, address: &H160) -> Account {
        backend.get_account(*address)
    }
}

impl RTEvmExecutor {
    pub fn evm_exec<B: Backend + ApplyBackend + Adapter>(
        backend: &mut B,
        config: &Config,
        precompiles: &BTreeMap<H160, PrecompileFn>,
        tx: &SignedTransaction,
    ) -> TxResp {
        // Deduct pre-pay gas
        let sender = tx.sender;
        let tx_gas_price = backend.gas_price();
        let gas_limit = tx.transaction.unsigned.gas_limit();

        let mut account = backend.get_account(sender);

        let current_nonce = account.nonce;

        #[cfg(not(feature = "benchmark"))]
        if tx.transaction.unsigned.nonce() != &current_nonce {
            let min_gas_limit = U256::from(MIN_TRANSACTION_GAS_LIMIT);

            let fee_cost = tx_gas_price.saturating_mul(min_gas_limit);
            account.nonce = current_nonce + U256::one();
            backend.save_account(sender, &account);
            return TxResp {
                exit_reason: ExitReason::Error(ExitError::Other("invalid nonce".into())),
                gas_used: min_gas_limit.as_u64(),
                remain_gas: u64::default(),
                fee_cost,
                removed: false,
                ret: vec![],
                logs: vec![],
                code_address: None,
            };
        }

        backend.save_account(sender, &account);

        let metadata = StackSubstateMetadata::new(gas_limit.as_u64(), config);

        let mut executor = StackExecutor::new_with_precompiles(
            MemoryStackState::new(metadata, backend),
            config,
            precompiles,
        );

        let access_list = tx
            .transaction
            .unsigned
            .access_list()
            .into_iter()
            .map(|x| (x.address, x.storage_keys))
            .collect::<Vec<_>>();

        let (exit, res) = match tx.transaction.unsigned.action() {
            TransactionAction::Call(addr) => executor.transact_call(
                tx.sender,
                *addr,
                *tx.transaction.unsigned.value(),
                tx.transaction.unsigned.data().to_vec(),
                gas_limit.as_u64(),
                access_list,
            ),
            TransactionAction::Create => executor.transact_create(
                tx.sender,
                *tx.transaction.unsigned.value(),
                tx.transaction.unsigned.data().to_vec(),
                gas_limit.as_u64(),
                access_list,
            ),
        };

        let remained_gas = executor.gas();
        let used_gas = executor.used_gas();

        let code_addr = if tx.transaction.unsigned.action() == &TransactionAction::Create
            && exit.is_succeed()
        {
            Some(code_address(tx.sender, &current_nonce))
        } else {
            None
        };

        if exit.is_succeed() {
            let (values, logs) = executor.into_state().deconstruct();
            backend.apply(values, logs, true);
        }

        let mut account = backend.get_account(tx.sender);
        account.nonce = current_nonce + U256::one();

        backend.save_account(tx.sender, &account);

        TxResp {
            exit_reason: exit,
            ret: res,
            remain_gas: remained_gas,
            gas_used: used_gas,
            fee_cost: tx_gas_price.saturating_mul(used_gas.into()),
            logs: vec![],
            code_address: code_addr,
            removed: false,
        }
    }
}
