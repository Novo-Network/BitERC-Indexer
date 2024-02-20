#![deny(warnings, unused_crate_dependencies)]
#![cfg_attr(feature = "benchmark", allow(warnings))]

use bitcoin::{
    consensus::{deserialize, serialize},
    Transaction, Txid,
};
pub use ethabi;
pub use trie_db::MptStore;
pub use vsdb_trie_db as trie_db;
pub use FunStorage as Storage;

use moka::sync::Cache as Lru;
use parking_lot::RwLock;
use rayon::prelude::*;
use rt_evm_model::{
    codec::ProtocolCodec,
    traits::{BlockStorage, TxStorage},
    types::{
        Account, Block, BlockNumber, FatBlock, Hash, Header, Receipt, SignedTransaction, H160,
        H256, NIL_HASH, U256, WORLD_STATE_META_KEY,
    },
};
use ruc::*;
use serde::{Deserialize, Serialize};
use std::{sync::Arc, time::Duration};
use trie_db::MptOnce;
use vsdb::{KeyEnDeOrdered, MapxOrd, MapxRaw};

const BATCH_LIMIT: usize = 1000;

#[derive(Debug, Serialize, Deserialize)]
pub struct FunStorage {
    db: DB,
    #[serde(skip)]
    cache: Cache,
}

const DEFAULT_CACHE_SIZE: u64 = 100_0000;

impl FunStorage {
    pub fn new(cache_size: u64) -> Self {
        Self {
            db: DB::new(),
            cache: Cache::new(cache_size),
        }
    }

    fn get_txs_unlimited(&self, hashes: &[Hash]) -> Vec<Option<(BlockNumber, SignedTransaction)>> {
        hashes
            .par_iter()
            .map(|txh| {
                self.cache
                    .transactions
                    .get(txh)
                    .or_else(|| self.db.transactions.get(txh))
            })
            .collect()
    }
}

impl Default for FunStorage {
    fn default() -> Self {
        Self::new(DEFAULT_CACHE_SIZE)
    }
}

#[derive(Debug, Clone, Hash, Eq, PartialEq, PartialOrd)]
pub struct TxidWrapper(Txid);

impl Ord for TxidWrapper {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        serialize(&self.0).cmp(&serialize(&other.0))
    }
}
impl KeyEnDeOrdered for TxidWrapper {
    fn to_bytes(&self) -> vsdb::RawBytes {
        serialize(&self.0)
    }

    fn from_slice(b: &[u8]) -> Result<Self> {
        Ok(Self(deserialize(b).map_err(|e| eg!(e))?))
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct DB {
    blocks: MapxOrd<u64, Block>,
    block_numbers: MapxOrd<Hash, u64>,
    headers: MapxOrd<u64, Header>,

    transactions: MapxOrd<Hash, (BlockNumber, SignedTransaction)>,

    codes: MapxRaw,
    codes_addr_to_hash: MapxRaw,

    receipts: MapxOrd<Hash, Receipt>,

    btc_txhashs: MapxOrd<u64, Vec<Vec<u8>>>,
    btc_txs: MapxOrd<Vec<u8>, Vec<u8>>,
}

impl DB {
    fn new() -> Self {
        Self {
            blocks: MapxOrd::new(),
            block_numbers: MapxOrd::new(),
            headers: MapxOrd::new(),

            transactions: MapxOrd::new(),

            codes: MapxRaw::new(),
            codes_addr_to_hash: MapxRaw::new(),

            receipts: MapxOrd::new(),

            btc_txhashs: MapxOrd::new(),
            btc_txs: MapxOrd::new(),
        }
    }

    // safe in the context of EVM
    fn shadow(&self) -> Self {
        unsafe {
            Self {
                blocks: self.blocks.shadow(),
                block_numbers: self.block_numbers.shadow(),
                headers: self.headers.shadow(),
                transactions: self.transactions.shadow(),
                codes: self.codes.shadow(),
                codes_addr_to_hash: self.codes_addr_to_hash.shadow(),
                receipts: self.receipts.shadow(),
                btc_txhashs: self.btc_txhashs.shadow(),
                btc_txs: self.btc_txs.shadow(),
            }
        }
    }
}

#[macro_export(local_inner_macros)]
macro_rules! gen_lru {
    ($size: expr) => {
        Lru::builder()
            .max_capacity($size)
            .time_to_idle(Duration::from_secs(600)) // 10 minutes
            .build()
    };
}

#[derive(Debug, Clone)]
struct Cache {
    blocks: Lru<u64, Block>,
    block_numbers: Lru<Hash, u64>,
    headers: Lru<u64, Header>,

    transactions: Lru<Hash, (BlockNumber, SignedTransaction)>,

    btc_txhashs: Lru<u64, Vec<Txid>>,
    btc_txs: Lru<Txid, Transaction>,

    codes: Lru<Hash, Vec<u8>>,
    codes_addr_to_hash: Lru<H256, Hash>,

    receipts: Lru<Hash, Receipt>,

    latest_block: Arc<RwLock<Option<Block>>>,
}

impl Cache {
    fn new(size: u64) -> Self {
        Self {
            blocks: gen_lru!(size),
            block_numbers: gen_lru!(size),
            headers: gen_lru!(size),
            transactions: gen_lru!(size),
            btc_txhashs: gen_lru!(size),
            btc_txs: gen_lru!(size),
            codes: gen_lru!(size),
            codes_addr_to_hash: gen_lru!(size),
            receipts: gen_lru!(size),
            latest_block: Arc::new(RwLock::new(None)),
        }
    }
}

impl Default for Cache {
    fn default() -> Self {
        Self::new(DEFAULT_CACHE_SIZE)
    }
}

impl BlockStorage for FunStorage {
    fn set_block(&self, block: Block) -> Result<()> {
        let mut db = self.db.shadow();

        let bh = block.hash();
        let header = block.header.clone();
        let number = header.number;

        db.block_numbers.insert(&bh, &number);
        db.headers.insert(&number, &header);
        db.blocks.insert(&number, &block);

        self.cache.block_numbers.insert(bh, number);
        self.cache.headers.insert(number, header);
        self.cache.blocks.insert(number, block.clone());

        self.set_latest_block(block).c(d!())
    }

    fn get_block(&self, number: u64) -> Result<Option<Block>> {
        Ok(self
            .cache
            .blocks
            .get(&number)
            .or_else(|| self.db.blocks.get(&number)))
    }

    fn get_fatblock(&self, number: u64) -> Result<Option<FatBlock>> {
        if let Some(block) = self.get_block(number).c(d!())? {
            let txs = self
                .get_txs_unlimited(&block.tx_hashes)
                .into_iter()
                .map(|maybe_tx| pnk!(maybe_tx).1)
                .collect();
            let fat_block = FatBlock { block, txs };
            Ok(Some(fat_block))
        } else {
            Ok(None)
        }
    }

    fn get_block_header(&self, number: u64) -> Result<Option<Header>> {
        Ok(self
            .cache
            .headers
            .get(&number)
            .or_else(|| self.db.headers.get(&number)))
    }

    fn get_latest_block(&self) -> Result<Block> {
        self.cache
            .latest_block
            .read()
            .clone()
            .or_else(|| self.db.blocks.last().map(|(_, b)| b))
            .ok_or_else(|| eg!("no blocks found"))
    }

    fn set_latest_block(&self, block: Block) -> Result<()> {
        self.cache.latest_block.write().replace(block);
        Ok(())
    }

    fn get_latest_block_header(&self) -> Result<Header> {
        self.get_latest_block().c(d!()).map(|b| b.header)
    }
}

impl TxStorage for FunStorage {
    fn insert_btc_txs(&self, block_number: u64, btc_txs: Vec<Transaction>) -> Result<()> {
        let mut db = self.db.shadow();

        let mut cache_ids = vec![];
        let mut db_ids = vec![];
        for tx in btc_txs.into_iter() {
            let id = tx.txid();
            cache_ids.push(id);
            let key = serialize(&id);
            db_ids.push(key.clone());
            db.btc_txs.insert(&key, &serialize(&tx));
            self.cache.btc_txs.insert(id, tx);
        }
        db.btc_txhashs.insert(&block_number, &db_ids);
        self.cache.btc_txhashs.insert(block_number, cache_ids);
        Ok(())
    }

    fn insert_txs(&self, block_number: u64, signed_txs: Vec<SignedTransaction>) -> Result<()> {
        let mut db = self.db.shadow();

        signed_txs
            .into_iter()
            .map(|tx| (block_number, tx))
            .for_each(|h_tx| {
                db.transactions.insert(&h_tx.1.transaction.hash, &h_tx);
                self.cache
                    .transactions
                    .insert(h_tx.1.transaction.hash, h_tx);
            });

        Ok(())
    }

    fn get_block_by_hash(&self, block_hash: &Hash) -> Result<Option<Block>> {
        if let Some(number) = self
            .cache
            .block_numbers
            .get(block_hash)
            .or_else(|| self.db.block_numbers.get(block_hash))
        {
            self.cache
                .blocks
                .get(&number)
                .or_else(|| self.db.blocks.get(&number))
                .map(Some)
                .c(d!("BUG!"))
        } else {
            Ok(None)
        }
    }
    fn get_btc_txid_by_height(&self, block_height: u64) -> Result<Vec<Txid>> {
        if let Some(v) = self.cache.btc_txhashs.get(&block_height) {
            Ok(v)
        } else {
            self.db
                .btc_txhashs
                .get(&block_height)
                .ok_or(eg!("btc txid not fount"))
                .and_then(|id| {
                    id.iter()
                        .map(|v| deserialize(v).map_err(|e| eg!(e)))
                        .collect::<Result<Vec<Txid>>>()
                })
        }
    }

    fn get_btc_tx_by_txid(&self, id: &Txid) -> Result<Option<Transaction>> {
        if let Some(v) = self.cache.btc_txs.get(id) {
            Ok(Some(v))
        } else if let Some(v) = self.db.btc_txs.get(&serialize(&id)) {
            Ok(Some(deserialize(&v).c(d!())?))
        } else {
            Ok(None)
        }
    }

    fn get_txs(
        &self,
        block_number: u64,
        hashes: &[Hash],
    ) -> Result<Vec<Option<SignedTransaction>>> {
        if hashes.len() > BATCH_LIMIT {
            return Err(eg!("request too large"));
        }

        Ok(self
            .get_txs_unlimited(hashes)
            .into_iter()
            .map(|maybe_tx| {
                if let Some((number, tx)) = maybe_tx {
                    if number == block_number {
                        return Some(tx);
                    }
                }
                None
            })
            .collect())
    }

    fn get_tx_by_hash(&self, hash: &Hash) -> Result<Option<SignedTransaction>> {
        Ok(self
            .cache
            .transactions
            .get(hash)
            .or_else(|| self.db.transactions.get(hash))
            .map(|(_, tx)| tx))
    }

    fn insert_receipts(&self, _block_number: u64, receipts: Vec<Receipt>) -> Result<()> {
        let mut db = self.db.shadow();

        receipts.into_iter().for_each(|r| {
            db.receipts.insert(&r.tx_hash, &r);
            self.cache.receipts.insert(r.tx_hash, r);
        });

        Ok(())
    }

    fn get_receipt_by_hash(&self, hash: &Hash) -> Result<Option<Receipt>> {
        Ok(self
            .cache
            .receipts
            .get(hash)
            .or_else(|| self.db.receipts.get(hash)))
    }

    fn get_receipts(&self, block_number: u64, hashes: &[Hash]) -> Result<Vec<Option<Receipt>>> {
        if hashes.len() > BATCH_LIMIT {
            return Err(eg!("request too large"));
        }

        Ok(hashes
            .iter()
            .map(|txh| {
                self.cache
                    .receipts
                    .get(txh)
                    .or_else(|| self.db.receipts.get(txh))
                    .and_then(|r| alt!(r.block_number == block_number, Some(r), None))
            })
            .collect())
    }

    fn insert_code(&self, code_address: H256, code_hash: Hash, code: Vec<u8>) -> Result<()> {
        let mut db = self.db.shadow();

        db.codes_addr_to_hash
            .insert(code_address.as_bytes(), code_hash.as_bytes());
        db.codes.insert(code_hash.as_bytes(), &code);

        self.cache
            .codes_addr_to_hash
            .insert(code_address, code_hash);
        self.cache.codes.insert(code_hash, code);

        Ok(())
    }

    fn get_code_by_hash(&self, hash: &Hash) -> Result<Option<Vec<u8>>> {
        Ok(self
            .cache
            .codes
            .get(hash)
            .or_else(|| self.db.codes.get(hash)))
    }

    fn get_code_by_address(&self, address: &H256) -> Result<Option<Vec<u8>>> {
        if let Some(h) = self.cache.codes_addr_to_hash.get(address).or_else(|| {
            self.db
                .codes_addr_to_hash
                .get(address)
                .map(|hash| H256::from_slice(&hash))
        }) {
            self.get_code_by_hash(&h).c(d!())
        } else {
            Ok(None)
        }
    }
}

pub fn get_account_by_backend(
    trie_db: &MptStore,
    storage: &Storage,
    address: H160,
    number: Option<BlockNumber>,
) -> Result<Account> {
    let header = if let Some(n) = number {
        storage.get_block_header(n).c(d!())?.c(d!())?
    } else {
        storage.get_latest_block_header().c(d!())?
    };

    let state = trie_db
        .trie_restore(&WORLD_STATE_META_KEY, header.state_root.into())
        .c(d!())?;

    get_account_by_state(&state, address).c(d!())
}

pub fn get_account_by_state(state: &MptOnce, address: H160) -> Result<Account> {
    match state.get(address.as_bytes()).c(d!())? {
        Some(bytes) => Account::decode(bytes).c(d!()),
        None => Ok(Account {
            nonce: U256::zero(),
            balance: U256::zero(),
            storage_root: NIL_HASH,
            code_hash: NIL_HASH,
        }),
    }
}

pub fn save_account_by_backend(
    trie_db: &MptStore,
    storage: &Storage,
    address: H160,
    account: &Account,
) -> Result<()> {
    let header = storage.get_latest_block_header().c(d!())?;
    let mut state = trie_db
        .trie_restore(&WORLD_STATE_META_KEY, header.state_root.into())
        .c(d!())?;

    save_account_by_state(&mut state, address, account).c(d!())
}

pub fn save_account_by_state(state: &mut MptOnce, address: H160, account: &Account) -> Result<()> {
    account
        .encode()
        .c(d!())
        .and_then(|acc| state.insert(address.as_bytes(), &acc).c(d!()))
}
