use ruc::*;

#[allow(unused)]
#[derive(Debug)]
pub struct VoutCode {
    chain_id: u32,
    tx_ty: u8,
    da_ty: u8,
    version: u8,
    filling: u8,
    hash: [u8; 32],
}

#[allow(unused)]
impl VoutCode {
    pub fn new(chain_id: u32, tx_ty: u8, da_ty: u8, version: u8, hash: &[u8]) -> Result<Self> {
        Ok(Self {
            chain_id,
            tx_ty,
            da_ty,
            version,
            filling: 0,
            hash: hash.try_into().map_err(|_| eg!("try into error"))?,
        })
    }
    pub fn da_hash(&self) -> Vec<u8> {
        let mut hash = vec![self.da_ty];
        hash.extend_from_slice(&self.hash);
        hash
    }
    pub fn encode(&self) -> [u8; 40] {
        let mut code: [u8; 40] = [0; 40];
        let chain_id = self.chain_id.to_be_bytes();
        for i in 0..4 {
            code[i] = chain_id[i];
        }
        code[4] = self.tx_ty;
        code[5] = self.da_ty;
        code[6] = self.filling;
        for i in 0..self.hash.len() {
            code[i + 8] = self.hash[i];
        }
        code
    }
    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.len() != 40 {
            return Err(eg!("Not long enough"));
        }
        let chain_id = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        let tx_ty = data[4];
        let da_ty = data[5];
        let version = data[6];
        let filling = data[7];
        let mut hash = [0; 32];
        for i in 0..hash.len() {
            hash[i] = data[i + 8];
        }
        Ok(Self {
            chain_id,
            tx_ty,
            da_ty,
            version,
            filling,
            hash,
        })
    }
    pub fn check(&self, chain_id: u32, da_tys: Vec<u8>) -> Result<()> {
        if self.chain_id != chain_id {
            Err(eg!("chain id error:{} {}", self.chain_id, chain_id))
        } else if 0 != self.tx_ty && 1 != self.tx_ty {
            Err(eg!("tx type error:{}", self.tx_ty))
        } else if !da_tys.contains(&self.da_ty) {
            Err(eg!("da type error:{:?},{}", da_tys, self.da_ty))
        } else if 0 != self.version {
            Err(eg!("version error:{}", self.version))
        } else if 0 != self.filling {
            Err(eg!("filling error:{}", self.filling))
        } else {
            Ok(())
        }
    }
}
