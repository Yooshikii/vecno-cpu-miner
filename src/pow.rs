pub use crate::pow::hasher::HeaderHasher;
use crate::{
    pow::{
        hasher::{Hasher, PowHash},
        mem_hash::mem_hash,
    },
    proto::{RpcBlock, RpcBlockHeader},
    target::{self, Uint256},
    Error,
};

use blake3;
use sha3::{Digest, Sha3_256};
use crate::Hash;
mod hasher;
mod mem_hash;

/// Computes SHA3-256 hash of a 32-byte input
fn sha3_hash(input: [u8; 32]) -> [u8; 32] {
    let mut sha3_hasher = Sha3_256::new();
    sha3_hasher.update(input);
    sha3_hasher.finalize().as_slice().try_into().expect("SHA-3 output length mismatch")
}

/// Computes Blake3 hash of a 32-byte input
fn blake3_hash(input: [u8; 32]) -> [u8; 32] {
    *blake3::hash(&input).as_bytes() // Safe: Blake3 outputs 32 bytes
}

/// Calculates the number of hash rounds (1–4) based on the first 4 bytes
fn calculate_rounds(input: [u8; 32]) -> usize {
    (u32::from_le_bytes(input[0..4].try_into().unwrap_or_default()) % 4 + 1) as usize
}

/// Performs XOR manipulations on adjacent bytes in 4-byte chunks
fn bit_manipulations(data: &mut [u8; 32]) {
    for i in (0..32).step_by(4) {
        data[i] ^= data[i + 1];
    }
}

/// Combines SHA3-256 and Blake3 hashes with byte-wise XOR
fn byte_mixing(sha3_hash: &[u8; 32], b3_hash: &[u8; 32]) -> [u8; 32] {
    let mut temp_buf = [0u8; 32];
    for i in 0..32 {
        temp_buf[i] = sha3_hash[i] ^ b3_hash[i];
    }
    temp_buf
}

#[derive(Clone)]
pub struct State {
    #[allow(dead_code)]
    pub id: usize,
    pub nonce: u64,
    target: Uint256,
    block: RpcBlock,
    hasher: PowHash,
}

impl State {
    #[inline]
    pub fn new(id: usize, block: RpcBlock) -> Result<Self, Error> {
        let header = &block.header.as_ref().ok_or("Header is missing")?;

        let target = target::u256_from_compact_target(header.bits);
        let mut hasher = HeaderHasher::new();
        serialize_header(&mut hasher, header, true);
        let pre_pow_hash = hasher.finalize();
        // PRE_POW_HASH || TIME || 32 zero byte padding || NONCE
        let hasher = PowHash::new(pre_pow_hash, header.timestamp as u64);

        Ok(Self { id, nonce: 0, target, block, hasher })
    }

    #[inline(always)]
    /// PRE_POW_HASH || TIME || 32 zero byte padding || NONCE
    pub fn calculate_pow(&mut self) -> Uint256 {
        // TODO: Parallelize nonce iteration by cloning State for multiple threads
        let hash = self.hasher.clone().finalize_with_nonce(self.nonce);
        let mut hash_bytes: [u8; 32] = hash.as_bytes().try_into().expect("Hash output length mismatch");
        let rounds = calculate_rounds(hash_bytes);
        let b3_hash: [u8; 32];

        for _ in 0..rounds {
            hash_bytes = blake3_hash(hash_bytes);
            bit_manipulations(&mut hash_bytes);
        }
        b3_hash = hash_bytes;

        for _ in 0..rounds {
            hash_bytes = sha3_hash(hash_bytes);
            bit_manipulations(&mut hash_bytes);
        }

        let m_hash = byte_mixing(&hash_bytes, &b3_hash);
        let final_hash = mem_hash(Hash::from_le_bytes(m_hash));
        Uint256::from_le_bytes(final_hash.as_bytes())
    }

    /// Verifies if the PoW hash meets the difficulty target
    #[inline(always)]
    pub fn check_pow(&mut self) -> bool {
        let pow = self.calculate_pow();
        // The pow hash must be less or equal than the claimed target.
        pow <= self.target
    }

    #[inline(always)]
    pub fn generate_block_if_pow(&mut self) -> Option<RpcBlock> {
        self.check_pow().then(|| {
            let mut block = self.block.clone();
            let header = block.header.as_mut().expect("We checked that a header exists on creation");
            header.nonce = self.nonce;
            block
        })
    }
}

#[cfg(not(any(target_pointer_width = "64", target_pointer_width = "32")))]
compile_error!("Supporting only 32/64 bits");

#[inline(always)]
pub fn serialize_header<H: Hasher>(hasher: &mut H, header: &RpcBlockHeader, for_pre_pow: bool) {
    let (nonce, timestamp) = if for_pre_pow { (0, 0) } else { (header.nonce, header.timestamp) };
    let num_parents = header.parents.len();
    let version: u16 = header.version.try_into().unwrap();
    hasher.update(version.to_le_bytes()).update((num_parents as u64).to_le_bytes());

    let mut hash = [0u8; 32];
    for parent in &header.parents {
        hasher.update((parent.parent_hashes.len() as u64).to_le_bytes());
        for hash_string in &parent.parent_hashes {
            decode_to_slice(hash_string, &mut hash).unwrap();
            hasher.update(hash);
        }
    }
    decode_to_slice(&header.hash_merkle_root, &mut hash).unwrap();
    hasher.update(hash);

    decode_to_slice(&header.accepted_id_merkle_root, &mut hash).unwrap();
    hasher.update(hash);
    decode_to_slice(&header.utxo_commitment, &mut hash).unwrap();
    hasher.update(hash);

    hasher
        .update(timestamp.to_le_bytes())
        .update(header.bits.to_le_bytes())
        .update(nonce.to_le_bytes())
        .update(header.daa_score.to_le_bytes())
        .update(header.blue_score.to_le_bytes());

    let blue_work_len = (header.blue_work.len() + 1) / 2;
    if header.blue_work.len() % 2 == 0 {
        decode_to_slice(&header.blue_work, &mut hash[..blue_work_len]).unwrap();
    } else {
        let mut blue_work = String::with_capacity(header.blue_work.len() + 1);
        blue_work.push('0');
        blue_work.push_str(&header.blue_work);
        decode_to_slice(&blue_work, &mut hash[..blue_work_len]).unwrap();
    }

    hasher.update((blue_work_len as u64).to_le_bytes()).update(&hash[..blue_work_len]);

    decode_to_slice(&header.pruning_point, &mut hash).unwrap();
    hasher.update(hash);
}

#[allow(dead_code)]
#[derive(Debug)]
enum FromHexError {
    OddLength,
    InvalidStringLength,
    InvalidHexCharacter { c: char, index: usize },
}

#[inline(always)]
fn decode_to_slice<T: AsRef<[u8]>>(data: T, out: &mut [u8]) -> Result<(), FromHexError> {
    let data = data.as_ref();
    if data.len() % 2 != 0 {
        return Err(FromHexError::OddLength);
    }
    if data.len() / 2 != out.len() {
        return Err(FromHexError::InvalidStringLength);
    }

    for (i, byte) in out.iter_mut().enumerate() {
        *byte = val(data[2 * i], 2 * i)? << 4 | val(data[2 * i + 1], 2 * i + 1)?;
    }

    #[inline(always)]
    fn val(c: u8, idx: usize) -> Result<u8, FromHexError> {
        match c {
            b'A'..=b'F' => Ok(c - b'A' + 10),
            b'a'..=b'f' => Ok(c - b'a' + 10),
            b'0'..=b'9' => Ok(c - b'0'),
            _ => Err(FromHexError::InvalidHexCharacter { c: c as char, index: idx }),
        }
    }

    Ok(())
}
