pub use crate::pow::hasher::HeaderHasher;
use crate::Hash;
use crate::{
    pow::{
        hasher::{Hasher, PowHash},
        mem_hash::mem_hash,
    },
    proto::{RpcBlock, RpcBlockHeader},
    target::{self, Uint256},
    Error,
};
use std::error::Error as StdError;
use std::fmt;

mod hasher;
mod mem_hash;

/// Calculates the number of hash rounds based on immutable block header fields
///
/// Determines a dynamic number of rounds (1–4) using the Blake3 hash of the pre-PoW hash
/// and the block timestamp. This prevents nonce selection attacks by ensuring the round count
/// is independent of the nonce.
///
/// # Arguments
/// * `pre_pow_hash` - A 32-byte hash of the block header (excluding nonce and timestamp).
/// * `timestamp` - The block timestamp as a u64.
///
/// # Returns
/// A `usize` representing the number of rounds (1–4).
fn calculate_rounds(pre_pow_hash: [u8; 32], timestamp: u64) -> usize {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&pre_pow_hash);
    hasher.update(&timestamp.to_le_bytes());
    let hash = hasher.finalize();
    (u32::from_le_bytes(hash.as_bytes()[0..4].try_into().unwrap_or_default()) % 4 + 1) as usize
}

/// Performs XOR manipulations on adjacent bytes in 4-byte chunks
///
/// Applies XOR operations to adjacent bytes in 4-byte chunks to enhance diffusion.
///
/// # Arguments
/// * `data` - A mutable 32-byte array to manipulate.
fn bit_manipulations(data: &mut [u8; 32]) {
    for i in (0..32).step_by(4) {
        data[i] ^= data[i + 1];
        data[i + 2] ^= data[i + 3];
    }
}

/// Combines two Blake3 hashes with byte-wise XOR
///
/// # Arguments
/// * `b3_hash1` - A 32-byte Blake3 hash.
/// * `b3_hash2` - A 32-byte Blake3 hash.
///
/// # Returns
/// A 32-byte array resulting from the byte-wise XOR of the inputs.
fn byte_mixing(b3_hash1: &[u8; 32], b3_hash2: &[u8; 32]) -> [u8; 32] {
    let mut temp_buf = [0u8; 32];
    for i in 0..32 {
        temp_buf[i] = b3_hash1[i] ^ b3_hash2[i];
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
    pre_pow_hash: [u8; 32], // Store pre-PoW hash for round calculation
    timestamp: u64,         // Store timestamp for round calculation
}

impl State {
    /// Creates a new PoW state for a given block
    ///
    /// Initializes the PoW state with the block's target difficulty, pre-PoW hash,
    /// timestamp, and merkle_root. The pre-PoW hash is computed with nonce and timestamp set to 0.
    ///
    /// # Arguments
    /// * `id` - A unique identifier for the state.
    /// * `block` - The `RpcBlock` containing the block header.
    ///
    /// # Returns
    /// A `Result` containing the initialized `State` or an error if the header is missing.
    #[inline]
    pub fn new(id: usize, block: RpcBlock) -> Result<Self, Error> {
        let header = block.header.as_ref().ok_or("Header is missing")?;
        let timestamp = header.timestamp as u64; // Extract timestamp before moving block
        let target = target::u256_from_compact_target(header.bits);
        let mut hasher = HeaderHasher::new();
        serialize_header(&mut hasher, header, true);
        let pre_pow_hash = hasher.finalize();
        let hasher = PowHash::new(pre_pow_hash, timestamp);
        let mut merkle_root = [0u8; 32];
        decode_to_slice(&header.hash_merkle_root, &mut merkle_root)
            .map_err(|e| Error::from(format!("Failed to decode merkle root: {}", e)))?;

        Ok(Self { id, nonce: 0, target, block, hasher, pre_pow_hash: pre_pow_hash.as_bytes(), timestamp })
    }

    /// Computes the PoW hash for a given nonce
    ///
    /// Combines Blake3 and memory-hard hashing with a dynamic number of rounds
    /// based on the pre-PoW hash and timestamp to prevent nonce selection attacks.
    ///
    /// # Arguments
    /// * `nonce` - The nonce to include in the hash computation.
    ///
    /// # Returns
    /// A `Uint256` representing the PoW hash.
    #[inline(always)]
    pub fn calculate_pow(&self, nonce: u64) -> Uint256 {
        let hash = self.hasher.clone().finalize_with_nonce(nonce);
        let mut hash_bytes: [u8; 32] = hash.as_bytes();
        let rounds = calculate_rounds(self.pre_pow_hash, self.timestamp);

        for _ in 0..rounds {
            hash_bytes = *blake3::hash(&hash_bytes).as_bytes();
            bit_manipulations(&mut hash_bytes);
        }
        let b3_hash = hash_bytes;

        for _ in 0..rounds {
            hash_bytes = *blake3::hash(&hash_bytes).as_bytes();
            bit_manipulations(&mut hash_bytes);
        }

        let m_hash = byte_mixing(&hash_bytes, &b3_hash);
        let final_hash = mem_hash(Hash::from_le_bytes(m_hash), self.timestamp, nonce);
        Uint256::from_le_bytes(final_hash.as_bytes())
    }

    /// Verifies if the PoW hash meets the difficulty target
    ///
    /// # Arguments
    /// * `nonce` - The nonce to verify.
    ///
    /// # Returns
    /// `true` if the PoW hash is less than or equal to the target, `false` otherwise.
    #[inline(always)]
    pub fn check_pow(&self, nonce: u64) -> bool {
        let pow = self.calculate_pow(nonce);
        pow <= self.target
    }

    /// Generates a block if the current nonce satisfies the PoW
    ///
    /// # Returns
    /// An `Option<RpcBlock>` containing the block with the updated nonce if the PoW is valid,
    /// or `None` if it is not.
    #[inline(always)]
    pub fn generate_block_if_pow(&mut self) -> Option<RpcBlock> {
        self.check_pow(self.nonce).then(|| {
            let mut block = self.block.clone();
            let header = block.header.as_mut().expect("Header exists on creation");
            header.nonce = self.nonce;
            block
        })
    }
}

#[cfg(not(any(target_pointer_width = "64", target_pointer_width = "32")))]
compile_error!("Supporting only 32/64 bits");

/// Serializes a block header into a hasher
///
/// Serializes the header fields in a consistent order, optionally setting nonce and timestamp
/// to 0 for pre-PoW hashing.
///
/// # Arguments
/// * `hasher` - The hasher to update with serialized data.
/// * `header` - The block header to serialize.
/// * `for_pre_pow` - If `true`, sets nonce and timestamp to 0.
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

    let blue_work_len = header.blue_work.len().div_ceil(2);
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

#[derive(Debug)]
enum FromHexError {
    OddLength,
    InvalidStringLength,
    InvalidHexCharacter { c: char, index: usize },
}

impl fmt::Display for FromHexError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FromHexError::OddLength => write!(f, "hex string has odd length"),
            FromHexError::InvalidStringLength => write!(f, "hex string length does not match output buffer"),
            FromHexError::InvalidHexCharacter { c, index } => {
                write!(f, "invalid hex character '{}' at index {}", c, index)
            }
        }
    }
}

impl StdError for FromHexError {}

/// Decodes a hexadecimal string into a byte slice
///
/// # Arguments
/// * `data` - The hexadecimal string to decode.
/// * `out` - The output byte slice to fill.
///
/// # Returns
/// A `Result` indicating success or a `FromHexError` if decoding fails.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mem_hash() {
        let block_hash = Hash::from_le_bytes([0u8; 32]);
        let seed = 0u64;
        let nonce = 0u64;
        let result = mem_hash(block_hash, seed, nonce);
        assert_eq!(result.as_bytes().len(), 32);
    }

    #[test]
    fn test_calculate_rounds() {
        let pre_pow_hash = [0u8; 32];
        let timestamp = 0u64;
        let rounds = calculate_rounds(pre_pow_hash, timestamp);
        assert!(rounds >= 1 && rounds <= 4);
    }
}
