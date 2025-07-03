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
use std::error::Error as StdError;
use std::fmt;

mod hasher;
mod mem_hash;

/// Computes SHA3-256 hash of a 32-byte input
///
/// # Arguments
/// * `input` - A 32-byte input array to hash.
///
/// # Returns
/// A `Result` containing the 32-byte SHA3-256 hash or an error if the output length is invalid.
///
/// # Errors
/// Returns an error if the SHA3-256 output cannot be converted to a 32-byte array.
fn sha3_hash(input: [u8; 32]) -> Result<[u8; 32], &'static str> {
    let mut sha3_hasher = Sha3_256::new();
    sha3_hasher.update(input);
    sha3_hasher
        .finalize()
        .as_slice()
        .try_into()
        .map_err(|_| "SHA3-256 output length mismatch")
}

/// Computes Blake3 hash of a 32-byte input
///
/// # Arguments
/// * `input` - A 32-byte input array to hash.
///
/// # Returns
/// A 32-byte Blake3 hash.
fn blake3_hash(input: [u8; 32]) -> [u8; 32] {
    *blake3::hash(&input).as_bytes() // Safe: Blake3 outputs 32 bytes
}

/// Calculates the number of hash rounds based on immutable block header fields
///
/// Determines a dynamic number of rounds (1–4) using the SHA3-256 hash of the pre-PoW hash
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
    let mut hasher = Sha3_256::new();
    hasher.update(pre_pow_hash);
    hasher.update(timestamp.to_le_bytes());
    let hash = hasher.finalize();
    (u32:: from_le_bytes(hash[0..4].try_into().unwrap_or_default()) % 4 + 1) as usize
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

/// Combines SHA3-256 and Blake3 hashes with byte-wise XOR
///
/// # Arguments
/// * `sha3_hash` - A 32-byte SHA3-256 hash.
/// * `b3_hash` - A 32-byte Blake3 hash.
///
/// # Returns
/// A 32-byte array resulting from the byte-wise XOR of the inputs.
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
    pre_pow_hash: [u8; 32], // Store pre-PoW hash for round calculation
    timestamp: u64, // Store timestamp for round calculation
    merkle_root: [u8; 32], // Store merkle_root for mem_hash
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
        decode_to_slice(&header.hash_merkle_root, &mut merkle_root).map_err(|e| Error::from(format!("Failed to decode merkle root: {}", e)))?;

        Ok(Self {
            id,
            nonce: 0,
            target,
            block,
            hasher,
            pre_pow_hash: pre_pow_hash.as_bytes().try_into().expect("Pre-PoW hash length mismatch"),
            timestamp,
            merkle_root,
        })
    }

    /// Computes the PoW hash for a given nonce
    ///
    /// Combines Blake3, SHA3-256, and memory-hard hashing with a dynamic number of rounds
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
        let mut hash_bytes: [u8; 32] = hash
            .as_bytes()
            .try_into()
            .expect("Hash output length mismatch");
        let rounds = calculate_rounds(self.pre_pow_hash, self.timestamp);
        let b3_hash: [u8; 32];

        for _ in 0..rounds {
            hash_bytes = blake3_hash(hash_bytes);
            bit_manipulations(&mut hash_bytes);
        }
        b3_hash = hash_bytes;

        for _ in 0..rounds {
            hash_bytes = sha3_hash(hash_bytes).expect("SHA3-256 failed");
            bit_manipulations(&mut hash_bytes);
        }

        let m_hash = byte_mixing(&hash_bytes, &b3_hash);
        let final_hash = mem_hash(
            Hash::from_le_bytes(m_hash), // Changed to from_bytes to match mem_hash.rs
            self.timestamp,
            nonce,
            self.merkle_root,
            &self.target,
        );
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
    let (nonce, timestamp) = if for_pre_pow {
        (0, 0)
    } else {
        (header.nonce, header.timestamp)
    };
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