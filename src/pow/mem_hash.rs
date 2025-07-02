use crate::Hash;
use crate::pow::hasher::VecnoHash;
use rand_chacha::{ChaCha20Rng, rand_core::{SeedableRng, RngCore}};
use sha3::{Digest, Sha3_256};

/// Calculates the dynamic memory size for memory-hard hashing
///
/// Computes a memory size between 64KB and 256KB based on the block hash and seed.
/// Ensures the size is a multiple of 4 bytes for u32 alignment.
///
/// # Arguments
/// * `block_hash` - A 32-byte block hash.
/// * `seed` - A 64-bit seed (e.g., timestamp).
///
/// # Returns
/// A tuple of `(H_MEM, H_MEM_U32)` where `H_MEM` is the memory size in bytes and
/// `H_MEM_U32` is the number of u32 elements.
fn calculate_memory_size(block_hash: &[u8; 32], seed: u64) -> (usize, usize) {
    let mut hasher = Sha3_256::new();
    hasher.update(block_hash);
    hasher.update(seed.to_le_bytes());
    let hash = hasher.finalize();
    let mem_size_kb = 64 + (u32::from_le_bytes(hash[0..4].try_into().unwrap()) % 192); // 64KB to 256KB
    let h_mem = (mem_size_kb as usize) * 1024;
    assert!(h_mem % 4 == 0, "Memory size must be a multiple of 4 bytes");
    let h_mem_u32 = h_mem / 4;
    (h_mem, h_mem_u32)
}

/// Generates a dynamic S-box using ChaCha20 and non-linear transformations
///
/// Creates a 32-byte substitution box (S-box) by initializing with ChaCha20 pseudo-random
/// data and applying non-linear transformations to enhance ASIC resistance. Ensures no fixed
/// points (i.e., sbox[i] != i) to improve cryptographic strength.
///
/// # Arguments
/// * `block_hash` - A 32-byte input hash used as the seed for ChaCha20.
///
/// # Returns
/// A 32-byte array representing the S-box with no fixed points.
fn generate_sbox(block_hash: [u8; 32]) -> [u8; 32] {
    let mut rng = ChaCha20Rng::from_seed(block_hash);
    let mut output = [0u8; 32];
    rng.fill_bytes(&mut output);

    for i in 0..32 {
        // Non-linear transformation: mix with polynomial and rotate
        output[i] = output[i]
            ^ output[(i + 1) % 32]
            ^ output[(i + 31) % 32]
            ^ output[i].wrapping_mul(output[i]);
    }

    // Ensure no fixed points (sbox[i] != i)
    for i in 0..32 {
        if output[i] == i as u8 {
            output[i] ^= 0xFF;
        }
    }

    output
}

/// Fills a memory buffer with pseudo-random data using ChaCha20
///
/// Initializes a memory buffer with pseudo-random data derived from a 32-byte seed using
/// ChaCha20, ensuring the buffer size is a multiple of 4 bytes for u32 alignment.
///
/// # Arguments
/// * `seed` - A 32-byte seed for the ChaCha20 RNG.
/// * `memory` - A mutable vector to fill with pseudo-random data.
///
/// # Panics
/// Panics if the memory length is not a multiple of 4 bytes.
fn fill_memory(seed: &[u8; 32], memory: &mut Vec<u8>) {
    assert!(memory.len() % 4 == 0, "Memory length must be a multiple of 4 bytes");

    let mut rng = ChaCha20Rng::from_seed(*seed);
    let num_elements = memory.len() / 4;

    for i in 0..num_elements {
        let offset = i * 4;
        let mut v = [0u8; 4];
        rng.fill_bytes(&mut v);
        memory[offset..offset + 4].copy_from_slice(&v);
    }
}

/// Converts a [u32; 8] array to a [u8; 32] array in little-endian order
///
/// Transforms an array of 8 u32 values into a 32-byte array, with each u32 converted
/// to 4 bytes in little-endian order.
///
/// # Arguments
/// * `input` - An array of 8 u32 values.
///
/// # Returns
/// A 32-byte array in little-endian order.
fn u32_array_to_u8_array(input: [u32; 8]) -> [u8; 32] {
    let mut output = [0u8; 32];
    for (i, &value) in input.iter().enumerate() {
        let bytes = value.to_le_bytes();
        let offset = i * 4;
        output[offset..offset + 4].copy_from_slice(&bytes);
    }
    output
}

/// Calculates the number of rounds for memory-hard hashing
///
/// Determines a dynamic number of rounds (between 32 and 64) based on the SHA3-256 hash
/// of the block hash and an additional seed (e.g., timestamp). This ensures the round count
/// is deterministic but not manipulable by nonce selection, enhancing ASIC resistance.
///
/// # Arguments
/// * `block_hash` - A 32-byte block hash.
/// * `seed` - A 64-bit seed (e.g., timestamp) to incorporate into the round calculation.
///
/// # Returns
/// A `usize` representing the number of rounds (32–64).
fn calculate_hash_rounds(block_hash: [u8; 32], seed: u64) -> usize {
    let mut hasher = Sha3_256::new();
    hasher.update(block_hash);
    hasher.update(seed.to_le_bytes());
    let hash = hasher.finalize();
    ((u32::from_le_bytes(hash[0..4].try_into().unwrap()) % 32) + 32) as usize
}

/// Memory-hard hash function using a dynamic memory buffer and Feistel network
///
/// Computes a memory-hard hash by filling a dynamically-sized buffer (64KB–256KB) with
/// ChaCha20-derived data, applying a dynamic number of transformation rounds with memory-dependent
/// branching and a Feistel network, and finalizing with a Blake3 hash. The memory size and
/// number of rounds are dynamically determined to enhance ASIC resistance.
///
/// # Arguments
/// * `block_hash` - A 32-byte input hash to be processed.
/// * `seed` - A 64-bit seed (e.g., timestamp) to determine the number of rounds and memory size.
///
/// # Returns
/// A 32-byte `Hash` representing the memory-hard hash of the input.
pub fn mem_hash(block_hash: Hash, seed: u64) -> Hash {
    // Calculate dynamic memory size
    let (h_mem, h_mem_u32) = calculate_memory_size(&block_hash.as_bytes(), seed);
    let mut memory = vec![0u8; h_mem];
    let mut result = [0u32; 8];
    let block_hash_bytes = block_hash.as_bytes();
    let sbox: [u8; 32] = generate_sbox(block_hash_bytes);

    // Fill memory based on block_hash
    fill_memory(&block_hash_bytes, &mut memory);

    // Calculate dynamic rounds
    let rounds = calculate_hash_rounds(block_hash_bytes, seed);

    // Initialize result from block_hash
    for i in 0..8 {
        let pos = i * 4;
        result[i] = u32::from_le_bytes([
            block_hash_bytes[pos],
            block_hash_bytes[pos + 1],
            block_hash_bytes[pos + 2],
            block_hash_bytes[pos + 3],
        ]);
    }

    for _ in 0..rounds {
        // Feistel network for increased diffusion
        {
            let mut temp = result; // Create a temporary copy to avoid borrow issues
            for i in 0..4 {
                let f = temp[i + 4].wrapping_add(sbox[(temp[i] & 0xFF) as usize % 32] as u32);
                temp[i] ^= f.rotate_left(7);
            }
            // Swap halves
            result[0..4].copy_from_slice(&temp[4..8]);
            result[4..8].copy_from_slice(&temp[0..4]);
        }

        // Memory-hard round with dynamic indexing
        for i in 0..8 {
            let mem_index = (result[i] % h_mem_u32 as u32) as usize * 4;
            let mut v = u32::from_le_bytes([
                memory[mem_index],
                memory[mem_index + 1],
                memory[mem_index + 2],
                memory[mem_index + 3],
            ]);
            v ^= result[i];

            // Memory-dependent branching
            let branch = (v & 0xFF) as usize % 4;
            match branch {
                0 => v = v.wrapping_add(result[(i + 1) % 8]),
                1 => v = v.wrapping_sub(result[(i + 7) % 8]),
                2 => v = v.rotate_left((result[i] & 0x1F) as u32),
                3 => v = v ^ result[(i + 3) % 8],
                _ => unreachable!(),
            }

            // Write back to memory
            memory[mem_index] = (v & 0xFF) as u8;
            memory[mem_index + 1] = ((v >> 8) & 0xFF) as u8;
            memory[mem_index + 2] = ((v >> 16) & 0xFF) as u8;
            memory[mem_index + 3] = ((v >> 24) & 0xFF) as u8;

            // Apply S-box
            let b: [u8; 4] = v.to_le_bytes();
            v = u32::from_le_bytes([
                sbox[b[0] as usize % 32],
                sbox[b[1] as usize % 32],
                sbox[b[2] as usize % 32],
                sbox[b[3] as usize % 32],
            ]);
            result[i] = v;
        }
    }

    // Final Blake3 hash
    VecnoHash::hash(Hash::from_le_bytes(u32_array_to_u8_array(result)))
}