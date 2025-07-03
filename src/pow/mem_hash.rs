use crate::Hash;
use crate::pow::hasher::VecnoHash;
use rand_chacha::{ChaCha20Rng, rand_core::{SeedableRng, RngCore}};
use blake3::Hasher as Blake3;
use crate::target::Uint256;

/// Calculates the dynamic memory size for memory-hard hashing
///
/// Computes a fixed 4KB memory size for normal hashes and a randomized 4MB–8MB size for close hashes
/// based on the block hash, seed, nonce, merkle_root, and target difficulty.
/// Ensures the size is a multiple of 4 bytes for u32 alignment.
///
/// # Arguments
/// * `block_hash` - A 32-byte block hash.
/// * `seed` - A 64-bit seed (e.g., timestamp).
/// * `nonce` - A 64-bit nonce for per-attempt variability.
/// * `merkle_root` - A 32-byte Merkle root of the block's transactions.
/// * `target` - The difficulty target as a Uint256.
/// * `is_close_hash` - Whether the hash is close to the target.
///
/// # Returns
/// A tuple of `(H_MEM, H_MEM_U32)` where `H_MEM` is the memory size in bytes and
/// `H_MEM_U32` is the number of u32 elements.
pub fn calculate_memory_size(
    block_hash: &[u8; 32],
    seed: u64,
    nonce: u64,
    merkle_root: &[u8; 32],
    target: &Uint256,
    is_close_hash: bool,
) -> (usize, usize) {
    if !is_close_hash {
        let h_mem = 4 * 1024;
        let h_mem_u32 = h_mem / 4;
        return (h_mem, h_mem_u32);
    }

    // Close hash: compute randomized memory size using Blake3
    let mut hasher = Blake3::new();
    hasher.update(merkle_root);
    hasher.update(block_hash);
    hasher.update(&seed.to_le_bytes());
    hasher.update(&nonce.to_le_bytes());
    hasher.update(&target.to_le_bytes());
    hasher.update(b"close_hash");
    let hash = hasher.finalize();
    let hash_bytes = hash.as_bytes();

    // Memory size for close hashes: 4MB–8MB
    let min_mem_kb = 4_000; // 4MB
    let max_mem_kb = 8_000; // 8MB
    let mem_size_kb = min_mem_kb + (u32::from_le_bytes(hash_bytes[0..4].try_into().unwrap()) % (max_mem_kb - min_mem_kb));

    let h_mem = (mem_size_kb as usize) * 1024;
    assert!(h_mem % 4 == 0, "Memory size must be a multiple of 4 bytes");
    let h_mem_u32 = h_mem / 4;
    (h_mem, h_mem_u32)
}

/// Generates a dynamic S-box using ChaCha20 and enhanced non-linear transformations
///
/// Creates a substitution box (S-box) of 32–1024 bytes by initializing with ChaCha20 pseudo-random
/// data and applying complex non-linear transformations with modular arithmetic and multiple layers.
/// Ensures no fixed points (sbox[i] != i % 256).
///
/// # Arguments
/// * `block_hash` - A 32-byte input hash used as the seed for ChaCha20.
/// * `target` - The difficulty target to determine S-box size.
///
/// # Returns
/// A Vec<u8> representing the S-box with no fixed points.
pub fn generate_sbox(block_hash: [u8; 32], target: &Uint256) -> Vec<u8> {
    let mut rng = ChaCha20Rng::from_seed(block_hash);
    
    // S-box size ranges from 32 to 256 bytes based on difficulty (integer-based scaling)
    let difficulty_factor = target.bits() as u32;
    let max_bits = 256;
    let max_sbox_size = 128; // 1KB
    let min_sbox_size = 32;
    let sbox_size = min_sbox_size + ((difficulty_factor as u64 * (max_sbox_size - min_sbox_size) as u64) / max_bits as u64) as usize;
    
    let mut output = vec![0u8; sbox_size];
    rng.fill_bytes(&mut output);

    // First layer: Non-linear transformation with modular arithmetic
    for i in 0..sbox_size {
        let next = (i + 1) % sbox_size;
        let prev = (i + sbox_size - 1) % sbox_size;
        // Incorporate modular multiplication and addition for stronger diffusion
        output[i] = output[i]
            .wrapping_add(output[next].wrapping_mul(output[prev]))
            .wrapping_add((output[i] as u16 * output[prev] as u16 % 251) as u8); // 251 is prime
    }

    // Second layer: Additional non-linear transformation
    for i in 0..sbox_size {
        let next = (i + 2) % sbox_size;
        let prev = (i + sbox_size - 2) % sbox_size;
        output[i] = output[i]
            ^ output[next]
            ^ (output[prev].rotate_left(3) as u8)
            ^ ((output[i] as u16 * output[next] as u16 % 257) as u8); // 257 is prime
    }

    // Ensure no fixed points
    for i in 0..sbox_size {
        if output[i] == (i % 256) as u8 {
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
/// * `memory` - A mutable slice to fill with pseudo-random data.
///
/// # Panics
/// Panics if the memory length is not a multiple of 4 bytes.
pub fn fill_memory(seed: &[u8; 32], memory: &mut [u8]) {
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
#[inline]
pub fn u32_array_to_u8_array(input: [u32; 8]) -> [u8; 32] {
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
/// Determines a dynamic number of rounds (16–32) based on the Blake3 hash
/// of the block hash and seed. Wider range enhances ASIC resistance.
///
/// # Arguments
/// * `block_hash` - A 32-byte block hash.
/// * `seed` - A 64-bit seed (e.g., timestamp).
///
/// # Returns
/// A `usize` representing the number of rounds (16–32).
pub fn calculate_hash_rounds(block_hash: [u8; 32], seed: u64) -> usize {
    let mut hasher = Blake3::new();
    hasher.update(&block_hash);
    hasher.update(&seed.to_le_bytes());
    let hash = hasher.finalize();
    let hash_bytes = hash.as_bytes();
    ((u32::from_le_bytes(hash_bytes[0..4].try_into().unwrap()) % 16) + 16) as usize
}

/// Initializes the result array from the block hash
///
/// Converts the 32-byte block hash into an array of 8 u32 values in little-endian order.
///
/// # Arguments
/// * `block_hash_bytes` - A 32-byte block hash.
///
/// # Returns
/// An array of 8 u32 values.
#[inline]
fn initialize_result(block_hash_bytes: &[u8; 32]) -> [u32; 8] {
    let mut result = [0u32; 8];
    for i in 0..8 {
        let pos = i * 4;
        result[i] = u32::from_le_bytes([
            block_hash_bytes[pos],
            block_hash_bytes[pos + 1],
            block_hash_bytes[pos + 2],
            block_hash_bytes[pos + 3],
        ]);
    }
    result
}

/// Applies a Feistel network transformation to the result array
///
/// Performs a Feistel round using the provided S-box for non-linear transformations.
///
/// # Arguments
/// * `result` - The current state of the result array.
/// * `sbox` - The substitution box for non-linear transformations.
fn apply_feistel_network(result: &mut [u32; 8], sbox: &[u8]) {
    let mut temp = *result;
    for i in 0..4 {
        let f = temp[i + 4].wrapping_add(sbox[(temp[i] & 0xFF) as usize % sbox.len()] as u32);
        temp[i] ^= f.rotate_left(7);
    }
    result[0..4].copy_from_slice(&temp[4..8]);
    result[4..8].copy_from_slice(&temp[0..4]);
}

/// Performs constant-time memory access for a single result element
///
/// Computes a memory-dependent value using constant-time access within a window
/// and applies a memory-dependent operation based on branching logic.
///
/// # Arguments
/// * `i` - The index of the result element being processed.
/// * `result` - The current state of the result array.
/// * `prev_v` - The previous value used for memory indexing.
/// * `nonce` - The nonce for variability in indexing.
/// * `memory` - The memory buffer.
/// * `h_mem` - The total memory size in bytes.
/// * `h_mem_u32` - The number of u32 elements in the memory.
/// * `window_elements` - The number of u32 elements in the access window.
/// * `sbox` - The substitution box for final transformation.
/// * `round_hash` - Precomputed Blake3 hash for the round (optimization).
///
/// # Returns
/// The updated value for the result element.
fn process_memory_access(
    i: usize,
    result: &[u32; 8],
    prev_v: u32,
    memory: &[u8],
    h_mem: usize,
    h_mem_u32: usize,
    window_elements: usize,
    sbox: &[u8],
    round_hash: &[u8; 32],
) -> u32 {
    // Use precomputed round hash instead of computing a new Blake3 hash
    let start_idx = (i * 4) % 28;
    let target_index = (u32::from_le_bytes(round_hash[start_idx..start_idx + 4].try_into().unwrap()) % (window_elements as u32)) as usize;

    // Constant-time memory access
    let mut v = 0u32;
    for j in 0..window_elements {
        let mem_index = if h_mem > 4 * 1024 {
            ((prev_v % (h_mem_u32 as u32)) as usize * 4 + j * 4) % h_mem
        } else {
            if i % 2 == 0 {
                ((prev_v % (h_mem_u32 as u32)) as usize * 4 + j * 4) % h_mem
            } else {
                (i * 4 + j * 4) % h_mem
            }
        };
        let current_v = u32::from_le_bytes([
            memory[mem_index],
            memory[mem_index + 1],
            memory[mem_index + 2],
            memory[mem_index + 3],
        ]);
        let mask = ((j == target_index) as u32).wrapping_neg();
        v ^= current_v & mask;
    }
    v ^= result[i];

    // Memory-dependent branching
    let branch = (v & 0xFF) as usize % 4;
    let operations: [fn(u32, u32) -> u32; 4] = [
        |a: u32, b: u32| a.wrapping_add(b),
        |a: u32, b: u32| a.wrapping_sub(b),
        |a: u32, b: u32| a.rotate_left((b & 0x1F) as u32),
        |a: u32, b: u32| a ^ b,
    ];
    v = operations[branch](v, result[(i + 1) % 8]);

    // Apply S-box
    let b: [u8; 4] = v.to_le_bytes();
    u32::from_le_bytes([
        sbox[b[0] as usize % sbox.len()],
        sbox[b[1] as usize % sbox.len()],
        sbox[b[2] as usize % sbox.len()],
        sbox[b[3] as usize % sbox.len()],
    ])
}

/// Performs additional memory access for close hashes
///
/// Computes an additional memory-dependent value for close hashes using constant-time access.
///
/// # Arguments
/// * `v` - The current value being processed.
/// * `i` - The index of the result element being processed.
/// * `nonce` - The nonce for variability in indexing.
/// * `memory` - The memory buffer.
/// * `h_mem` - The total memory size in bytes.
/// * `h_mem_u32` - The number of u32 elements in the memory.
/// * `window_elements` - The number of u32 elements in the access window.
/// * `round_hash` - Precomputed Blake3 hash for the round (optimization).
///
/// # Returns
/// The additional value to XOR with the current value.
fn extra_memory_access(
    v: u32,
    i: usize,
    memory: &[u8],
    h_mem: usize,
    h_mem_u32: usize,
    window_elements: usize,
    round_hash: &[u8; 32],
) -> u32 {
    // Use precomputed round hash, cycling within bounds
    let start_idx = ((i + 1) * 4) % 28; // Ensure index stays within 0..28 to allow 4-byte slice
    let target_extra_index = (u32::from_le_bytes(round_hash[start_idx..start_idx + 4].try_into().unwrap()) % (window_elements as u32)) as usize;

    let mut extra_v = 0u32;
    for j in 0..window_elements {
        let mem_index = ((v % (h_mem_u32 as u32)) as usize * 4 + j * 4) % h_mem;
        let current_v = u32::from_le_bytes([
            memory[mem_index],
            memory[mem_index + 1],
            memory[mem_index + 2],
            memory[mem_index + 3],
        ]);
        let mask = ((j == target_extra_index) as u32).wrapping_neg();
        extra_v ^= current_v & mask;
    }
    extra_v
}

/// Updates the memory buffer selectively based on the delta
///
/// Writes the new value to the memory buffer if the delta exceeds the threshold.
///
/// # Arguments
/// * `v` - The new value to potentially write.
/// * `result_i` - The current result value at index i.
/// * `i` - The index of the result element.
/// * `h_mem` - The total memory size in bytes.
/// * `h_mem_u32` - The number of u32 elements in the memory.
/// * `memory` - The mutable memory buffer.
fn update_memory(v: u32, result_i: u32, i: usize, h_mem: usize, h_mem_u32: usize, memory: &mut [u8]) {
    let delta = v ^ result_i;
    if delta > 0xFFFF {
        let mem_index = if h_mem > 4 * 1024 {
            ((v % (h_mem_u32 as u32)) as usize * 4) % h_mem
        } else {
            (i * 4) % h_mem
        };
        memory[mem_index] = (v & 0xFF) as u8;
        memory[mem_index + 1] = ((v >> 8) & 0xFF) as u8;
        memory[mem_index + 2] = ((v >> 16) & 0xFF) as u8;
        memory[mem_index + 3] = ((v >> 24) & 0xFF) as u8;
    }
}

/// Processes a single round of the memory-hard hash
///
/// Applies a Feistel network and memory-dependent transformations for all result elements.
///
/// # Arguments
/// * `result` - The mutable result array.
/// * `nonce` - The nonce for variability.
/// * `memory` - The memory buffer.
/// * `h_mem` - The total memory size in bytes.
/// * `h_mem_u32` - The number of u32 elements in the memory.
/// * `window_elements` - The number of u32 elements in the access window.
/// * `sbox` - The substitution box.
/// * `is_close_hash` - Whether this is a close hash (affects memory access).
fn process_round(
    result: &mut [u32; 8],
    nonce: u64,
    memory: &mut [u8],
    h_mem: usize,
    h_mem_u32: usize,
    window_elements: usize,
    sbox: &[u8],
    is_close_hash: bool,
) {
    apply_feistel_network(result, sbox);

    // Compute a single Blake3 hash for the entire round
    let mut idx_hasher = Blake3::new();
    idx_hasher.update(&nonce.to_le_bytes());
    idx_hasher.update(&result[0].to_le_bytes()); // Use first result element for entropy
    let round_hash = idx_hasher.finalize();
    let round_hash_bytes = round_hash.as_bytes();

    let mut prev_v = result[0];
    for i in 0..8 {
        let mut v = process_memory_access(
            i,
            result,
            prev_v,
            memory,
            h_mem,
            h_mem_u32,
            window_elements,
            sbox,
            round_hash_bytes, // Pass precomputed hash
        );

        if is_close_hash {
            let extra_v = extra_memory_access(v, i, memory, h_mem, h_mem_u32, window_elements, round_hash_bytes);
            v ^= extra_v;
        }

        update_memory(v, result[i], i, h_mem, h_mem_u32, memory);
        result[i] = v;
        prev_v = v;
    }
}

/// Memory-hard hash function using a dynamic memory buffer and Feistel network
///
/// Computes a memory-hard hash with a fixed 4KB memory for normal hashes and 4MB–8MB for close hashes.
/// Applies a dynamic number of rounds with memory-dependent branching, a Feistel network,
/// constant-time memory access for close hashes, and a dynamic S-box.
///
/// # Arguments
/// * `block_hash` - A 32-byte input hash to be processed.
/// * `seed` - A 64-bit seed (e.g., timestamp).
/// * `nonce` - A 64-bit nonce for per-attempt variability.
/// * `merkle_root` - A 32-byte Merkle root of the block's transactions.
/// * `target` - The difficulty target as a Uint256.
///
/// # Returns
/// A 32-byte `Hash` representing the memory-hard hash.
pub fn mem_hash(
    block_hash: Hash,
    seed: u64,
    nonce: u64,
    merkle_root: [u8; 32],
    target: &Uint256,
) -> Hash {
    // Initialize parameters
    let max_h_mem = 8 * 1024 * 1024; // 8MB max
    let (mut h_mem, mut h_mem_u32) = calculate_memory_size(&block_hash.as_bytes(), seed, nonce, &merkle_root, target, false);
    let mut memory = vec![0u8; h_mem];
    let block_hash_bytes = block_hash.as_bytes();
    let sbox = generate_sbox(block_hash_bytes, target);
    let mut result = initialize_result(&block_hash_bytes);
    let rounds = calculate_hash_rounds(block_hash_bytes, seed);
    let extra_rounds = if h_mem > 4 * 1024 { 32 } else { 0 };
    let window_elements = 64 / 4; // Number of u32 elements in 64-byte window

    // Fill initial memory
    fill_memory(&block_hash_bytes, &mut memory);

    // Initial rounds
    for _ in 0..(rounds + extra_rounds) {
        process_round(
            &mut result,
            nonce,
            &mut memory,
            h_mem,
            h_mem_u32,
            window_elements,
            &sbox,
            false,
        );
    }

    // Feedback loop for close hashes with dynamic threshold
    let preliminary_hash = Uint256::from_le_bytes(u32_array_to_u8_array(result));
    let difficulty_bits = target.bits() as u32;
    let threshold_exponent = 48 - ((difficulty_bits as u64 * 16) / 256) as u32;
    let closeness_threshold = Uint256::from_u64(1u64) << ((256 - threshold_exponent)).try_into().unwrap();
    if preliminary_hash <= *target + closeness_threshold {
        let (new_h_mem, new_h_mem_u32) = calculate_memory_size(&block_hash_bytes, seed, nonce, &merkle_root, target, true);
        if new_h_mem <= max_h_mem {
            // Resize memory and reinitialize
            memory.resize(new_h_mem, 0);
            h_mem = new_h_mem;
            h_mem_u32 = new_h_mem_u32;
            fill_memory(&block_hash_bytes, &mut memory);

            // Additional rounds for close hash
            for _ in 0..(rounds + extra_rounds) {
                process_round(
                    &mut result,
                    nonce,
                    &mut memory,
                    h_mem,
                    h_mem_u32,
                    window_elements,
                    &sbox,
                    true,
                );
            }
        }
    }

    // Final Blake3 hash
    VecnoHash::hash(Hash::from_le_bytes(u32_array_to_u8_array(result)))
}