use crate::pow::hasher::VecnoHash;
use crate::Hash;
use blake3::Hasher as Blake3;

const HASH_MEMORY: usize = 4 * 1024; // 4KB per thread
const HASH_MEMORY_U32: usize = HASH_MEMORY / 4;

/// Memory-hard hash function
pub fn mem_hash(block_hash: Hash, seed: u64, nonce: u64) -> Hash {
    let block_hash_bytes = block_hash.as_bytes();

    // Generate S-box efficiently
    let mut sbox = [0u8; 32];
    for i in 0..32 {
        sbox[i] = block_hash_bytes[i] ^ block_hash_bytes[(i + 1) % 32] ^ block_hash_bytes[(i + 31) % 32];
    }

    // Calculate number of rounds
    let mut hasher = Blake3::new();
    hasher.update(&block_hash_bytes);
    hasher.update(&seed.to_le_bytes());
    let hash = hasher.finalize();
    let rounds = (u32::from_le_bytes(hash.as_bytes()[0..4].try_into().unwrap()) % 16 + 16) as usize;

    // Initialize result array
    let mut result = [0u32; 8];
    for i in 0..8 {
        result[i] = u32::from_le_bytes(block_hash_bytes[i * 4..i * 4 + 4].try_into().unwrap());
    }

    // Initialize memory with pseudo-random data
    let mut memory = vec![0u8; HASH_MEMORY];
    let mut hasher = Blake3::new();
    hasher.update(&block_hash_bytes);
    hasher.update(&nonce.to_le_bytes());
    let mut offset = 0;
    let mut hash = hasher.finalize();
    while offset < HASH_MEMORY {
        let bytes_to_copy = core::cmp::min(32, HASH_MEMORY - offset);
        memory[offset..offset + bytes_to_copy].copy_from_slice(&hash.as_bytes()[..bytes_to_copy]);
        offset += bytes_to_copy;
        if offset < HASH_MEMORY {
            hasher = Blake3::new();
            hasher.update(hash.as_bytes());
            hash = hasher.finalize();
        }
    }

    // Process rounds
    let operations: [fn(u32, u32) -> u32; 4] = [
        |a, b| a.wrapping_add(b),
        |a, b| a.wrapping_sub(b),
        |a, b| a.rotate_left(b & 0x1F),
        |a, b| a ^ b,
    ];

    for round in 0..rounds {
        let mut idx_hasher = Blake3::new();
        idx_hasher.update(&nonce.to_le_bytes());
        idx_hasher.update(&round.to_le_bytes());
        idx_hasher.update(&result[0].to_le_bytes());
        let round_hash = idx_hasher.finalize();
        let round_hash_bytes = round_hash.as_bytes();

        for i in 0..8 {
            // Simplified memory access
            let mem_index_base = u32::from_le_bytes(
                round_hash_bytes[(i * 4) % 28..(i * 4) % 28 + 4].try_into().unwrap(),
            ) % (HASH_MEMORY_U32 as u32);
            let mem_index = (mem_index_base as usize) * 4;

            let mut v = u32::from_le_bytes(memory[mem_index..mem_index + 4].try_into().unwrap());
            v ^= result[i];

            // Memory-dependent branching
            let branch = (v & 0xFF) as usize % 4;
            v = operations[branch](v, result[(i + 1) % 8]);

            // Apply S-box
            let b = v.to_le_bytes();
            v = u32::from_le_bytes([
                sbox[b[0] as usize & 31],
                sbox[b[1] as usize & 31],
                sbox[b[2] as usize & 31],
                sbox[b[3] as usize & 31],
            ]);

            // Update memory and result
            memory[mem_index..mem_index + 4].copy_from_slice(&v.to_le_bytes());
            result[i] = v;
        }
    }

    // Convert result to u8 array
    let mut output = [0u8; 32];
    for (i, &value) in result.iter().enumerate() {
        output[i * 4..i * 4 + 4].copy_from_slice(&value.to_le_bytes());
    }

    // Final hash
    VecnoHash::hash(Hash::from_le_bytes(output))
}