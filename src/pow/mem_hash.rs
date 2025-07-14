use crate::pow::hasher::VecnoHash;
use crate::Hash;
use blake3::Hasher as Blake3;

// Constants for memory sizes and S-box bounds
const HASH_MEMORY: usize = 4 * 1024; // 4KB per thread
const HASH_MEMORY_U32: usize = HASH_MEMORY / 4;
const WINDOW_ELEMENTS: usize = 32 / 4; // 8 u32 elements

/// Memory-hard hash function
pub fn mem_hash(block_hash: Hash, seed: u64, nonce: u64) -> Hash {
    let block_hash_bytes = block_hash.as_bytes();

    // Generate S-box
    let mut sbox = [0u8; 32];
    for i in 0..32 {
        sbox[i] = block_hash_bytes[i] ^ block_hash_bytes[(i + 1) % 32] ^ block_hash_bytes[(i + 31) % 32];
    }

    // Calculate number of rounds
    let mut hasher = Blake3::new();
    hasher.update(&block_hash_bytes);
    hasher.update(&seed.to_le_bytes());
    let hash = hasher.finalize();
    let rounds = ((u32::from_le_bytes(hash.as_bytes()[0..4].try_into().unwrap()) % 16) + 16) as usize;

    // Initialize result array
    let mut result = [0u32; 8];
    for i in 0..8 {
        result[i] = u32::from_le_bytes(block_hash_bytes[i * 4..i * 4 + 4].try_into().unwrap());
    }

    // Fill memory with pseudo-random data using Blake3
    let mut memory = vec![0u8; HASH_MEMORY];
    let mut hasher = Blake3::new();
    hasher.update(&block_hash_bytes);
    let mut offset = 0;
    while offset < memory.len() {
        hasher.update(&(offset as u64).to_le_bytes());
        let hash = hasher.finalize();
        let bytes_to_copy = core::cmp::min(32, memory.len() - offset);
        memory[offset..offset + bytes_to_copy].copy_from_slice(&hash.as_bytes()[..bytes_to_copy]);
        offset += bytes_to_copy;
    }

    // Process rounds
    for _ in 0..rounds {
        // Generate round hash
        let mut idx_hasher = Blake3::new();
        idx_hasher.update(&nonce.to_le_bytes());
        idx_hasher.update(&result[0].to_le_bytes());
        let round_hash = idx_hasher.finalize();
        let round_hash_bytes = round_hash.as_bytes();

        for i in 0..8 {
            // Process memory access
            let start_idx = (i * 4) % 28;
            let target_index = (u32::from_le_bytes(round_hash_bytes[start_idx..start_idx + 4].try_into().unwrap())
                % (WINDOW_ELEMENTS as u32)) as usize;

            let mut v = 0u32;
            for j in 0..WINDOW_ELEMENTS {
                // Use round hash to generate a random memory index
                let hash_idx = (i * 4 + j) % 28;
                let mem_index_base = u32::from_le_bytes(round_hash_bytes[hash_idx..hash_idx + 4].try_into().unwrap())
                    % (HASH_MEMORY_U32 as u32);
                let mem_index = (mem_index_base as usize * 4 + j * 4) % HASH_MEMORY;

                let current_v = u32::from_le_bytes(memory[mem_index..mem_index + 4].try_into().unwrap());
                let mask = ((j == target_index) as u32).wrapping_neg();
                v ^= current_v & mask;
            }
            v ^= result[i];

            // Memory-dependent branching
            let branch = (v & 0xFF) as usize % 4;
            let operations: [fn(u32, u32) -> u32; 4] =
                [|a, b| a.wrapping_add(b), |a, b| a.wrapping_sub(b), |a, b| a.rotate_left(b & 0x1F), |a, b| a ^ b];
            v = operations[branch](v, result[(i + 1) % 8]);

            // Apply S-box
            let b = v.to_le_bytes();
            v = u32::from_le_bytes([
                sbox[b[0] as usize % sbox.len()],
                sbox[b[1] as usize % sbox.len()],
                sbox[b[2] as usize % sbox.len()],
                sbox[b[3] as usize % sbox.len()],
            ]);

            // Update memory unconditionally
            let mem_index = (u32::from_le_bytes(round_hash_bytes[(i * 4) % 28..(i * 4) % 28 + 4].try_into().unwrap())
                % (HASH_MEMORY_U32 as u32)) as usize
                * 4
                % HASH_MEMORY;
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
