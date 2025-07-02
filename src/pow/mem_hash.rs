use crate::Hash;
use crate::pow::hasher::VecnoHash;

/// Constants for memory-hard hashing
const H_MEM: usize = 1024 * 1024; // 1MB buffer for ASIC resistance
const H_MEM_U32: usize = H_MEM / 4; // Number of u32 elements (512K)
const H_MUL: u32 = 1664525; // LCG multiplier for pseudo-randomness
const H_INC: u32 = 1013904223; // LCG increment for good distribution

/// Generates a dynamic S-box by XORing each byte with its neighbors
fn generate_sbox(block_hash: [u8; 32]) -> [u8; 32] {
    let mut output = [0u8; 32];
    for i in 0..32 {
        output[i] = block_hash[i] ^ block_hash[(i + 1) % 32] ^ block_hash[(i + 31) % 32];
    }
    output
}

/// Fills a 1MB memory buffer with pseudo-random data using an LCG
fn fill_memory(seed: &[u8; 32], memory: &mut Vec<u8>) {
    // Ensure memory length is a multiple of 4 (since each u32 is 4 bytes)
    assert!(memory.len() % 4 == 0, "Memory length must be a multiple of 4 bytes");

    // Initialize state from the first 4 bytes of the seed
    let mut state: u32 = ((seed[0] as u32) << 24)
        | ((seed[1] as u32) << 16)
        | ((seed[2] as u32) << 8)
        | (seed[3] as u32);
    let num_elements = H_MEM_U32;

    // Treat memory as a slice of u8 and write u32 values as bytes
    for i in 0..num_elements {
        let offset = i * 4;
        state = state.wrapping_mul(H_MUL).wrapping_add(H_INC);
        memory[offset] = (state & 0xFF) as u8;
        memory[offset + 1] = ((state >> 8) & 0xFF) as u8;
        memory[offset + 2] = ((state >> 16) & 0xFF) as u8;
        memory[offset + 3] = ((state >> 24) & 0xFF) as u8;
    }
}

/// Converts a [u32; 8] array to a [u8; 32] array in little-endian order
fn u32_array_to_u8_array(input: [u32; 8]) -> [u8; 32] {
    let mut output = [0u8; 32];
    for (i, &value) in input.iter().enumerate() {
        let bytes = value.to_le_bytes();
        let offset = i * 4;
        output[offset..offset + 4].copy_from_slice(&bytes);
    }
    output
}

/// Memory-hard hash function using a 1MB buffer and dynamic S-box
pub fn mem_hash(block_hash: Hash) -> Hash {
    let mut memory = vec![0u8; H_MEM];
    let mut result = [0u32; 8];
    let block_hash_bytes = block_hash.to_le_bytes();
    let sbox: [u8; 32] = generate_sbox(block_hash_bytes);

    // Fill memory based on block_hash
    fill_memory(&block_hash_bytes, &mut memory);

    // Calculate the number of rounds [32 - 63]
    let dynamic_loops = (u32::from_le_bytes(memory[0..4].try_into().unwrap()) % 32) + 32;

    // Initial values for random indexes
    for i in 0..8 {
        let pos = i * 4;
        result[i] = u32::from_le_bytes([
            block_hash_bytes[pos],
            block_hash_bytes[pos + 1],
            block_hash_bytes[pos + 2],
            block_hash_bytes[pos + 3],
        ]);
    }

    for _ in 0..dynamic_loops {
        for i in 0..8 {
            // Get random u32 from memory
            let mem_index = result[i] % H_MEM_U32 as u32;
            let pos = mem_index as usize * 4;
            let mut v = u32::from_le_bytes([
                memory[pos],
                memory[pos + 1],
                memory[pos + 2],
                memory[pos + 3],
            ]);
            v ^= result[i];

            // Write back new value to memory at same index
            memory[pos] = (v & 0xFF) as u8;
            memory[pos + 1] = ((v >> 8) & 0xFF) as u8;
            memory[pos + 2] = ((v >> 16) & 0xFF) as u8;
            memory[pos + 3] = ((v >> 24) & 0xFF) as u8;

            // Simple sbox
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

    // Final blake3
    VecnoHash::hash(Hash::from_le_bytes(u32_array_to_u8_array(result)))
}