use core::cmp::Ordering;
use std::fmt;

pub fn u256_from_compact_target(bits: u32) -> Uint256 {
    // This is a floating-point "compact" encoding originally used by
    // OpenSSL, which satoshi put into consensus code, so we're stuck
    // with it. The exponent needs to have 3 subtracted from it, hence
    // this goofy decoding code:
    let (mant, expt) = {
        let unshifted_expt = bits >> 24;
        if unshifted_expt <= 3 {
            ((bits & 0xFFFFFF) >> (8 * (3 - unshifted_expt as usize)), 0)
        } else {
            (bits & 0xFFFFFF, 8 * ((bits >> 24) - 3))
        }
    };

    // The mantissa is signed but may not be negative
    if mant > 0x7FFFFF {
        Default::default()
    } else {
        Uint256::from_u64(mant as u64) << (expt as usize)
    }
}

/// Little-endian large integer type
#[derive(Copy, Clone, PartialEq, Eq, Hash, Default, Debug)]
pub struct Uint256(pub [u64; 4]);

impl Uint256 {
    #[inline(always)]
    pub fn new(v: [u64; 4]) -> Self {
        Self(v)
    }

    /// Create an object from a given unsigned 64-bit integer
    #[inline]
    pub fn from_u64(init: u64) -> Uint256 {
        let mut ret = [0; 4];
        ret[0] = init;
        Uint256(ret)
    }

    /// Returns the number of significant bits in the Uint256
    /// Counts the number of bits from the most significant non-zero bit.
    #[inline]
    pub fn bits(&self) -> u32 {
        let mut bits = 0;
        for (i, &word) in self.0.iter().enumerate().rev() {
            if word != 0 {
                bits = (i as u32 * 64) + (64 - word.leading_zeros());
                break;
            }
        }
        bits
    }

    #[inline(always)]
    pub fn as_bytes(&self) -> [u8; 32] {
        self.to_le_bytes()
    }

    #[inline(always)]
    pub fn from_le_bytes(bytes: [u8; 32]) -> Uint256 {
        let mut out = [0u64; 4];
        out.iter_mut()
            .zip(bytes.chunks_exact(8))
            .for_each(|(word, bytes)| *word = u64::from_le_bytes(bytes.try_into().unwrap()));
        Self(out)
    }

    #[inline(always)]
    pub fn to_le_bytes(self) -> [u8; 32] {
        let mut out = [0u8; 32];
        out.chunks_exact_mut(8).zip(self.0).for_each(|(bytes, word)| bytes.copy_from_slice(&word.to_le_bytes()));
        out
    }
}

impl fmt::LowerHex for Uint256 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.to_le_bytes().iter().try_for_each(|&c| write!(f, "{:02x}", c))
    }
}

impl PartialOrd for Uint256 {
    #[inline(always)]
    fn partial_cmp(&self, other: &Uint256) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Uint256 {
    #[inline(always)]
    fn cmp(&self, other: &Uint256) -> Ordering {
        Iterator::cmp(self.0.iter().rev(), other.0.iter().rev())
    }
}

impl core::ops::Shl<usize> for Uint256 {
    type Output = Uint256;

    fn shl(self, shift: usize) -> Uint256 {
        let Uint256(ref original) = self;
        let mut ret = [0u64; 4];
        let word_shift = shift / 64;
        let bit_shift = shift % 64;
        for i in 0..4 {
            // Shift
            if bit_shift < 64 && i + word_shift < 4 {
                ret[i + word_shift] += original[i] << bit_shift;
            }
            // Carry
            if bit_shift > 0 && i + word_shift + 1 < 4 {
                ret[i + word_shift + 1] += original[i] >> (64 - bit_shift);
            }
        }
        Uint256(ret)
    }
}

impl core::ops::Add for Uint256 {
    type Output = Uint256;

    fn add(self, rhs: Uint256) -> Uint256 {
        let mut result = [0u64; 4];
        let mut carry = 0u64;
        for i in 0..4 {
            let sum = self.0[i].wrapping_add(rhs.0[i]).wrapping_add(carry);
            result[i] = sum;
            carry = (sum < self.0[i] || (sum == self.0[i] && carry > 0)) as u64;
        }
        Uint256(result)
    }
}