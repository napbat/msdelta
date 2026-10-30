//! Decode the canonical Huffman codes of the PA30 compressor.
//!
//! The compressor sends only the code length of each symbol. The decoder reads a code one bit
//! at a time, from the first bit of the code. Codes of the same length are in symbol order.
//! PA30 uses complete codes, with two exceptions: a tree with no codes, and a tree with one
//! symbol of length 1.

use crate::bits::BitReader;
use crate::prelude::*;
use crate::{Error, Result};

/// The longest code length that PA30 uses.
pub(crate) const MAX_BITS: usize = 16;

/// A canonical Huffman decoder.
#[derive(Debug, Clone)]
pub(crate) struct Huffman {
    /// For each code length minus one, the smallest code value of that length, aligned to the
    /// length.
    firsts: [u32; MAX_BITS],
    /// For each code length minus one, the index in `symbols` of the first code value.
    offsets: [i64; MAX_BITS],
    /// The symbols in code order.
    symbols: Vec<u16>,
}

impl Huffman {
    /// Build a decoder from the code length of each symbol. A length of zero means that the
    /// symbol has no code.
    ///
    /// # Errors
    ///
    /// Returns an error if a length is longer than `MAX_BITS`, or if the code is not complete.
    pub(crate) fn new(lengths: &[u8]) -> Result<Self> {
        let mut counts = [0u32; MAX_BITS + 1];
        for &len in lengths {
            let len = usize::from(len);
            if len > MAX_BITS {
                return Err(Error::invalid_data(
                    "a Huffman code length is longer than 16",
                ));
            }
            counts[len] += 1;
        }

        // A complete code uses each bit pattern at each length.
        let mut available: i64 = 1;
        for &count in &counts[1..] {
            available = available * 2 - i64::from(count);
            if available < 0 {
                return Err(Error::invalid_data("the Huffman code is over-subscribed"));
            }
        }
        // The compressor sends complete codes, a tree with no codes, or a tree with one
        // symbol of length 1. A read of an unused code is an error.
        let used = lengths.len() - counts[0] as usize;
        let single = used == 1 && counts[1] == 1;
        if available != 0 && used != 0 && !single {
            return Err(Error::invalid_data("the Huffman code is not complete"));
        }

        let mut firsts = [0u32; MAX_BITS];
        let mut sum = 0u32;
        for len in (1..=MAX_BITS).rev() {
            firsts[len - 1] = sum;
            sum = sum.midpoint(counts[len]);
        }

        let size = lengths.len();
        let mut starts = [0usize; MAX_BITS];
        let mut offsets = [0i64; MAX_BITS];
        let mut assigned = counts[0] as usize;
        for len in 0..MAX_BITS {
            assigned += counts[len + 1] as usize;
            starts[len] = size - assigned;
            offsets[len] = i64::try_from(starts[len]).unwrap_or(i64::MAX) - i64::from(firsts[len]);
        }

        let mut symbols = vec![0u16; size];
        for (symbol, &len) in lengths.iter().enumerate() {
            if len > 0 {
                let slot = &mut starts[usize::from(len) - 1];
                symbols[*slot] = u16::try_from(symbol)
                    .map_err(|_| Error::invalid_data("a Huffman tree has too many symbols"))?;
                *slot += 1;
            }
        }

        Ok(Self {
            firsts,
            offsets,
            symbols,
        })
    }

    /// Build a decoder with the default lengths for `size` symbols.
    ///
    /// The default code gives each symbol the same weight. The lower symbols get the shorter
    /// codes if `size` is not a power of two.
    pub(crate) fn default_lengths(size: usize) -> Vec<u8> {
        if size <= 2 {
            return vec![1; size];
        }
        let len = u8::try_from((size - 1).ilog2() + 1).unwrap_or(u8::MAX);
        let shorter = (1usize << len) - size;
        let mut lengths = vec![len - 1; shorter];
        lengths.resize(size, len);
        lengths
    }

    /// Read one symbol.
    ///
    /// # Errors
    ///
    /// Returns an error if the stream ends inside a code.
    #[inline]
    pub(crate) fn read(&self, reader: &mut BitReader<'_>) -> Result<u16> {
        let (mut bits, fill) = reader.peek();
        let mut code = 0u32;
        let mut used = 0u32;
        for (len, &first) in self.firsts.iter().enumerate() {
            code |= u32::from(bits & 1 == 1);
            bits >>= 1;
            used += 1;
            if code >= first {
                if used > fill {
                    return Err(Error::unexpected_end());
                }
                reader.consume(used);
                let index = self.offsets[len] + i64::from(code);
                return usize::try_from(index)
                    .ok()
                    .and_then(|index| self.symbols.get(index))
                    .copied()
                    .ok_or_else(|| Error::invalid_data("bad Huffman code"));
            }
            code <<= 1;
        }
        Err(Error::invalid_data("bad Huffman code"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_lengths_give_complete_codes() {
        for size in [1usize, 2, 3, 16, 39, 256, 600] {
            let lengths = Huffman::default_lengths(size);
            assert_eq!(lengths.len(), size);
            if size > 1 {
                Huffman::new(&lengths).unwrap();
            }
        }
        assert_eq!(Huffman::default_lengths(600)[..424], [9; 424]);
        assert_eq!(Huffman::default_lengths(600)[424..], [10; 176]);
    }

    #[test]
    fn only_the_code_shapes_of_the_compressor_are_valid() {
        assert!(Huffman::new(&[1, 2]).is_err(), "incomplete");
        assert!(Huffman::new(&[1, 1, 1]).is_err(), "over-subscribed");
        assert!(Huffman::new(&[0, 0, 0]).is_ok(), "no codes");
        assert!(Huffman::new(&[0, 1, 0]).is_ok(), "one symbol");
    }
}
