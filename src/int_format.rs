//! Read the integer format of a rift table.
//!
//! A rift table codes each value with a Huffman code of 252 symbols. Symbols 0 to 125 give a
//! value that is not negative, and symbols 126 to 251 give a negative value. A symbol from 4
//! up to 125 gives the high bits of the value, and extra bits give the low bits.

use crate::bits::BitReader;
use crate::huffman::Huffman;
use crate::prelude::*;
use crate::{Error, Result};

/// The number of symbols for each sign.
const HALF: usize = 126;
/// The number of symbols of the code.
const SYMBOLS: usize = 2 * HALF;

/// A Huffman code for signed integers.
#[derive(Debug, Clone)]
pub(crate) struct IntFormat {
    code: Huffman,
}

impl IntFormat {
    /// Read the code lengths of an integer format.
    ///
    /// The stream gives the lengths of the first symbols of each sign. The other symbols get
    /// lengths that decrease by one after a given count of symbols.
    pub(crate) fn read(reader: &mut BitReader<'_>) -> Result<Self> {
        let bad = |what: &str| Error::invalid_data(format!("bad integer format: {what}"));
        let positive = reader.bits(8)?;
        if positive > 126 {
            return Err(bad("too many positive lengths"));
        }
        let negative = reader.bits(8)?;
        if negative > 126 {
            return Err(bad("too many negative lengths"));
        }
        let mut run = reader.bits(8)?;
        if run > 252 - negative - positive {
            return Err(bad("the run is too long"));
        }
        let mut lengths = [0u8; SYMBOLS];
        // `bits(4)` is smaller than 16, so each length fits in `u8`.
        let next_length = |reader: &mut BitReader<'_>| -> Result<u8> {
            Ok(u8::try_from(reader.bits(4)? + 1).unwrap_or(16))
        };
        for length in &mut lengths[..positive as usize] {
            *length = next_length(reader)?;
        }
        for length in &mut lengths[HALF..HALF + negative as usize] {
            *length = next_length(reader)?;
        }
        let mut length = next_length(reader)?;
        // `msdelta.dll` gives the remaining positive symbols the current length. When the run
        // ends, it uses one bit less, and a new run for the remaining symbols of both signs.
        for index in positive..126 {
            if run == 0 {
                length = length
                    .checked_sub(1)
                    .ok_or_else(|| bad("a length is zero"))?;
                run = 252 - negative - index;
            } else {
                run -= 1;
            }
            lengths[index as usize] = length;
        }
        for index in negative..126 {
            if run == 0 {
                length = length
                    .checked_sub(1)
                    .ok_or_else(|| bad("a length is zero"))?;
                run = 126 - index;
            } else {
                run -= 1;
            }
            lengths[HALF + index as usize] = length;
        }
        Ok(Self {
            code: Huffman::new(&lengths)?,
        })
    }

    /// Read one signed integer.
    pub(crate) fn number(&self, reader: &mut BitReader<'_>) -> Result<i64> {
        let symbol = u32::from(self.code.read(reader)?);
        let negative = symbol >= 126;
        let slot = if negative { symbol - 126 } else { symbol };
        let mut value = u64::from(slot);
        if slot >= 4 {
            let extra = (slot >> 1) - 1;
            value = reader.bits64(extra)? | (u64::from((slot & 1) + 2) << extra);
        }
        // `slot <= 125`, so `extra <= 61` and `value < 2^63`.
        let value = i64::try_from(value).map_err(|_| Error::invalid_data("integer overflow"))?;
        Ok(if negative { !value } else { value })
    }
}
