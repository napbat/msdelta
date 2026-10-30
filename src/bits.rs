//! Read a PA30 bitstream.
//!
//! A PA30 bitstream stores bits LSB first. The first three bits give the number of padding bits
//! in the last byte. The stream codes integers as a count of nibbles followed by the nibbles,
//! and buffers as an integer size, padding to a byte boundary, and the bytes.

use crate::{Error, Result};

/// A reader for one PA30 bitstream.
#[derive(Debug, Clone)]
pub(crate) struct BitReader<'a> {
    data: &'a [u8],
    /// The index of the next byte to load into `value`.
    pos: usize,
    /// The loaded bits. Bit 0 is the next bit.
    value: u64,
    /// The number of valid bits in `value`.
    fill: u32,
    /// The number of padding bits in the last byte.
    pad: u32,
}

impl<'a> BitReader<'a> {
    /// Open a bitstream, and read its 3-bit padding count.
    ///
    /// # Errors
    ///
    /// Returns an error if `data` is empty, or if the padding is longer than the stream.
    pub(crate) fn new(data: &'a [u8]) -> Result<Self> {
        let mut reader = Self {
            data,
            pos: 0,
            value: 0,
            fill: 0,
            pad: 0,
        };
        let pad = reader.bits(3)?;
        reader.pad = pad;
        if reader.pos == data.len() {
            // The last byte is already loaded: remove its padding now.
            reader.fill = reader
                .fill
                .checked_sub(pad)
                .ok_or_else(|| Error::invalid_data("the padding is longer than the stream"))?;
        }
        Ok(reader)
    }

    /// Load bytes until `value` has at least 57 bits or the stream ends.
    #[inline]
    fn refill(&mut self) {
        while self.fill <= 56 {
            let Some(&byte) = self.data.get(self.pos) else {
                break;
            };
            self.value |= u64::from(byte) << self.fill;
            self.fill += 8;
            self.pos += 1;
            if self.pos == self.data.len() {
                // The padding of a stream with one byte is removed in `new`.
                self.fill = self.fill.saturating_sub(self.pad);
            }
        }
    }

    /// Return the loaded bits and the number of valid bits, after a refill.
    #[inline]
    pub(crate) fn peek(&mut self) -> (u64, u32) {
        self.refill();
        (self.value, self.fill)
    }

    /// Consume `n` bits that [`Self::peek`] returned.
    #[inline]
    pub(crate) fn consume(&mut self, n: u32) {
        debug_assert!(n <= self.fill);
        self.value = self.value.checked_shr(n).unwrap_or(0);
        self.fill -= n;
    }

    /// Read `n` bits, with `n <= 32`.
    #[inline]
    pub(crate) fn bits(&mut self, n: u32) -> Result<u32> {
        debug_assert!(n <= 32);
        if n == 0 {
            return Ok(0);
        }
        self.refill();
        if self.fill < n {
            return Err(Error::unexpected_end());
        }
        // `n <= 32`, so the masked value fits in `u32`.
        let value = u32::try_from(self.value & ((1u64 << n) - 1)).unwrap_or_default();
        self.consume(n);
        Ok(value)
    }

    /// Read one bit as a `bool`.
    #[inline]
    pub(crate) fn bit(&mut self) -> Result<bool> {
        Ok(self.bits(1)? == 1)
    }

    /// Read a number of at most `max_nibbles` nibbles.
    fn number_with(&mut self, max_nibbles: u32) -> Result<u64> {
        let mut nibbles = 1;
        while !self.bit()? {
            nibbles += 1;
            if nibbles > max_nibbles {
                return Err(Error::invalid_data("a number has too many nibbles"));
            }
        }
        let bits = nibbles * 4;
        let low = u64::from(self.bits(bits.min(32))?);
        let high = if bits > 32 {
            u64::from(self.bits(bits - 32)?)
        } else {
            0
        };
        Ok(low | (high << 32))
    }

    /// Read a 32-bit number.
    pub(crate) fn number(&mut self) -> Result<u32> {
        u32::try_from(self.number_with(8)?).map_err(|_| Error::invalid_data("number overflow"))
    }

    /// Read a 64-bit number.
    pub(crate) fn number64(&mut self) -> Result<u64> {
        self.number_with(16)
    }

    /// Read the long match length coding: `z` zero bits, a one bit, then `z + 8` bits under an
    /// implicit leading one bit.
    pub(crate) fn long_length(&mut self) -> Result<u32> {
        let mut zeros = 0;
        while !self.bit()? {
            zeros += 1;
            if zeros >= 24 {
                return Err(Error::invalid_data("a match length is too long"));
            }
        }
        let len = zeros + 8;
        Ok((1 << len) | self.bits(len)?)
    }

    /// Read a buffer: a 64-bit size, padding to the next byte boundary, and the bytes.
    pub(crate) fn buffer(&mut self) -> Result<&'a [u8]> {
        let len = usize::try_from(self.number64()?)
            .map_err(|_| Error::invalid_data("buffer size overflow"))?;
        // Round the consumed bits up to the next byte boundary.
        let loaded_pad = if self.pos == self.data.len() {
            self.pad
        } else {
            0
        };
        let consumed = self.pos * 8 - (self.fill + loaded_pad) as usize;
        let start = consumed.div_ceil(8);
        let end = start
            .checked_add(len)
            .filter(|&end| end <= self.data.len())
            .ok_or_else(Error::unexpected_end)?;
        self.pos = end;
        self.value = 0;
        self.fill = 0;
        Ok(&self.data[start..end])
    }

    /// Return the number of unread bits.
    pub(crate) fn bits_left(&self) -> u64 {
        let unloaded = (self.data.len() - self.pos) * 8;
        let pad = if self.pos < self.data.len() {
            self.pad as usize
        } else {
            0
        };
        u64::from(self.fill) + (unloaded - pad) as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numbers_use_the_nibble_count_prefix() {
        // The example of the format notes: padding 1, then 14, then 17.
        let mut reader = BitReader::new(&[0xe9, 0x46, 0x00]).unwrap();
        assert_eq!(reader.number().unwrap(), 14);
        assert_eq!(reader.number().unwrap(), 17);
    }
}
