//! Apply a bsdiff patch (`UpdateCompression.dll`, flag `0x2000000`).
//!
//! A PA31 delta can store the target as a bsdiff patch instead of a compressed stream. The
//! patch buffer is LZMS data in the framing of the Windows Compression API (flag `0x8000000`).
//! After decompression, the patch is one stream of commands. Each command has three 64-bit
//! numbers in sign and magnitude form, then the bytes that the command adds and copies:
//!
//! 1. Add: the count of bytes to add to the source bytes at the source position.
//! 2. Copy: the count of new bytes to copy.
//! 3. Seek: the change of the source position after the add bytes.

use crate::prelude::*;
use crate::{Error, Result};

/// The flag that selects the LZMS framing of the patch buffer.
pub(crate) const FLAG_LZMS: u64 = 0x800_0000;

/// The largest add or copy count of one command.
const MAX_COUNT: u64 = 0x7fff_ffff;

/// A reader for the command stream.
struct Stream<'a> {
    data: &'a [u8],
}

impl<'a> Stream<'a> {
    /// Take `n` bytes from the stream.
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if n > self.data.len() {
            return Err(Error::unexpected_end().in_structure("bsdiff patch"));
        }
        let (head, tail) = self.data.split_at(n);
        self.data = tail;
        Ok(head)
    }

    /// Read one number in sign and magnitude form.
    fn number(&mut self) -> Result<i64> {
        let bytes = self.take(8)?;
        let raw = u64::from_le_bytes(bytes.try_into().unwrap_or([0; 8]));
        let magnitude = (raw & !(1 << 63)).cast_signed();
        Ok(if raw >> 63 == 1 {
            magnitude.wrapping_neg()
        } else {
            magnitude
        })
    }
}

/// Apply the decompressed patch `patch` to `source`, as `bspatch` does.
pub(crate) fn bspatch(source: &[u8], patch: &[u8], target_size: usize) -> Result<Vec<u8>> {
    let bad = |what: &str| Error::invalid_data(format!("bad bsdiff command: {what}"));
    let mut stream = Stream { data: patch };
    let mut target = vec![0u8; target_size];
    let mut new_pos = 0usize;
    let mut old_pos = 0i64;
    while new_pos < target_size {
        let add = stream.number()?;
        let copy = stream.number()?;
        let seek = stream.number()?;
        let count = |value: i64| {
            u64::try_from(value)
                .ok()
                .filter(|&value| value <= MAX_COUNT)
                .and_then(|value| usize::try_from(value).ok())
                .ok_or_else(|| bad("a count is too large"))
        };
        let add_len = count(add)?;
        let copy_len = count(copy)?;
        let add_end = new_pos
            .checked_add(add_len)
            .filter(|&end| end <= target_size)
            .ok_or_else(|| bad("the add bytes end after the target"))?;
        let diff = stream.take(add_len)?;
        for (i, (out, &byte)) in target[new_pos..add_end].iter_mut().zip(diff).enumerate() {
            // `i < 2^31`, so it fits in `i64`.
            let old = old_pos
                .checked_add(i64::try_from(i).unwrap_or(i64::MAX))
                .and_then(|old| usize::try_from(old).ok())
                .and_then(|old| source.get(old));
            *out = old.map_or(byte, |&old| byte.wrapping_add(old));
        }
        let copy_end = add_end
            .checked_add(copy_len)
            .filter(|&end| end <= target_size)
            .ok_or_else(|| bad("the copy bytes end after the target"))?;
        target[add_end..copy_end].copy_from_slice(stream.take(copy_len)?);
        new_pos = copy_end;
        old_pos = old_pos
            .checked_add(add)
            .and_then(|pos| pos.checked_add(seek))
            .ok_or_else(|| bad("the source position overflows"))?;
    }
    Ok(target)
}

/// Return the largest decompressed patch that the decoder accepts for a target size: the
/// target bytes, 24 bytes of commands for each target byte and 1 MiB more.
#[cfg(feature = "lzms")]
fn patch_limit(target_size: usize) -> usize {
    target_size.saturating_mul(25).saturating_add(1 << 20)
}

/// Decompress a patch buffer in the framing of the Windows Compression API.
#[cfg(feature = "lzms")]
fn decompress(patch: &[u8], target_size: usize) -> Result<Vec<u8>> {
    lzms::decompress_buffer_with_limit(patch, patch_limit(target_size)).map_err(|e| {
        Error::invalid_data("the LZMS data of the bsdiff patch is not valid")
            .with_details(format!("{e}"))
    })
}

/// Decompress a patch buffer in the framing of the Windows Compression API.
#[cfg(not(feature = "lzms"))]
fn decompress(_patch: &[u8], _target_size: usize) -> Result<Vec<u8>> {
    Err(Error::unsupported(
        "an LZMS bsdiff patch (enable the `lzms` feature)",
    ))
}

/// Apply a bsdiff patch buffer, as `BsDiffCompressor::ApplyPatch` does.
pub(crate) fn apply(
    source: &[u8],
    patch: &[u8],
    flags: u64,
    target_size: usize,
) -> Result<Vec<u8>> {
    let commands = if patch.is_empty() {
        Vec::new()
    } else if flags & FLAG_LZMS == 0 {
        return Err(Error::unsupported("a bsdiff patch without LZMS framing"));
    } else {
        decompress(patch, target_size)?
    };
    if source.is_empty() {
        // With no source, the patch buffer holds the target.
        if commands.len() != target_size {
            return Err(Error::invalid_data(
                "the size of the bsdiff data is not the target size",
            ));
        }
        return Ok(commands);
    }
    bspatch(source, &commands, target_size)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn command(add: i64, copy: i64, seek: i64) -> Vec<u8> {
        let code = |v: i64| {
            let magnitude = v.unsigned_abs();
            (if v < 0 {
                magnitude | 1 << 63
            } else {
                magnitude
            })
            .to_le_bytes()
        };
        [code(add), code(copy), code(seek)].concat()
    }

    #[test]
    fn add_copy_and_seek_make_the_target() {
        let source = b"abcdefgh";
        let mut patch = command(3, 2, 2);
        patch.extend([0, 1, 0]);
        patch.extend(*b"XY");
        patch.extend(command(2, 0, 0));
        patch.extend([0, 0]);
        let target = bspatch(source, &patch, 7).unwrap();
        assert_eq!(
            &target,
            b"acc"
                .iter()
                .chain(b"XYfg")
                .copied()
                .collect::<Vec<_>>()
                .as_slice()
        );
    }

    #[test]
    fn a_short_patch_is_an_error() {
        assert!(bspatch(b"abc", &command(3, 0, 0), 3).is_err());
    }
}
