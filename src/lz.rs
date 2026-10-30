//! Decode the compressed target of a PA30 patch buffer.
//!
//! The compressor is an LZX variant. It uses a window that starts with the source, and appends
//! the target. A match copies from the window behind the output position (a distance), from
//! the source at the position that the rift table gives, or from the last three distances.
//!
//! The compression parameters ("composite format") give one or more blocks. Each block starts
//! at a window position and has three Huffman trees: the main tree (600 symbols), the length
//! tree (256 symbols) and the aligned offset tree (16 symbols).

use crate::bits::BitReader;
use crate::huffman::Huffman;
use crate::prelude::*;
use crate::{Error, Result};

/// The number of symbols of the main tree.
const MAIN_SYMBOLS: usize = 0x258;
/// The number of symbols of the length tree.
const LENGTH_SYMBOLS: usize = 0x100;
/// The number of symbols of the aligned offset tree.
const ALIGNED_SYMBOLS: usize = 0x10;
/// The number of code lengths of one block.
const BLOCK_LENGTHS: usize = MAIN_SYMBOLS + LENGTH_SYMBOLS + ALIGNED_SYMBOLS;
/// The number of symbols of the pre-tree that codes the block code lengths.
const PRETREE_SYMBOLS: usize = 39;

/// One block of compression parameters.
#[derive(Debug, Clone)]
struct Block {
    /// The window position where the block starts.
    start: u64,
    /// The code lengths of the three trees.
    lengths: Vec<u8>,
}

/// The three Huffman trees of a block.
#[derive(Debug, Clone)]
struct Trees {
    main: Huffman,
    length: Huffman,
    aligned: Huffman,
}

impl Trees {
    fn new(lengths: &[u8]) -> Result<Self> {
        let (main, rest) = lengths.split_at(MAIN_SYMBOLS);
        let (length, aligned) = rest.split_at(LENGTH_SYMBOLS);
        Ok(Self {
            main: Huffman::new(main)?,
            length: Huffman::new(length)?,
            aligned: Huffman::new(aligned)?,
        })
    }
}

/// Read the compression parameters.
fn read_blocks(reader: &mut BitReader<'_>) -> Result<Vec<Block>> {
    if reader.bit()? {
        let mut lengths = Huffman::default_lengths(MAIN_SYMBOLS);
        lengths.extend(Huffman::default_lengths(LENGTH_SYMBOLS));
        lengths.extend(Huffman::default_lengths(ALIGNED_SYMBOLS));
        return Ok(vec![Block { start: 0, lengths }]);
    }

    let count = reader.number()?;
    if count == 0 {
        return Err(Error::invalid_data("the composite format has no blocks"));
    }
    // Each block needs at least one bit, so the count cannot be larger than the stream.
    if u64::from(count) > reader.bits_left() {
        return Err(Error::unexpected_end());
    }
    let mut starts = Vec::with_capacity(count as usize);
    let mut start = 0u64;
    for _ in 0..count {
        start = start
            .checked_add(reader.number64()?)
            .ok_or_else(|| Error::invalid_data("block start overflow"))?;
        starts.push(start);
    }

    let mut pretree = [0u8; PRETREE_SYMBOLS];
    for length in &mut pretree {
        *length = u8::try_from(reader.bits(4)?).unwrap_or_default();
    }
    let pretree = Huffman::new(&pretree)?;

    let mut blocks: Vec<Block> = Vec::with_capacity(starts.len());
    let empty = [0u8; BLOCK_LENGTHS];
    for start in starts {
        let previous = blocks.last().map_or(&empty[..], |block| &block.lengths);
        let lengths = read_lengths(reader, &pretree, previous)?;
        blocks.push(Block { start, lengths });
    }
    Ok(blocks)
}

/// Read the code lengths of one block. The coding refers to the lengths of the previous block.
fn read_lengths(reader: &mut BitReader<'_>, pretree: &Huffman, previous: &[u8]) -> Result<Vec<u8>> {
    let bad = || Error::invalid_data("bad code length coding");
    let mut lengths = vec![0u8; BLOCK_LENGTHS];
    let mut i = 0;
    while i < BLOCK_LENGTHS {
        let symbol = u8::try_from(pretree.read(reader)?).map_err(|_| bad())?;
        match symbol {
            0..=16 => {
                lengths[i] = symbol;
                i += 1;
            }
            17..=19 => {
                let value = previous[i] + (symbol - 16);
                if value > 16 {
                    return Err(bad());
                }
                lengths[i] = value;
                i += 1;
            }
            20..=22 => {
                lengths[i] = previous[i].checked_sub(symbol - 19).ok_or_else(bad)?;
                i += 1;
            }
            _ => {
                let code = u32::from(symbol - 23) & 7;
                let run = if code < 3 {
                    code as usize + 1
                } else {
                    ((1 << (code - 1)) | reader.bits(code - 1)?) as usize
                };
                let end = i
                    .checked_add(run)
                    .filter(|&end| end <= BLOCK_LENGTHS)
                    .ok_or_else(bad)?;
                if symbol < 31 {
                    let fill = *lengths.get(i.wrapping_sub(1)).ok_or_else(bad)?;
                    lengths[i..end].fill(fill);
                } else {
                    lengths[i..end].copy_from_slice(&previous[i..end]);
                }
                i = end;
            }
        }
    }
    Ok(lengths)
}

/// One decoded match.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Match {
    /// One literal byte.
    Literal(u8),
    /// A copy from the source, at the rift position of the output position minus `delta`.
    Source { delta: i64, length: u64 },
    /// A copy from the source at the rift position of the output position.
    FullSource { length: u64 },
    /// A copy at a distance from the last three distances.
    Repeat { index: usize, length: u64 },
    /// A copy from the window, `distance` bytes behind the output position.
    Window { distance: u64, length: u64 },
}

/// The copy part of a match, before the decoder reads the length.
enum Kind {
    Source(i64),
    FullSource,
    Repeat(usize),
    Window(u64),
}

/// Read one match.
fn read_match(reader: &mut BitReader<'_>, trees: &Trees) -> Result<Match> {
    let symbol = trees.main.read(reader)?;
    if let Ok(byte) = u8::try_from(symbol) {
        return Ok(Match::Literal(byte));
    }
    let symbol = u32::from(symbol - 256);
    let mut slot = symbol >> 3;
    let short_length = symbol & 7;

    let kind = match slot {
        0 => Kind::Source(i64::from(reader.bits(14)?) - 0x2000),
        1 => {
            let raw = i64::from(reader.bits(16)?) - 0x8000;
            Kind::Source(if raw < 0 { raw - 0x2000 } else { raw + 0x2000 })
        }
        2 => {
            let raw = i64::from(reader.bits(18)?) - 0x2_0000;
            Kind::Source(if raw < 0 { raw - 0xa000 } else { raw + 0xa000 })
        }
        3 => Kind::FullSource,
        4..=6 => Kind::Repeat((slot - 4) as usize),
        8..=10 => Kind::Window(u64::from(slot - 7)),
        _ => {
            if slot == 7 {
                // Slots 43 to 70: 0xx, 10xxx or 11xxxx, LSB first.
                let (base, bits) = if reader.bit()? {
                    if reader.bit()? { (55, 4) } else { (47, 3) }
                } else {
                    (43, 2)
                };
                slot = base + reader.bits(bits)?;
            }
            let verbatim = (slot - 9) >> 1;
            let top = 2 | ((slot - 11) & 1);
            let mut distance = u64::from(top) << verbatim;
            if verbatim < 4 {
                distance |= u64::from(reader.bits(verbatim)?);
            } else {
                distance |= u64::from(reader.bits(verbatim - 4)?) << 4;
                distance |= u64::from(trees.aligned.read(reader)?);
            }
            Kind::Window(distance)
        }
    };

    let length = if short_length == 0 {
        let bits = trees.length.read(reader)?;
        if bits == 0 {
            u64::from(reader.long_length()?) + 8
        } else {
            u64::from(bits) + 8
        }
    } else {
        u64::from(short_length) + 1
    };

    Ok(match kind {
        Kind::Source(delta) => Match::Source { delta, length },
        Kind::FullSource => Match::FullSource { length },
        Kind::Repeat(index) => Match::Repeat { index, length },
        Kind::Window(distance) => Match::Window { distance, length },
    })
}

/// Move `distance` to the front of the list of the last three distances.
fn update_repeats(repeats: &mut [u64; 3], distance: u64) {
    if repeats[0] == distance {
        return;
    }
    if repeats[1] != distance {
        repeats[2] = repeats[1];
    }
    repeats[1] = repeats[0];
    repeats[0] = distance;
}

/// Append `length` bytes from window position `start` to `out`. The window is `source`
/// followed by `out`. The copy can overlap the bytes that it appends.
fn copy_window(source: &[u8], out: &mut Vec<u8>, start: usize, length: usize) {
    let mut start = start;
    let mut length = length;
    if start < source.len() {
        let take = length.min(source.len() - start);
        out.extend_from_slice(&source[start..start + take]);
        start += take;
        length -= take;
    }
    if length == 0 {
        return;
    }
    let mut from = start - source.len();
    while length > 0 {
        // Copy at most the bytes that exist now; an overlapping copy repeats them.
        let take = length.min(out.len() - from);
        out.extend_from_within(from..from + take);
        from += take;
        length -= take;
    }
}

/// Decode the target from a patch buffer.
///
/// The decoder supports the patch buffers of raw data: an empty base rift table, and an
/// identity mapping from target positions to source positions.
pub(crate) fn decode(patch: &[u8], source: &[u8], target_size: usize) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(target_size.min(patch.len().saturating_mul(64)));
    if target_size == 0 && patch.is_empty() {
        return Ok(out);
    }
    let mut reader = BitReader::new(patch)?;
    if reader.bit()? {
        return Err(Error::unsupported("a non-empty base rift table"));
    }
    let blocks = read_blocks(&mut reader)?;

    let mut next_block = 0;
    let mut trees: Option<Trees> = None;
    let mut repeats = [0u64; 3];
    let base = source.len();

    while out.len() < target_size {
        let target_pos = out.len();
        let window_pos = base
            .checked_add(target_pos)
            .ok_or_else(|| Error::invalid_data("the window is too large"))?;
        let window_pos64 = window_pos as u64;
        while let Some(block) = blocks.get(next_block).filter(|b| b.start <= window_pos64) {
            trees = Some(Trees::new(&block.lengths)?);
            next_block += 1;
        }
        let trees = trees
            .as_ref()
            .ok_or_else(|| Error::invalid_data("no compression block covers the output"))?;

        let remaining = target_size - target_pos;
        let checked_length = |length: u64| {
            usize::try_from(length)
                .ok()
                .filter(|&length| length <= remaining)
                .ok_or_else(|| Error::invalid_data("a match is longer than the target"))
        };
        // A window start is before `window_pos`, so it fits in `usize`.
        let window_start = |distance: u64| {
            window_pos64
                .checked_sub(distance)
                .filter(|_| distance > 0)
                .and_then(|start| usize::try_from(start).ok())
                .ok_or_else(|| Error::invalid_data("a match distance is outside the window"))
        };

        match read_match(&mut reader, trees)? {
            Match::Literal(byte) => out.push(byte),
            Match::Window { distance, length } => {
                let length = checked_length(length)?;
                let start = window_start(distance)?;
                update_repeats(&mut repeats, distance);
                copy_window(source, &mut out, start, length);
            }
            Match::Repeat { index, length } => {
                let length = checked_length(length)?;
                let distance = repeats[index];
                let start = window_start(distance)?;
                update_repeats(&mut repeats, distance);
                copy_window(source, &mut out, start, length);
            }
            Match::Source { delta, length } => {
                let length = checked_length(length)?;
                let start = i64::try_from(target_pos)
                    .ok()
                    .and_then(|pos| pos.checked_sub(delta))
                    .and_then(|start| usize::try_from(start).ok())
                    .filter(|&start| start.saturating_add(length) <= source.len())
                    .ok_or_else(|| Error::invalid_data("a source match is outside the source"))?;
                update_repeats(&mut repeats, (window_pos - start) as u64);
                out.extend_from_slice(&source[start..start + length]);
            }
            Match::FullSource { length } => {
                let length = checked_length(length)?;
                let end = target_pos
                    .checked_add(length)
                    .filter(|&end| end <= source.len())
                    .ok_or_else(|| Error::invalid_data("a source match is outside the source"))?;
                out.extend_from_slice(&source[target_pos..end]);
            }
        }
    }
    Ok(out)
}
