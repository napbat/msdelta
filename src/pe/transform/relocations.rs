//! Map the base relocations (`DELTA_FLAG_RELOCS`, `TransformRelocations`).
//!
//! The transform maps each fixup of the base relocation table:
//!
//! 1. It reads the blocks of the table. For each entry, it maps the RVA of the fixup with the
//!    rift table. For a `HIGHLOW` or a `DIR64` fixup, it also maps the address in the image to
//!    the target image base and the target RVA. It marks the bytes of each fixup in the hint
//!    buffer.
//! 2. It sorts the entries by the mapped RVA.
//! 3. It writes the entries back as new blocks, one block for each target page.
//!
//! An I386 image without a relocation directory gets the inferred transform: each `u32` that
//! points into the image is an address, and the transform maps it.

use crate::pe::image::{
    MACHINE_I386, Relocations, at, directory, low32, set_u32, set_u64, u16_at, u32_at, u64_at,
};
use crate::prelude::*;
use crate::{Error, Result};
use portex::reloc::{RelocationEntry as Word, RelocationType};

use super::Context;

/// The size of the `IMAGE_BASE_RELOCATION` block header.
const HEADER_SIZE: u32 = 8;
/// The bits of an RVA that select the page of a relocation block.
const PAGE_MASK: u32 = 0xffff_f000;
/// The hint bits of a header or a data directory, for each of four bytes.
const HINT_DIRECTORY: u32 = 0x0202_0202;
/// The hint bits of data that is not code, for each of four bytes.
const HINT_DATA: u32 = 0x0101_0101;

/// One relocation entry (`TransformRelocations::RelocationEntry`).
#[derive(Debug, Clone, Copy)]
struct Entry {
    /// The target RVA of the fixup.
    rva: u32,
    /// The relocation type. The transform keeps only the types that it knows, and stores zero
    /// for the other types.
    kind: RelocationType,
    /// The parameter word of a `HIGHADJ` entry.
    param: u16,
}

/// The image bases that the fixups use.
#[derive(Debug, Clone, Copy)]
struct ImageBases {
    /// The low 32 bits of the source image base.
    source: u32,
    /// The target image base.
    target: u64,
}

/// Run `TransformRelocations`.
pub(super) fn run(context: &mut Context<'_>, image: &mut [u8]) -> Result<()> {
    let pe = context.pe;
    if pe.headers.coff_header.machine == MACHINE_I386
        && pe.directories.offset[directory::BASERELOC] == 0
    {
        return infer_x86(context, image);
    }
    let Some(relocations) = pe.directories.relocations else {
        return Ok(());
    };
    let mut entries = read(context, image, &relocations)?;
    if entries.is_empty() {
        return Ok(());
    }
    // `RadixSortIncreasing` is a stable sort on the low four bytes of an entry: the RVA.
    entries.sort_by_key(|entry| entry.rva);
    write(image, &relocations, &entries)
}

/// Return the file offset of a fixup of `size` bytes at `offset`, if the fixup is in the file.
fn fixup(offset: u32, size: u32, file_size: u32) -> Option<usize> {
    offset
        .checked_add(size)
        .is_some_and(|end| end <= file_size)
        .then(|| at(offset))
}

/// Set bit 0 in the `size` hint bytes at `offset`.
fn mark(hint: &mut [u8], offset: usize, size: usize) {
    if let Some(bytes) = offset
        .checked_add(size)
        .and_then(|end| hint.get_mut(offset..end))
    {
        for byte in bytes {
            *byte |= 1;
        }
    }
}

/// Read the relocation entries and map the `HIGHLOW` and `DIR64` fixups, as
/// `TransformRelocations::ReadRelocationEntries` does.
///
/// The function reads the table from `image` while it changes the fixups, as `msdelta.dll`
/// does.
fn read(
    context: &mut Context<'_>,
    image: &mut [u8],
    relocations: &Relocations,
) -> Result<Vec<Entry>> {
    let pe = context.pe;
    // `msdelta.dll` uses the low 32 bits of the image bases for the subtraction and the map.
    let source = if pe.is32 {
        u32_at(image, pe.optional + 28)?
    } else {
        low32(u64_at(image, pe.optional + 24)?.cast_signed())
    };
    let bases = ImageBases {
        source,
        target: context.info.image_base,
    };
    let mut entries = Vec::new();
    let mut block = relocations.offset;
    let mut remaining = relocations.size;
    while remaining >= HEADER_SIZE {
        let page = u32_at(image, block)?;
        let size = u32_at(image, block + 4)?;
        if size < HEADER_SIZE || size > remaining {
            break;
        }
        let base = pe.image_offset(page, 0);
        if base != 0 {
            let words = block + at(HEADER_SIZE)..block + at(size);
            read_block(context, image, page, base, words, &mut entries, bases)?;
        }
        remaining -= size;
        block += at(size);
    }
    Ok(entries)
}

/// Read the entries of one block. `base` is the file offset of `page`, and `words` holds
/// the file offsets of the entry words.
fn read_block(
    context: &mut Context<'_>,
    image: &mut [u8],
    page: u32,
    base: u32,
    words: core::ops::Range<usize>,
    entries: &mut Vec<Entry>,
    bases: ImageBases,
) -> Result<()> {
    let file_size = context.pe.file_size;
    let mut word = words.start;
    let mut count = (words.end - words.start) / 2;
    while count != 0 {
        let raw = Word::from_u16(u16_at(image, word)?);
        if raw.is_padding() {
            break;
        }
        // `msdelta.dll` adds the offset in 32 bits, with wraparound.
        let offset = base.wrapping_add(u32::from(raw.offset));
        let rva = page.wrapping_add(u32::from(raw.offset));
        let mut entry = Entry {
            rva: low32(context.map(i64::from(rva))),
            kind: raw.reloc_type,
            param: 0,
        };
        match raw.reloc_type {
            RelocationType::High | RelocationType::Low => {
                if let Some(fix) = fixup(offset, 2, file_size) {
                    mark(&mut context.hint, fix, 2);
                }
            }
            RelocationType::HighLow => {
                if let Some(fix) = fixup(offset, 4, file_size) {
                    mark(&mut context.hint, fix, 4);
                    let value = u32_at(image, fix)?.wrapping_sub(bases.source);
                    let mapped = low32(context.map(i64::from(value)));
                    let target = low32(bases.target.cast_signed());
                    set_u32(image, fix, mapped.wrapping_add(target))?;
                }
            }
            RelocationType::HighAdj => {
                if let Some(fix) = fixup(offset, 2, file_size) {
                    mark(&mut context.hint, fix, 2);
                }
                if count > 1 {
                    word += 2;
                    count -= 1;
                    entry.param = u16_at(image, word)?;
                } else {
                    // A `HIGHADJ` entry without its parameter word becomes an `ABSOLUTE` entry.
                    entry.kind = RelocationType::Absolute;
                }
            }
            RelocationType::Dir64 => {
                if let Some(fix) = fixup(offset, 8, file_size) {
                    mark(&mut context.hint, fix, 8);
                    let value = low32(u64_at(image, fix)?.cast_signed()).wrapping_sub(bases.source);
                    let mapped = low32(context.map(i64::from(value)));
                    set_u64(image, fix, bases.target.wrapping_add(u64::from(mapped)))?;
                }
            }
            _ => entry.kind = RelocationType::Absolute,
        }
        entries.push(entry);
        word += 2;
        count -= 1;
    }
    Ok(())
}

/// Write a little-endian `u16` at `offset`.
fn set_u16(data: &mut [u8], offset: usize, value: u16) -> Result<()> {
    offset
        .checked_add(2)
        .and_then(|end| data.get_mut(offset..end))
        .ok_or_else(|| Error::invalid_data("a relocation entry is outside the image"))?
        .copy_from_slice(&value.to_le_bytes());
    Ok(())
}

/// Write the sorted entries as new blocks, as `TransformRelocations::WriteRelocationEntries`
/// does.
///
/// The blocks fill the relocation extent from its start. The function does not change the
/// bytes after the last block.
fn write(image: &mut [u8], relocations: &Relocations, entries: &[Entry]) -> Result<()> {
    let mut room = relocations.extent & !1;
    let mut block = relocations.offset;
    let mut next = 0;
    while room >= HEADER_SIZE && next < entries.len() {
        let page = entries[next].rva & PAGE_MASK;
        set_u32(image, block, page)?;
        let first = block + at(HEADER_SIZE);
        let mut word = first;
        room -= HEADER_SIZE;
        while room != 0 {
            let Some(entry) = entries
                .get(next)
                .filter(|entry| entry.rva & PAGE_MASK == page)
            else {
                break;
            };
            let value = Word {
                reloc_type: entry.kind,
                offset: u16::try_from(entry.rva & !PAGE_MASK).unwrap_or_default(),
            };
            set_u16(image, word, value.to_u16())?;
            word += 2;
            room -= 2;
            if entry.kind == RelocationType::HighAdj && room != 0 {
                set_u16(image, word, entry.param)?;
                word += 2;
                room -= 2;
            }
            next += 1;
        }
        // Add an `ABSOLUTE` entry after an odd count of words, if the extent has room for it.
        if room != 0 && (word - first) / 2 % 2 == 1 {
            set_u16(image, word, 0)?;
            word += 2;
            room -= 2;
        }
        let size = u32::try_from(word - block)
            .map_err(|_| Error::invalid_data("a relocation block is too large"))?;
        set_u32(image, block + 4, size)?;
        block = word;
    }
    Ok(())
}

/// Map each `u32` that points into the image, as
/// `TransformRelocations::TransformInferredRelocationsX86` does.
///
/// The function scans from `SizeOfHeaders` to the end of the file. It skips the headers and
/// the data directories that `MarkNonExe` marked in the hint buffer.
fn infer_x86(context: &mut Context<'_>, image: &mut [u8]) -> Result<()> {
    let pe = context.pe;
    let base = u32_at(image, pe.optional + 28)?;
    let end = base.wrapping_add(u32_at(image, pe.optional + 56)?);
    let target_base = low32(context.info.image_base.cast_signed());
    let limit = pe.file_size.saturating_sub(4);
    let mut offset = u32_at(image, pe.optional + 60)?;
    while offset < limit {
        let value = u32_at(image, at(offset))?;
        if value <= base || value >= end {
            offset += 1;
            continue;
        }
        let hint = u32_at(&context.hint, at(offset))?;
        if hint & HINT_DIRECTORY == 0 {
            set_u32(&mut context.hint, at(offset), hint | HINT_DATA)?;
            let mapped = low32(context.map(i64::from(value - base)));
            set_u32(image, at(offset), mapped.wrapping_add(target_base))?;
        }
        offset += 4;
    }
    Ok(())
}
