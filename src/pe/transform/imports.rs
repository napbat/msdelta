//! Map the RVAs in the import tables (`DELTA_FLAG_IMPORTS`, `TransformImports`).
//!
//! For each import descriptor before the first one with a zero `OriginalFirstThunk`, the
//! transform does these steps:
//!
//! 1. It maps the `IMAGE_IMPORT_BY_NAME` RVAs in the import lookup table
//!    (`OriginalFirstThunk`).
//! 2. It maps the entries of the import address table (`FirstThunk`). If the descriptor has a
//!    time stamp, the entries are bound virtual addresses: the transform maps them as RVAs
//!    and adds the image base again.
//! 3. It maps the `Name`, `OriginalFirstThunk` and `FirstThunk` RVAs of the descriptor.
//!
//! The transform sets the hint bytes of the thunk tables and of the `IMAGE_IMPORT_BY_NAME`
//! entries to 3. It reads each field from the image when `msdelta.dll` reads it, because a
//! table can overlap another table.

use portex::{ImportDescriptor, ImportThunk};

use crate::pe::Pe;
use crate::pe::image::{at, low32, set_u32, set_u64, u32_at, u64_at};
use crate::{Error, Result};

use super::Context;
use super::mark_non_exe::fill;

/// The size of `IMAGE_IMPORT_DESCRIPTOR`.
const DESCRIPTOR_SIZE: usize = ImportDescriptor::SIZE;
/// The offset of `TimeDateStamp` in `IMAGE_IMPORT_DESCRIPTOR`.
const TIME_STAMP: usize = 4;
/// The offset of `Name` in `IMAGE_IMPORT_DESCRIPTOR`.
const NAME: usize = 12;
/// The offset of `FirstThunk` in `IMAGE_IMPORT_DESCRIPTOR`.
const FIRST_THUNK: usize = 16;
/// The hint value for the import tables.
const HINT: u8 = 3;

/// Read the import descriptor at file offset `offset` with `portex`.
pub(super) fn descriptor(image: &[u8], offset: usize) -> Result<ImportDescriptor> {
    image
        .get(offset..)
        .and_then(|data| ImportDescriptor::parse(data).ok())
        .ok_or_else(|| Error::invalid_data("an import descriptor is outside the image"))
}

/// Find the `IMAGE_IMPORT_BY_NAME` entry at `rva`, as
/// `DataDirectories::GetImageImportByNameConst` does.
///
/// Return the file offset of the entry and the length of the name, or `None` if the entry is
/// not in the file or the name has no terminator in its section.
fn import_by_name(pe: &Pe, image: &[u8], rva: u32) -> Result<Option<(u32, u32)>> {
    let offset = pe.image_offset(rva, 4);
    if offset == 0 {
        return Ok(None);
    }
    let max = pe.max_size(rva);
    if max <= 2 {
        return Ok(None);
    }
    // The name starts after the 2-byte hint.
    let mut end = 2;
    loop {
        let byte = image
            .get(at(offset) + at(end))
            .ok_or_else(|| Error::invalid_data("an import name is outside the image"))?;
        if *byte == 0 {
            break;
        }
        end += 1;
        if end >= max {
            break;
        }
    }
    Ok((max > end).then_some((offset, end - 2)))
}

/// Map the low 32 bits of a thunk as the RVA of an `IMAGE_IMPORT_BY_NAME` entry.
///
/// The transform changes nothing for an import by ordinal or for an entry that is not in the
/// file. It writes only the low 32 bits of the thunk, also in a PE32+ image.
fn map_name(context: &mut Context<'_>, image: &mut [u8], entry: usize, value: u64) -> Result<()> {
    let ordinal = if context.pe.is32 {
        ImportThunk::is_ordinal_entry_32(low32(value.cast_signed()))
    } else {
        ImportThunk::is_ordinal_entry_64(value)
    };
    if ordinal {
        return Ok(());
    }
    let rva = low32(value.cast_signed());
    if let Some((offset, length)) = import_by_name(context.pe, image, rva)? {
        // Mark the hint, the name and its terminator.
        fill(&mut context.hint, offset, length + 3, HINT);
        set_u32(image, entry, low32(context.map(i64::from(rva))))?;
    }
    Ok(())
}

/// Map a bound virtual address of the import address table.
fn map_bound(
    context: &Context<'_>,
    image: &mut [u8],
    entry: usize,
    value: u64,
    image_base: u64,
) -> Result<()> {
    if context.pe.is32 {
        // A PE32 image uses 32-bit arithmetic that wraps, as `msdelta.dll` does.
        let base = low32(image_base.cast_signed());
        let rva = low32(value.cast_signed()).wrapping_sub(base);
        let mapped = low32(context.map(i64::from(rva)));
        set_u32(image, entry, base.wrapping_add(mapped))
    } else {
        // `msdelta.dll` uses 64-bit arithmetic that wraps.
        let rva = value.wrapping_sub(image_base).cast_signed();
        let mapped = context.map(rva).cast_unsigned();
        set_u64(image, entry, image_base.wrapping_add(mapped))
    }
}

/// Map the thunk table at `rva`.
///
/// For the import address table, `stamped` is the file offset of the import descriptor:
/// the transform maps bound addresses while its time stamp is not zero.
fn map_thunks(
    context: &mut Context<'_>,
    image: &mut [u8],
    rva: u32,
    stamped: Option<usize>,
    image_base: u64,
) -> Result<()> {
    let pe = context.pe;
    let width: u32 = if pe.is32 { 4 } else { 8 };
    let count = pe.max_size(rva) / width;
    let start = pe.image_offset(rva, 0);
    if start == 0 {
        return Ok(());
    }
    let mut index = 0;
    while index < count {
        // The thunk is in the section of `rva`: `count` limits the index.
        let entry = at(start) + at(index * width);
        let value = if pe.is32 {
            u64::from(u32_at(image, entry)?)
        } else {
            u64_at(image, entry)?
        };
        if value == 0 {
            break;
        }
        let bound = match stamped {
            Some(offset) => u32_at(image, offset + TIME_STAMP)? != 0,
            None => false,
        };
        if bound {
            map_bound(context, image, entry, value, image_base)?;
        } else {
            map_name(context, image, entry, value)?;
        }
        index += 1;
    }
    fill(&mut context.hint, start, index * width, HINT);
    Ok(())
}

/// Map an RVA field of an import descriptor.
fn map_field(context: &Context<'_>, image: &mut [u8], offset: usize) -> Result<()> {
    let value = u32_at(image, offset)?;
    set_u32(image, offset, low32(context.map(i64::from(value))))
}

/// Run `TransformImports`.
pub(super) fn run(context: &mut Context<'_>, image: &mut [u8]) -> Result<()> {
    let pe = context.pe;
    let Some((table, count)) = pe.directories.imports else {
        return Ok(());
    };
    // `msdelta.dll` reads the image base from the image before the transforms change it.
    let image_base = if pe.is32 {
        u64::from(u32_at(image, pe.optional + 28)?)
    } else {
        u64_at(image, pe.optional + 24)?
    };
    for index in 0..at(count) {
        // `DataDirectories` limits the count to the descriptors in the file.
        let offset = table + DESCRIPTOR_SIZE * index;
        let lookup = descriptor(image, offset)?.original_first_thunk;
        map_thunks(context, image, lookup, None, image_base)?;
        let addresses = descriptor(image, offset)?.first_thunk;
        map_thunks(context, image, addresses, Some(offset), image_base)?;
        map_field(context, image, offset + NAME)?;
        map_field(context, image, offset)?;
        map_field(context, image, offset + FIRST_THUNK)?;
    }
    Ok(())
}
