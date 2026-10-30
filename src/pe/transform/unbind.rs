//! Clear the import binding of the source (`DELTA_FLAG_UNBIND`, `PeUnbinder::Unbind`).
//!
//! The function runs on the source before the transforms. It does these steps:
//!
//! 1. It fills the bound import directory with zeros and clears its data directory entry.
//! 2. For each import descriptor with a time stamp, it clears the time stamp, copies the import
//!    lookup table over the import address table, and clears the forwarder chain.
//! 3. It adds `IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE` to the first `.idata` section.
//!
//! `msdelta.dll` finds the data directories before this function, and the transforms use these
//! values. Thus `Pe` keeps the values from the bound source.

use crate::pe::Pe;
use crate::pe::image::{at, set_u32, u32_at};
use crate::{Error, Result};

use super::imports::descriptor;

/// `IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT`.
const BOUND_IMPORT: usize = 11;
/// The size of `IMAGE_IMPORT_DESCRIPTOR`.
const DESCRIPTOR_SIZE: usize = portex::ImportDescriptor::SIZE;
/// The offset of `TimeDateStamp` in `IMAGE_IMPORT_DESCRIPTOR`.
const TIME_STAMP: usize = 4;
/// The offset of `ForwarderChain` in `IMAGE_IMPORT_DESCRIPTOR`.
const FORWARDER_CHAIN: usize = 8;
/// The offset of `Characteristics` in `IMAGE_SECTION_HEADER`.
const CHARACTERISTICS: usize = 36;
/// `IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE`.
const SCN_MEM_READ_WRITE: u32 = 0xc000_0000;
/// The section name `.idata`, with the bit 0x20 set in each byte.
const IDATA: u64 = 0x2020_6174_6164_692e;

/// Return the error for unbind data outside the image.
fn outside() -> Error {
    Error::invalid_data("the bound import data is outside the image")
}

/// Fill the bound import directory with zeros, and clear its data directory entry.
fn clear_bound_directory(image: &mut [u8], pe: &Pe) -> Result<()> {
    let dirs = &pe.directories;
    let offset = dirs.offset[BOUND_IMPORT];
    if offset == 0 {
        return Ok(());
    }
    // `DataDirectories` limits the size to the end of the file.
    let start = at(offset);
    let end = start
        .checked_add(at(dirs.size[BOUND_IMPORT]))
        .ok_or_else(outside)?;
    image.get_mut(start..end).ok_or_else(outside)?.fill(0);
    if dirs.count <= 11 {
        return Err(Error::invalid_data(
            "the image has no bound import directory entry",
        ));
    }
    let entry = dirs.table + 8 * BOUND_IMPORT;
    set_u32(image, entry, 0)?;
    set_u32(image, entry + 4, 0)
}

/// Copy the import lookup table over the import address table of a bound descriptor.
fn restore_addresses(image: &mut [u8], pe: &Pe, offset: usize) -> Result<()> {
    let entry = descriptor(image, offset)?;
    let addresses = pe.image_offset(entry.first_thunk, 0);
    let lookup = pe.image_offset(entry.original_first_thunk, 0);
    if addresses == 0 || lookup == 0 {
        return Ok(());
    }
    let (addresses, lookup) = (at(addresses), at(lookup));
    let width: u32 = if pe.is32 { 4 } else { 8 };
    let mut addresses_left = pe.max_size(entry.first_thunk) / width;
    let mut lookup_left = pe.max_size(entry.original_first_thunk) / width;
    // `msdelta.dll` stops at a thunk with zero low 32 bits, also in a PE32+ image.
    let mut length = 0;
    while addresses_left != 0
        && lookup_left != 0
        && u32_at(image, addresses + at(length))? != 0
        && u32_at(image, lookup + at(length))? != 0
    {
        lookup_left -= 1;
        addresses_left -= 1;
        length += width;
    }
    // Both tables have `length` bytes in their sections.
    let end = lookup.checked_add(at(length)).ok_or_else(outside)?;
    if end > image.len() || addresses.saturating_add(at(length)) > image.len() {
        return Err(outside());
    }
    image.copy_within(lookup..end, addresses);
    Ok(())
}

/// Run `PeUnbinder::Unbind` on `image`, with the structure `pe` of the bound source.
pub(crate) fn unbind(image: &mut [u8], pe: &Pe) -> Result<()> {
    clear_bound_directory(image, pe)?;
    if let Some((table, count)) = pe.directories.imports {
        for index in 0..at(count) {
            // `DataDirectories` limits the count to the descriptors in the file.
            let offset = table + DESCRIPTOR_SIZE * index;
            if u32_at(image, offset + TIME_STAMP)? == 0 {
                continue;
            }
            set_u32(image, offset + TIME_STAMP, 0)?;
            restore_addresses(image, pe, offset)?;
            set_u32(image, offset + FORWARDER_CHAIN, 0)?;
        }
    }
    // `msdelta.dll` reads the names from the image and ignores the case of the letters.
    for index in 0..pe.sections().len() {
        let header = pe.section_header_offset(index);
        let name = image
            .get(header..)
            .and_then(|data| data.first_chunk::<8>())
            .ok_or_else(outside)?;
        if u64::from_le_bytes(*name) | 0x2020_2020_2020_2020 == IDATA {
            let field = header + CHARACTERISTICS;
            let value = u32_at(image, field)?;
            return set_u32(image, field, value | SCN_MEM_READ_WRITE);
        }
    }
    Ok(())
}
