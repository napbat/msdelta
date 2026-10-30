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

use portex::raw::{RawAddressTable, RawCursor};
use portex::section::characteristics;
use portex::{DataDirectory, SectionHeader};

use crate::pe::Pe;
use crate::pe::image::{at, directory, low32, pe_error, set_u32};
use crate::{Error, Result};

use super::imports::descriptor;

/// The section name `.idata`, with the bit 0x20 set in each byte.
const IDATA: u64 = 0x2020_6174_6164_692e;

/// Return the error for unbind data outside the image.
fn outside() -> Error {
    Error::invalid_data("the bound import data is outside the image")
}

/// Fill the bound import directory with zeros, and clear its data directory entry.
fn clear_bound_directory(image: &mut [u8], pe: &Pe) -> Result<()> {
    let dirs = &pe.directories;
    let offset = dirs.offset[directory::BOUND_IMPORT];
    if offset == 0 {
        return Ok(());
    }
    // `DataDirectories` limits the size to the end of the file.
    let start = at(offset);
    let end = start
        .checked_add(at(dirs.size[directory::BOUND_IMPORT]))
        .ok_or_else(outside)?;
    image.get_mut(start..end).ok_or_else(outside)?.fill(0);
    // `PeUnbinder::Unbind` needs a bound import entry in the data directory table.
    if dirs.count <= 11 {
        return Err(Error::invalid_data(
            "the image has no bound import directory entry",
        ));
    }
    let entry = pe
        .offsets
        .data_directory(directory::BOUND_IMPORT)
        .and_then(|entry| image.get_mut(entry..))
        .ok_or_else(outside)?;
    DataDirectory::default()
        .write(entry)
        .map_err(|e| pe_error(&e))
}

/// Copy the import lookup table over the import address table of a bound descriptor.
fn restore_addresses(image: &mut [u8], pe: &Pe, offset: usize) -> Result<()> {
    let entry = descriptor(image, offset)?;
    let (first_thunk, original_first_thunk) =
        (entry.first_thunk.value, entry.original_first_thunk.value);
    let addresses = pe.image_offset(first_thunk, 0);
    let lookup = pe.image_offset(original_first_thunk, 0);
    if addresses == 0 || lookup == 0 {
        return Ok(());
    }
    let (addresses, lookup) = (at(addresses), at(lookup));
    // `PeUnbinder::Unbind` limits both tables to the ends of their sections (`GetMaxSize`).
    let wide = !pe.is32;
    let mut address_table =
        RawAddressTable::zero_terminated(addresses, at(pe.max_size(first_thunk)), wide);
    let mut lookup_table =
        RawAddressTable::zero_terminated(lookup, at(pe.max_size(original_first_thunk)), wide);
    let width = address_table.entry_size();
    let mut length = 0;
    while let Some(address) = address_table.read_next(image).map_err(|e| pe_error(&e))? {
        let Some(name) = lookup_table.read_next(image).map_err(|e| pe_error(&e))? else {
            break;
        };
        // `msdelta.dll` stops at a thunk with zero low 32 bits, also in a PE32+ image.
        if low32(address.value.cast_signed()) == 0 || low32(name.value.cast_signed()) == 0 {
            break;
        }
        length += width;
    }
    // Both tables have `length` bytes in their sections.
    let end = lookup.checked_add(length).ok_or_else(outside)?;
    if end > image.len() || addresses.saturating_add(length) > image.len() {
        return Err(outside());
    }
    image.copy_within(lookup..end, addresses);
    Ok(())
}

/// Run `PeUnbinder::Unbind` on `image`, with the structure `pe` of the bound source.
pub(crate) fn unbind(image: &mut [u8], pe: &Pe) -> Result<()> {
    clear_bound_directory(image, pe)?;
    for &offset in &pe.directories.imports {
        let entry = descriptor(image, offset)?;
        if entry.time_date_stamp.value == 0 {
            continue;
        }
        set_u32(image, entry.time_date_stamp.offset, 0)?;
        restore_addresses(image, pe, offset)?;
        set_u32(image, entry.forwarder_chain.offset, 0)?;
    }
    // `msdelta.dll` reads the names from the image and ignores the case of the letters.
    for index in 0..pe.sections().len() {
        let header = pe
            .offsets
            .section_header(index)
            .and_then(|header| image.get_mut(header..))
            .ok_or_else(outside)?;
        let mut section = SectionHeader::parse(header).map_err(|e| pe_error(&e))?;
        if u64::from_le_bytes(section.name) | 0x2020_2020_2020_2020 == IDATA {
            section.characteristics |= characteristics::READ | characteristics::WRITE;
            return section.write(header).map_err(|e| pe_error(&e));
        }
    }
    Ok(())
}
