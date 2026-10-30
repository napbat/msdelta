//! Map the RVAs in the export directory (`DELTA_FLAG_EXPORTS`, `TransformExports`).
//!
//! The transform does these steps:
//!
//! 1. It maps each RVA of the export address table (`AddressOfFunctions`).
//! 2. It maps each RVA of the export name pointer table (`AddressOfNames`).
//! 3. It maps the `Name`, `AddressOfFunctions`, `AddressOfNames` and `AddressOfNameOrdinals`
//!    RVAs of `IMAGE_EXPORT_DIRECTORY`.
//!
//! It sets the hint bytes of the three tables to 3. `DataDirectories` finds the tables before
//! the transforms, and the transform uses these values.

use portex::raw::{RawAddressTable, RawCursor, RawExportDirectory};

use crate::pe::image::{at, low32, pe_error, set_u32};
use crate::{Error, Result};

use super::Context;
use super::mark_non_exe::fill;

/// The hint value for the export tables.
const HINT: u8 = 3;

/// Return the error for an export table outside the image.
fn outside() -> Error {
    Error::invalid_data("an export table is outside the image")
}

/// Map `count` RVAs at file offset `offset`, and set their hint bytes.
fn map_table(context: &mut Context<'_>, image: &mut [u8], offset: usize, count: u32) -> Result<()> {
    // `DataDirectories` accepts at most 0x3fff_ffff entries: the size fits in 32 bits.
    let start = u32::try_from(offset).map_err(|_| outside())?;
    fill(&mut context.hint, start, count * 4, HINT);
    let mut table = RawAddressTable::counted(offset, at(count), false);
    while let Some(entry) = table.read_next(image).map_err(|e| pe_error(&e))? {
        let value = low32(entry.value.cast_signed());
        set_u32(image, entry.offset, low32(context.map(i64::from(value))))?;
    }
    Ok(())
}

/// Run `TransformExports`.
pub(super) fn run(context: &mut Context<'_>, image: &mut [u8]) -> Result<()> {
    let exports = context.pe.directories.exports;
    let Some(directory) = exports.directory else {
        return Ok(());
    };
    if let Some((offset, count)) = exports.functions {
        map_table(context, image, offset, count)?;
    }
    if let Some((names, ordinals, count)) = exports.names {
        map_table(context, image, names, count)?;
        let start = u32::try_from(ordinals).map_err(|_| outside())?;
        fill(&mut context.hint, start, count * 2, HINT);
    }
    // `DataDirectories` accepts the directory only if its 40 bytes are in the file.
    let header = RawExportDirectory::parse(image, directory).map_err(|e| pe_error(&e))?;
    let fields = [
        header.name_rva,
        header.address_of_functions,
        header.address_of_names,
        header.address_of_name_ordinals,
    ];
    for field in fields {
        set_u32(
            image,
            field.offset,
            low32(context.map(i64::from(field.value))),
        )?;
    }
    Ok(())
}
