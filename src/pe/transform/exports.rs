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

use portex::ExportDirectory;

use crate::pe::image::{at, low32, set_u32, u32_at};
use crate::{Error, Result};

use super::Context;
use super::mark_non_exe::fill;

/// The offset of `Name` in `IMAGE_EXPORT_DIRECTORY`.
const NAME: usize = 12;
/// The offset of `AddressOfFunctions` in `IMAGE_EXPORT_DIRECTORY`.
const FUNCTIONS: usize = 28;
/// The offset of `AddressOfNames` in `IMAGE_EXPORT_DIRECTORY`.
const NAMES: usize = 32;
/// The offset of `AddressOfNameOrdinals` in `IMAGE_EXPORT_DIRECTORY`.
const ORDINALS: usize = 36;
/// The hint value for the export tables.
const HINT: u8 = 3;

/// Map `count` RVAs at file offset `offset`, and set their hint bytes.
fn map_table(context: &mut Context<'_>, image: &mut [u8], offset: usize, count: u32) -> Result<()> {
    // `DataDirectories` accepts at most 0x3fff_ffff entries: the size fits in 32 bits.
    let start = u32::try_from(offset)
        .map_err(|_| Error::invalid_data("an export table is outside the image"))?;
    fill(&mut context.hint, start, count * 4, HINT);
    for index in 0..at(count) {
        let entry = offset + 4 * index;
        let value = u32_at(image, entry)?;
        set_u32(image, entry, low32(context.map(i64::from(value))))?;
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
        let start = u32::try_from(ordinals)
            .map_err(|_| Error::invalid_data("an export table is outside the image"))?;
        fill(&mut context.hint, start, count * 2, HINT);
    }
    // `DataDirectories` accepts the directory only if its 40 bytes are in the file.
    let header = image
        .get(directory..)
        .and_then(|data| ExportDirectory::parse(data).ok())
        .ok_or_else(|| Error::invalid_data("the export directory is outside the image"))?;
    let fields = [
        (NAME, header.name_rva),
        (FUNCTIONS, header.address_of_functions),
        (NAMES, header.address_of_names),
        (ORDINALS, header.address_of_name_ordinals),
    ];
    for (field, value) in fields {
        set_u32(
            image,
            directory + field,
            low32(context.map(i64::from(value))),
        )?;
    }
    Ok(())
}
