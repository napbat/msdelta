//! Map the RVAs in the AMD64 exception directory (`DELTA_FLAG_AMD64_PDATA`, `TransformPdataX64`).
//!
//! For each `RUNTIME_FUNCTION` in the exception directory (`.pdata`), the transform maps these
//! RVAs with the rift table:
//!
//! - `BeginAddress` and `EndAddress`.
//! - The exception handler RVA (or the chained function) after the unwind codes of
//!   `UNWIND_INFO`, if the unwind flags have `UNW_FLAG_EHANDLER`, `UNW_FLAG_UHANDLER` or
//!   `UNW_FLAG_CHAININFO`. The transform maps only the first `u32` value after the unwind codes.
//! - `UnwindInfoAddress`.

use portex::raw::{RawCursor, RawRuntimeFunctions, RawUnwindInfo};

use crate::pe::image::{MACHINE_AMD64, at, directory, low32, pe_error, set_u32, u32_at};
use crate::{Error, Result};

use super::Context;

/// Return a cursor over the records of the exception directory, and the file offset and the
/// size of the directory. Return `None` if the image has no exception directory. Make sure
/// that the image is an AMD64 image.
pub(super) fn exception_directory(
    context: &Context<'_>,
) -> Result<Option<(RawRuntimeFunctions, u32, u32)>> {
    let pe = context.pe;
    if pe.headers.coff_header.machine != MACHINE_AMD64 {
        return Err(Error::invalid_data(
            "an AMD64 transform needs an AMD64 image",
        ));
    }
    let offset = pe.directories.offset[directory::EXCEPTION];
    if offset == 0 {
        return Ok(None);
    }
    let size = pe.directories.size[directory::EXCEPTION];
    // `DataDirectories` counts only the whole 12-byte records.
    let functions = RawRuntimeFunctions::new(at(offset), at(size));
    Ok(Some((functions, offset, size)))
}

/// Map the `u32` RVA at the file offset `offset`.
fn map_at(context: &Context<'_>, image: &mut [u8], offset: usize) -> Result<()> {
    let rva = u32_at(image, offset)?;
    set_u32(image, offset, low32(context.map(i64::from(rva))))
}

/// Map the RVA after the unwind codes of the `UNWIND_INFO` at `unwind`. `directory` and `size`
/// give the exception directory.
fn map_handler(
    context: &Context<'_>,
    image: &mut [u8],
    unwind: u32,
    directory: u32,
    size: u32,
) -> Result<()> {
    let pe = context.pe;
    let info = pe.image_offset(unwind, 0);
    // `TransformPdataX64` skips an `UNWIND_INFO` in the exception directory. It compares the
    // offsets with 32-bit wrapping arithmetic.
    if info == 0 || (directory <= info && directory.wrapping_add(size) >= info) {
        return Ok(());
    }
    // `TransformPdataX64` limits the `UNWIND_INFO` to its section, or to the exception
    // directory after it.
    let mut room = pe.max_size(unwind);
    if directory > info && directory < room.wrapping_add(info) {
        // The DLL subtracts in this order. The result wraps to a large value.
        room = info.wrapping_sub(directory);
    }
    if room < 4 {
        return Ok(());
    }
    let header = RawUnwindInfo::parse(image, at(info)).map_err(|e| pe_error(&e))?;
    if !header.has_trailer() {
        return Ok(());
    }
    // `TransformPdataX64` maps the trailer only if 4 more bytes are in the room.
    let field = header.size_without_trailer();
    if u64::from(room) > u64::try_from(field).unwrap_or(u64::MAX).saturating_add(4) {
        let trailer = header
            .trailer_offset()
            .ok_or_else(|| Error::invalid_data("an UNWIND_INFO is outside the image"))?;
        map_at(context, image, trailer)?;
    }
    Ok(())
}

/// Run `TransformPdataX64`.
pub(super) fn run(context: &mut Context<'_>, image: &mut [u8]) -> Result<()> {
    let Some((mut functions, directory, size)) = exception_directory(context)? else {
        return Ok(());
    };
    let count = u64::try_from(functions.len()).unwrap_or(u64::MAX);
    // The DLL checks 4 bytes for each entry, not 12.
    if u64::from(context.pe.file_size) <= u64::from(directory) + 4 * count {
        return Err(Error::invalid_data(
            "the exception directory is outside the image",
        ));
    }
    while let Some(function) = functions.read_next(image).map_err(|e| pe_error(&e))? {
        map_at(context, image, function.begin_address.offset)?;
        map_at(context, image, function.end_address.offset)?;
        let unwind = function.unwind_info_address.value;
        map_handler(context, image, unwind, directory, size)?;
        map_at(context, image, function.unwind_info_address.offset)?;
    }
    Ok(())
}
