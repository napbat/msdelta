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

use portex::exception::{
    RuntimeFunction, UNW_FLAG_CHAININFO, UNW_FLAG_EHANDLER, UNW_FLAG_UHANDLER,
};

use crate::pe::image::{MACHINE_AMD64, at, low32, set_u32, u32_at};
use crate::{Error, Result};

use super::Context;

/// The index of the exception directory (`IMAGE_DIRECTORY_ENTRY_EXCEPTION`).
const EXCEPTION: usize = 3;
/// The size of `RUNTIME_FUNCTION`.
const ENTRY_SIZE: u32 = 12;
/// The unwind flags (bits 3 to 7 of the first `UNWIND_INFO` byte) that put an RVA after the
/// unwind codes.
const HANDLER_FLAGS: u8 = (UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER | UNW_FLAG_CHAININFO) << 3;

/// Return the file offset and the entry count of the exception directory, or `None` if the
/// image has no exception directory. Make sure that the image is an AMD64 image.
pub(super) fn exception_directory(context: &Context<'_>) -> Result<Option<(u32, u32)>> {
    let pe = context.pe;
    if pe.headers.coff_header.machine != MACHINE_AMD64 {
        return Err(Error::invalid_data(
            "an AMD64 transform needs an AMD64 image",
        ));
    }
    let offset = pe.directories.offset[EXCEPTION];
    if offset == 0 {
        return Ok(None);
    }
    Ok(Some((offset, pe.directories.size[EXCEPTION] / ENTRY_SIZE)))
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
    // The DLL compares the offsets with 32-bit wrapping arithmetic.
    if info == 0 || (directory <= info && directory.wrapping_add(size) >= info) {
        return Ok(());
    }
    let mut room = pe.max_size(unwind);
    if directory > info && directory < room.wrapping_add(info) {
        // The DLL subtracts in this order. The result wraps to a large value.
        room = info.wrapping_sub(directory);
    }
    if room < 4 {
        return Ok(());
    }
    let base = at(info);
    let header = |index: usize| {
        image
            .get(base + index)
            .copied()
            .ok_or_else(|| Error::invalid_data("an UNWIND_INFO is outside the image"))
    };
    if header(0)? & HANDLER_FLAGS == 0 {
        return Ok(());
    }
    // The unwind codes have 2 bytes each, padded to a multiple of 4 bytes.
    let field = 4 * ((u32::from(header(2)?) + 1) >> 1) + 4;
    if u64::from(room) > u64::from(field) + 4 {
        map_at(context, image, base + at(field))?;
    }
    Ok(())
}

/// Run `TransformPdataX64`.
pub(super) fn run(context: &mut Context<'_>, image: &mut [u8]) -> Result<()> {
    let Some((directory, count)) = exception_directory(context)? else {
        return Ok(());
    };
    let size = context.pe.directories.size[EXCEPTION];
    // The DLL checks 4 bytes for each entry, not 12.
    if u64::from(context.pe.file_size) <= u64::from(directory) + 4 * u64::from(count) {
        return Err(Error::invalid_data(
            "the exception directory is outside the image",
        ));
    }
    for index in 0..count {
        let entry = at(directory) + at(index) * RuntimeFunction::SIZE;
        map_at(context, image, entry)?;
        map_at(context, image, entry + 4)?;
        let unwind = u32_at(image, entry + 8)?;
        map_handler(context, image, unwind, directory, size)?;
        map_at(context, image, entry + 8)?;
    }
    Ok(())
}
