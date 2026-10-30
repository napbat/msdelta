//! Mark the data that is not code in the hint buffer (`DELTA_FLAG_MARK`, `MarkNonExe`).
//!
//! The transform does not change the image. It sets the hint bytes:
//!
//! - 1 for the raw data of each section that is not executable.
//! - 3 for the headers and for each data directory.

use crate::Result;
use crate::pe::image::at;

use super::Context;

/// `IMAGE_SCN_MEM_EXECUTE`.
const SCN_MEM_EXECUTE: u32 = 0x2000_0000;

/// Set `count` hint bytes from `offset` to `value`. The range is in the image.
pub(super) fn fill(hint: &mut [u8], offset: u32, count: u32, value: u8) {
    let start = at(offset).min(hint.len());
    let end = start.saturating_add(at(count)).min(hint.len());
    hint[start..end].fill(value);
}

/// Run `MarkNonExe` on an image without CLI metadata.
pub(super) fn run(context: &mut Context<'_>, _image: &mut [u8]) -> Result<()> {
    let pe = context.pe;
    for section in pe.sections() {
        let raw = section.pointer_to_raw_data;
        if section.characteristics & SCN_MEM_EXECUTE == 0 && raw < pe.file_size {
            let count = (pe.file_size - raw).min(section.size_of_raw_data);
            fill(&mut context.hint, raw, count, 1);
        }
    }
    fill(&mut context.hint, 0, pe.header_limit, 3);
    let dirs = &pe.directories;
    if dirs.count > 16 {
        return Err(crate::Error::invalid_data(
            "the image has more than 16 data directories",
        ));
    }
    for index in 0..at(dirs.count) {
        if dirs.offset[index] != 0 {
            fill(&mut context.hint, dirs.offset[index], dirs.size[index], 3);
        }
    }
    Ok(())
}
