//! Map the relative operands in AMD64 code (`DELTA_FLAG_AMD64_DISASM`, `TransformDisasmX64`).
//!
//! The transform reads the code of each function in the exception directory (`.pdata`). It
//! decodes the instructions with the decoder of `DisassemblerAmd64`. For each 32-bit relative
//! operand (`CALL`, `JMP`, `Jcc` and RIP-relative memory operands), it maps the RVA of the
//! instruction end and the RVA of the operand target with the rift table. Then it stores the
//! difference of the two target RVAs in the operand.
//!
//! The hint buffer controls the walk:
//!
//! - The transform steps over one byte if its hint has bit 0 or bit 1 set.
//! - If a byte inside an instruction has bit 1 set, the transform does not change the
//!   instruction. It continues at that byte.

mod decoder;
mod tables;

use portex::raw::RawCursor;

use crate::pe::image::{at, low32, pe_error, set_u32, u32_at};
use crate::{Error, Result};

use super::Context;
use super::pdata_amd64::exception_directory;

/// Return the hint byte at `index`. Fail for an index outside the hint buffer, as
/// `buffer::operator[]` does.
fn hint(context: &Context<'_>, index: usize) -> Result<u8> {
    context
        .hint
        .get(index)
        .copied()
        .ok_or_else(|| Error::invalid_data("a code byte is outside the hint buffer"))
}

/// Map the relative operands in `size` bytes of code at the file offset `offset` and the RVA
/// `rva`.
fn walk(
    context: &Context<'_>,
    image: &mut [u8],
    mut rva: u32,
    mut offset: usize,
    size: u32,
) -> Result<()> {
    let mut remaining = size;
    while remaining != 0 {
        let step = if hint(context, offset)? & 3 != 0 {
            1
        } else {
            let code = offset
                .checked_add(at(remaining))
                .and_then(|end| image.get(offset..end))
                .ok_or_else(|| Error::invalid_data("a function is outside the image"))?;
            let instruction = decoder::decode(code);
            let length = instruction.length;
            let mut clean = 1;
            while clean < length && hint(context, offset + usize::from(clean))? & 2 == 0 {
                clean += 1;
            }
            if clean < length {
                clean
            } else {
                if let Some(position) = instruction.relative {
                    // The DLL computes the RVAs with 32-bit wrapping arithmetic.
                    let next = rva.wrapping_add(u32::from(length));
                    let field = offset + usize::from(position);
                    let target = next.wrapping_add(u32_at(image, field)?);
                    let mapped_next = low32(context.map(i64::from(next)));
                    let mapped_target = low32(context.map(i64::from(target)));
                    set_u32(image, field, mapped_target.wrapping_sub(mapped_next))?;
                }
                length
            }
        };
        // The decoder reads at most `remaining` bytes, so `step <= remaining`.
        remaining = remaining.saturating_sub(u32::from(step));
        offset += usize::from(step);
        rva = rva.wrapping_add(u32::from(step));
    }
    Ok(())
}

/// Run `TransformDisasmX64`.
pub(super) fn run(context: &mut Context<'_>, image: &mut [u8]) -> Result<()> {
    let Some((mut functions, _, _)) = exception_directory(context)? else {
        return Ok(());
    };
    while let Some(function) = functions.read_next(image).map_err(|e| pe_error(&e))? {
        let (begin, end) = (function.begin_address.value, function.end_address.value);
        if end <= begin {
            continue;
        }
        let size = end - begin;
        let offset = context.pe.image_offset(begin, size);
        if offset != 0 {
            walk(context, image, begin, at(offset), size)?;
        }
    }
    Ok(())
}
