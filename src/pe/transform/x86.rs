//! The x86 transforms: `SmashLockPrefixesX86`, `RelativeJmpsX86` and `RelativeCallsX86`.
//!
//! - `SmashLockPrefixesX86` writes a `lock` prefix (`F0`) at each address of the lock prefix
//!   table of the load configuration.
//! - `RelativeJmpsX86` changes the target of each near `jmp` (`E9`) and `jcc` (`0F 8x`) in the
//!   executable sections to the target that the rift table gives. If the new target is near,
//!   it uses the short form (`EB` or `7x`).
//! - `RelativeCallsX86` changes the target of each `call` (`E8`) in the executable sections in
//!   the same way.
//!
//! The scans skip all bytes that `MarkNonExe` marks as data in the hint buffer.

use crate::pe::Pe;
use crate::pe::image::{MACHINE_I386, at, low32, pe_error, set_u32, u32_at};
use crate::prelude::*;
use crate::{Error, Result};
use portex::raw::{RawAddressTable, RawCursor, RawLoadConfigDirectory};
use portex::section::{SectionHeader, characteristics};

use super::Context;

/// The `lock` prefix.
const LOCK: u8 = 0xf0;
/// The opcode of `call rel32`.
const CALL: u8 = 0xe8;
/// The opcode of `jmp rel32`.
const JMP: u8 = 0xe9;
/// The opcode of `jmp rel8`.
const JMP_SHORT: u8 = 0xeb;
/// The first opcode byte of `jcc rel32` (`0F 80` to `0F 8F`).
const TWO_BYTE: u8 = 0x0f;
/// The size of an instruction with a 32-bit relative operand, without a `0F` byte.
const SIZE: usize = 5;

/// Make sure that the source is an I386 image, as each x86 transform does.
fn check_i386(pe: &Pe, name: &str) -> Result<()> {
    if pe.headers.coff_header.machine != MACHINE_I386 {
        return Err(Error::invalid_data(format!(
            "the {name} transform needs an I386 image"
        )));
    }
    Ok(())
}

/// Return the hint byte at `offset`, as `buffer::operator[]` does.
fn hint(context: &Context<'_>, offset: usize) -> Result<u8> {
    context
        .hint
        .get(offset)
        .copied()
        .ok_or_else(|| Error::invalid_data("a hint offset is outside the image"))
}

/// Return `true` if `MarkNonExe` marks the byte at `offset` as data.
fn is_data(context: &Context<'_>, offset: usize) -> Result<bool> {
    Ok(hint(context, offset)? & 1 != 0)
}

/// Return `true` if `MarkNonExe` marks one of the `SIZE` bytes at `offset` as data.
fn any_data(context: &Context<'_>, offset: usize) -> Result<bool> {
    for index in offset..offset + SIZE {
        if is_data(context, index)? {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Run `SmashLockPrefixesX86` (`DELTA_FLAG_I386_SMASHLOCK`).
pub(super) fn smash_lock_prefixes(context: &mut Context<'_>, image: &mut [u8]) -> Result<()> {
    let pe = context.pe;
    check_i386(pe, "SmashLockPrefixesX86")?;
    if !pe.is32 {
        return Err(Error::invalid_data(
            "the SmashLockPrefixesX86 transform needs a PE32 image",
        ));
    }
    let Some(config) = pe.directories.load_config else {
        return Ok(());
    };
    let config = RawLoadConfigDirectory::parse(image, config, false).map_err(|e| pe_error(&e))?;
    let table = low32(config.lock_prefix_table.value.cast_signed());
    if table == 0 {
        return Ok(());
    }
    // The image base and the addresses are 32-bit values: the subtractions wrap.
    let base = low32(pe.image_base(image)?.cast_signed());
    let rva = table.wrapping_sub(base);
    let offset = pe.image_offset(rva, 0);
    if offset == 0 {
        return Ok(());
    }
    // `SmashLockPrefixesX86` limits the table to the end of its section (`GetMaxSize`).
    let mut entries = RawAddressTable::zero_terminated(at(offset), at(pe.max_size(rva)), false);
    while let Some(entry) = entries.read_next(image).map_err(|e| pe_error(&e))? {
        let address = low32(entry.value.cast_signed());
        let target = pe.image_offset(address.wrapping_sub(base), 1);
        // `msdelta.dll` compares the file offset with the virtual end of each section.
        let in_section = target != 0
            && pe.sections().iter().any(|section| {
                section.pointer_to_raw_data <= target
                    && section.virtual_size.wrapping_add(section.virtual_address) > target
            });
        if in_section {
            *image
                .get_mut(at(target))
                .ok_or_else(|| Error::invalid_data("a lock prefix is outside the image"))? = LOCK;
        }
    }
    Ok(())
}

/// The part of an executable section that the scans read.
struct Code {
    /// The RVA of the section.
    rva: u32,
    /// The file offset of the section.
    start: usize,
    /// The file offset after the last position of an instruction: the end of the section
    /// data minus `SIZE`.
    end: usize,
}

impl Code {
    /// Return the RVA after the instruction whose last operand byte is at `offset + 4`, as
    /// a 32-bit value.
    fn next_rva(&self, offset: usize) -> u32 {
        // The section data is in the file, so `offset - start` fits in `u32`.
        let delta = u32::try_from(offset - self.start).unwrap_or(u32::MAX);
        self.rva.wrapping_add(delta).wrapping_add(5)
    }
}

/// Find the part of `section` that the scans read, as `RelativeJmpsX86::Run` and
/// `RelativeCallsX86::Run` do. Return `None` for a section that the scans skip. `len` is the
/// size of the image.
fn code(pe: &Pe, section: &SectionHeader, len: usize) -> Result<Option<Code>> {
    if section.characteristics & characteristics::EXECUTE == 0 {
        return Ok(None);
    }
    let size = section.virtual_size.min(section.size_of_raw_data);
    let raw = section.pointer_to_raw_data;
    let Some(end) = raw.checked_add(size).filter(|&end| end <= pe.file_size) else {
        return Ok(None);
    };
    if at(end) > len {
        return Err(Error::invalid_data("a code section is outside the image"));
    }
    Ok((at(size) > SIZE).then(|| Code {
        rva: section.virtual_address,
        start: at(raw),
        end: at(end) - SIZE,
    }))
}

/// Read the 32-bit relative operand after the opcode at `offset`.
fn operand(image: &[u8], offset: usize) -> Result<i32> {
    Ok(u32_at(image, offset + 1)?.cast_signed())
}

/// Write the 32-bit relative operand after the opcode at `offset`.
fn set_operand(image: &mut [u8], offset: usize, value: i32) -> Result<()> {
    set_u32(image, offset + 1, value.cast_unsigned())
}

/// Return the new relative operand of a branch from `next` to `target`, or `None` if the
/// target is not code in the image. `size_of_image` limits the target.
fn remap(context: &Context<'_>, size_of_image: u32, next: u32, target: u32) -> Result<Option<i32>> {
    if target >= size_of_image {
        return Ok(None);
    }
    let offset = context.pe.image_offset(target, 0);
    if offset == 0 || is_data(context, at(offset))? {
        return Ok(None);
    }
    // `msdelta.dll` keeps the low 32 bits of each mapped RVA and subtracts them.
    let low = |rva: u32| low32(context.map(i64::from(rva))).cast_signed();
    Ok(Some(low(target).wrapping_sub(low(next))))
}

/// Find the opcode of a near `jmp` or `jcc` at `offset`. Return the offset of the last
/// opcode byte, or `None`.
fn jump_at(image: &[u8], code: &Code, offset: usize) -> Option<usize> {
    if image[offset] == JMP {
        return Some(offset);
    }
    let next = offset + 1;
    (next < code.end && image[offset] == TWO_BYTE && image[next] & 0xf0 == 0x80).then_some(next)
}

/// Run `RelativeJmpsX86` (`DELTA_FLAG_I386_JMPS`).
pub(super) fn relative_jumps(context: &mut Context<'_>, image: &mut [u8]) -> Result<()> {
    let pe = context.pe;
    check_i386(pe, "RelativeJmpsX86")?;
    let size_of_image = u32_at(image, pe.offsets.size_of_image)?;
    for section in pe.sections() {
        let Some(code) = code(pe, section, image.len())? else {
            continue;
        };
        let mut offset = code.start;
        while offset < code.end {
            let Some(opcode) = jump_at(image, &code, offset) else {
                offset += 1;
                continue;
            };
            offset = opcode;
            // A `jcc` counts only if `MarkNonExe` does not mark its `0F` byte as data.
            let jmp = image[opcode] == JMP;
            let near = jmp || !is_data(context, opcode - 1)?;
            if any_data(context, opcode)? || !near {
                offset += 1;
                continue;
            }
            let old = operand(image, opcode)?;
            if (-128..=127).contains(&old) {
                offset += 1;
                continue;
            }
            let next = code.next_rva(opcode);
            let Some(new) = remap(
                context,
                size_of_image,
                next,
                next.wrapping_add(old.cast_unsigned()),
            )?
            else {
                offset += 1;
                continue;
            };
            match i8::try_from(new) {
                Ok(short) if jmp => {
                    image[opcode] = JMP_SHORT;
                    image[opcode + 1] = short.cast_unsigned();
                }
                Ok(short) => {
                    image[opcode - 1] = image[opcode] & 0x0f | 0x70;
                    image[opcode] = short.cast_unsigned();
                }
                Err(_) if new != old => set_operand(image, opcode, new)?,
                Err(_) => {}
            }
            offset += SIZE;
        }
    }
    Ok(())
}

/// Run `RelativeCallsX86` (`DELTA_FLAG_I386_CALLS`).
pub(super) fn relative_calls(context: &mut Context<'_>, image: &mut [u8]) -> Result<()> {
    let pe = context.pe;
    check_i386(pe, "RelativeCallsX86")?;
    let size_of_image = u32_at(image, pe.offsets.size_of_image)?;
    for section in pe.sections() {
        let Some(code) = code(pe, section, image.len())? else {
            continue;
        };
        let mut offset = code.start;
        while offset < code.end {
            if image[offset] != CALL || any_data(context, offset)? {
                offset += 1;
                continue;
            }
            let old = operand(image, offset)?;
            let next = code.next_rva(offset);
            let Some(new) = remap(
                context,
                size_of_image,
                next,
                next.wrapping_add(old.cast_unsigned()),
            )?
            else {
                offset += 1;
                continue;
            };
            if new != old {
                set_operand(image, offset, new)?;
            }
            offset += SIZE;
        }
    }
    Ok(())
}
