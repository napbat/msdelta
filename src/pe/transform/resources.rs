//! Map the RVAs in the resource directory (`DELTA_FLAG_RESOURCES`, `TransformResources`).
//!
//! The resource directory stores offsets from the start of the resource data. The transform
//! maps each offset as an RVA with the rift table, and stores the offset from the target RVA of
//! the resource data. It changes the data entries, the subdirectory offsets and the name
//! offsets.

use portex::raw::{RawResourceDataEntry, RawResourceDirectory, RawResourceEntry};

use crate::Result;
use crate::pe::image::{Resources, at, low32, pe_error, set_u32};
use crate::prelude::*;

use super::Context;

/// The bit of an offset that marks a subdirectory or a name string.
const HIGH: u32 = 0x8000_0000;

/// One directory that the transform is in (a frame of `TransformRecursive`).
struct Frame {
    /// The file offset of the next entry.
    entry: usize,
    /// The count of entries that remain.
    remaining: usize,
    /// `true` if the transform returns from the subdirectory of `entry`.
    returning: bool,
}

/// Read the resource directory entry at `offset`.
fn entry_at(image: &[u8], offset: usize) -> Result<RawResourceEntry> {
    RawResourceEntry::parse(image, offset).map_err(|e| pe_error(&e))
}

/// Return a directory frame, or `None` for a directory outside the resource data.
fn frame(resources: &Resources, image: &[u8], directory: usize) -> Result<Option<Frame>> {
    // `TransformRecursive` skips a directory that is not in the resource data.
    if directory < resources.base
        || directory.saturating_add(RawResourceDirectory::SIZE) > resources.end
    {
        return Ok(None);
    }
    let header = RawResourceDirectory::parse(image, directory).map_err(|e| pe_error(&e))?;
    let first = directory + RawResourceDirectory::SIZE;
    // `TransformRecursive` limits the entries to the resource data.
    let room = resources.end.saturating_sub(first) / RawResourceEntry::SIZE;
    Ok(Some(Frame {
        entry: first,
        remaining: header.entry_count().min(room),
        returning: false,
    }))
}

/// Run `TransformResources`.
pub(super) fn run(context: &mut Context<'_>, image: &mut [u8]) -> Result<()> {
    let Some(resources) = context.pe.directories.resources else {
        return Ok(());
    };
    // The end of the resource data is in the file: `DataDirectories` limits the size.
    let Some(root) = frame(&resources, image, resources.base)? else {
        return Ok(());
    };
    let base_rva = i64::from(resources.rva);
    let target_base = context.map(base_rva);
    // Map an offset from the start of the resource data.
    let map = |offset: u32| -> u32 {
        let rva = resources.rva.wrapping_add(offset);
        // The target offset keeps the low 32 bits, as `msdelta.dll` does.
        low32(context.map(i64::from(rva)).wrapping_sub(target_base))
    };
    let mut stack = vec![root];
    while let Some(top) = stack.last_mut() {
        if top.remaining == 0 {
            stack.pop();
            continue;
        }
        let entry = entry_at(image, top.entry)?;
        if top.returning {
            top.returning = false;
        } else if entry.is_directory() {
            // A subdirectory: transform it first, then come back to this entry.
            top.returning = true;
            let child = resources.base + at(entry.child_offset());
            // The subdirectory must come after the entry, so the recursion ends.
            if child > entry.offset
                && let Some(child) = frame(&resources, image, child)?
            {
                stack.push(child);
            }
            continue;
        } else {
            let target = resources.base + at(entry.offset_to_data.value);
            // `TransformRecursive` maps a data entry only inside the resource data.
            if target.saturating_add(RawResourceDataEntry::SIZE) <= resources.end {
                let data = RawResourceDataEntry::parse(image, target).map_err(|e| pe_error(&e))?;
                let field = data.offset_to_data;
                set_u32(image, field.offset, map(field.value))?;
            }
            finish_name(image, entry.offset, &map)?;
            advance(&mut stack);
            continue;
        }
        // Back from the subdirectory of this entry.
        let field = entry.offset_to_data;
        let mapped = map(entry.child_offset());
        set_u32(image, field.offset, (field.value & HIGH) | (mapped & !HIGH))?;
        finish_name(image, entry.offset, &map)?;
        advance(&mut stack);
    }
    Ok(())
}

/// Map the name offset of the entry at `offset`, if the entry has a name string.
fn finish_name(image: &mut [u8], offset: usize, map: &impl Fn(u32) -> u32) -> Result<()> {
    let entry = entry_at(image, offset)?;
    if entry.is_named() {
        let field = entry.name_or_id;
        let mapped = map(entry.name_offset());
        set_u32(image, field.offset, (field.value & HIGH) | (mapped & !HIGH))?;
    }
    Ok(())
}

/// Go to the next entry of the top frame.
fn advance(stack: &mut [Frame]) {
    if let Some(top) = stack.last_mut() {
        top.entry += RawResourceEntry::SIZE;
        top.remaining -= 1;
    }
}
