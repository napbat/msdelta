//! Map the RVAs in the resource directory (`DELTA_FLAG_RESOURCES`, `TransformResources`).
//!
//! The resource directory stores offsets from the start of the resource data. The transform
//! maps each offset as an RVA with the rift table, and stores the offset from the target RVA of
//! the resource data. It changes the data entries, the subdirectory offsets and the name
//! offsets.

use crate::Result;
use crate::pe::image::{Resources, at, low32, set_u32, u16_at, u32_at};
use crate::prelude::*;

use super::Context;

/// The size of `IMAGE_RESOURCE_DIRECTORY`.
const DIRECTORY_SIZE: usize = 16;
/// The size of `IMAGE_RESOURCE_DIRECTORY_ENTRY`.
const ENTRY_SIZE: usize = 8;
/// The size of `IMAGE_RESOURCE_DATA_ENTRY`.
const DATA_SIZE: usize = 16;
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

/// Return a directory frame, or `None` for a directory outside the resource data.
fn frame(resources: &Resources, image: &[u8], directory: usize) -> Result<Option<Frame>> {
    if directory < resources.base || directory.saturating_add(DIRECTORY_SIZE) > resources.end {
        return Ok(None);
    }
    let count =
        usize::from(u16_at(image, directory + 12)?) + usize::from(u16_at(image, directory + 14)?);
    let first = directory + DIRECTORY_SIZE;
    let room = resources.end.saturating_sub(first) / ENTRY_SIZE;
    Ok(Some(Frame {
        entry: first,
        remaining: count.min(room),
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
        let entry = top.entry;
        let data = u32_at(image, entry + 4)?;
        if top.returning {
            top.returning = false;
        } else if data & HIGH != 0 {
            // A subdirectory: transform it first, then come back to this entry.
            top.returning = true;
            let offset = at(data & !HIGH);
            let child = resources.base + offset;
            // The subdirectory must come after the entry, so the recursion ends.
            if child > entry
                && let Some(child) = frame(&resources, image, child)?
            {
                stack.push(child);
            }
            continue;
        } else {
            let target = resources.base + at(data);
            if target.saturating_add(DATA_SIZE) <= resources.end {
                let value = u32_at(image, target)?;
                set_u32(image, target, map(value))?;
            }
            finish_name(image, entry, &map)?;
            advance(&mut stack);
            continue;
        }
        // Back from the subdirectory of this entry.
        let data = u32_at(image, entry + 4)?;
        let mapped = map(data & !HIGH);
        set_u32(image, entry + 4, (data & HIGH) | (mapped & !HIGH))?;
        finish_name(image, entry, &map)?;
        advance(&mut stack);
    }
    Ok(())
}

/// Map the name offset of an entry with a name string.
fn finish_name(image: &mut [u8], entry: usize, map: &impl Fn(u32) -> u32) -> Result<()> {
    let name = u32_at(image, entry)?;
    if name & HIGH != 0 {
        let mapped = map(name & !HIGH);
        set_u32(image, entry, (name & HIGH) | (mapped & !HIGH))?;
    }
    Ok(())
}

/// Go to the next entry of the top frame.
fn advance(stack: &mut [Frame]) {
    if let Some(top) = stack.last_mut() {
        top.entry += ENTRY_SIZE;
        top.remaining -= 1;
    }
}
