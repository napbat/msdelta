//! Run the transforms that make the source look like the target, as `TransformExecutor` does.
//!
//! Each transform has a flag. `TransformExecutor` runs the transforms of the set flags in a
//! fixed order (`g_transformsMap` of `UpdateCompression.dll`). The transforms share the hint
//! buffer: one byte for each byte of the image. `MarkNonExe` marks the bytes that are not code,
//! and the disassemblers skip them.
//!
//! The rift table of the transforms maps source RVAs to target RVAs.

mod exports;
mod imports;
mod mark_non_exe;
mod pdata_amd64;
mod relocations;
mod resources;
mod unbind;
mod x64;
mod x86;

pub(crate) use unbind::unbind;

use crate::prelude::*;
use crate::rift::RiftTable;
use crate::{Error, Result};

use super::{Pe, TargetInfo};

/// The state that all transforms share (`TransformBase`).
pub(crate) struct Context<'a> {
    /// The structure of the source image.
    pub(crate) pe: &'a Pe,
    /// The rift table from source RVAs to target RVAs.
    pub(crate) rift: &'a RiftTable,
    /// The information about the target.
    pub(crate) info: &'a TargetInfo,
    /// One byte for each byte of the image. `MarkNonExe` sets bit 0 for data that is not code
    /// and bit 1 for headers and data directories.
    pub(crate) hint: Vec<u8>,
}

impl Context<'_> {
    /// Map a source RVA to a target RVA, as `RiftTable::Map` does.
    pub(crate) fn map(&self, rva: i64) -> i64 {
        self.rift.map(rva)
    }
}

/// A transform function.
type Transform = fn(&mut Context<'_>, &mut [u8]) -> Result<()>;

/// An ARM transform, which the crate does not support.
fn arm(_context: &mut Context<'_>, _image: &mut [u8]) -> Result<()> {
    Err(Error::unsupported("the ARM transforms"))
}

/// The transforms and their flags, in the order of `g_transformsMap`.
const ORDER: [(u64, Transform); 18] = [
    (0x2, mark_non_exe::run),
    (0x4, imports::run),
    (0x8, exports::run),
    (0x10, resources::run),
    (0x20, relocations::run),
    (0x4000, cli),
    (0x40_0000, cli),
    (0x8000, cli),
    (0x20_0000, cli),
    (0x40, x86::smash_lock_prefixes),
    (0x80, x86::relative_jumps),
    (0x100, x86::relative_calls),
    (0x200, x64::run),
    (0x80_0000, arm),
    (0x8_0000, arm),
    (0x400, pdata_amd64::run),
    (0x100_0000, arm),
    (0x10_0000, arm),
];

/// A CLI transform. It changes nothing in an image without a CLI header.
fn cli(context: &mut Context<'_>, _image: &mut [u8]) -> Result<()> {
    if context.pe.directories.clr.is_some() {
        return Err(Error::unsupported("the CLI (.NET) transforms"));
    }
    Ok(())
}

/// Run the transforms of `flags` on `image`, in the order of `msdelta.dll`.
pub(crate) fn run(
    image: &mut [u8],
    pe: &Pe,
    flags: u64,
    rift: &RiftTable,
    info: &TargetInfo,
) -> Result<()> {
    let mut context = Context {
        pe,
        rift,
        info,
        hint: vec![0; image.len()],
    };
    for (flag, transform) in ORDER {
        if flags & flag != 0 {
            transform(&mut context, image)?;
        }
    }
    Ok(())
}
