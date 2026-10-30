//! Preprocess a PE image source, as `PreProcessor::PreProcessPEForApply` does.
//!
//! For an executable file type, the creator stores information about the target in the
//! preprocessing buffer. The applier changes a copy of the source to look like the target:
//! a chain of transforms maps the addresses in the source to the addresses of the target with
//! a rift table. The decompressor then finds more matches in the changed source.
//!
//! The preprocessing buffer has these items:
//!
//! 1. The target information: image base, global pointer, time stamp, a rift table from target
//!    RVAs to target file offsets, and the CLI metadata of the target.
//! 2. The rift table from source RVAs to target RVAs.
//! 3. The CLI map.
//!
//! The crate supports the I386 and AMD64 file types (also with the CLI4 preprocessing) for
//! images without .NET metadata.

mod image;
mod transform;

pub(crate) use image::Pe;

use crate::bits::BitReader;
use crate::header::file_type;
use crate::prelude::*;
use crate::rift::RiftTable;
use crate::{Error, Result};

/// `DELTA_FLAG_UNBIND`: clear the import binding of the source.
const FLAG_UNBIND: u64 = 0x2000;

/// The information about the target in the preprocessing buffer (`PortableExecutableInfo`).
#[derive(Debug, Clone)]
pub(crate) struct TargetInfo {
    /// The image base of the target.
    pub(crate) image_base: u64,
    /// The global pointer of the target (data directory 8).
    pub(crate) global_pointer: u32,
    /// The time stamp of the target.
    pub(crate) time_stamp: u32,
    /// The rift table from target RVAs to target file offsets.
    pub(crate) rva_to_offset: RiftTable,
}

impl TargetInfo {
    /// Read the target information, as `PortableExecutableInfo::FromBitReader` does.
    fn read(reader: &mut BitReader<'_>) -> Result<Self> {
        let image_base = reader.bits64(64)?;
        let global_pointer = reader.dword()?;
        let time_stamp = reader.dword()?;
        let rva_to_offset = RiftTable::read(reader)?;
        if reader.bit()? {
            return Err(Error::unsupported("CLI (.NET) metadata"));
        }
        Ok(Self {
            image_base,
            global_pointer,
            time_stamp,
            rva_to_offset,
        })
    }
}

/// Return `true` if the crate can preprocess `file_type`.
fn is_supported(file_type: u64) -> bool {
    matches!(
        file_type,
        file_type::I386 | file_type::AMD64 | file_type::CLI4_I386 | file_type::CLI4_AMD64
    )
}

/// Preprocess `source` for a delta of an executable file type.
///
/// Return the changed source and the rift table from target window positions to source
/// window positions.
pub(crate) fn preprocess(
    file_type: u64,
    flags: u64,
    source: &[u8],
    preprocess: &[u8],
) -> Result<(Vec<u8>, RiftTable)> {
    if !is_supported(file_type) {
        return Err(Error::unsupported(format!(
            "the preprocessing of file type {file_type:#x}"
        )));
    }
    let mut image = source.to_vec();
    let pe = Pe::parse(&image)?;
    if flags & FLAG_UNBIND != 0 {
        transform::unbind(&mut image, &pe)?;
    }
    let source_offset_to_rva = pe.image_offset_to_rva();

    let mut reader = BitReader::new(preprocess)?;
    let info = TargetInfo::read(&mut reader).map_err(|e| e.in_structure("target information"))?;
    let used = RiftTable::read(&mut reader).map_err(|e| e.in_structure("RVA rift table"))?;
    if reader.bit()? {
        return Err(Error::unsupported("a CLI (.NET) map"));
    }
    if reader.bits_left() != 0 {
        return Err(Error::invalid_data(
            "the preprocessing buffer has unused data",
        ));
    }

    transform::run(&mut image, &pe, flags, &used, &info)?;
    pe.set_target_fields(&mut image, &info)?;

    let compression = RiftTable::multiply(
        &RiftTable::multiply(&source_offset_to_rva, &used),
        &info.rva_to_offset,
    )
    .reverse();
    Ok((image, compression))
}
