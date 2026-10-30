//! Parse the header of a PA30 delta.
//!
//! A PA30 delta starts with the signature `PA30` and the 64-bit target file time. A bitstream
//! follows, with the fields of `DELTA_HEADER_INFO`, the preprocessing buffer and the patch
//! buffer.
//!
//! # Example
//!
//! ```no_run
//! # let delta: &[u8] = &[];
//! let header = msdelta::DeltaHeader::parse(delta)?;
//! println!("target size: {}", header.target_size);
//! # Ok::<(), msdelta::Error>(())
//! ```

use crate::bits::BitReader;
use crate::prelude::*;
use crate::{Error, ErrorKind, Result};

/// The signature of a PA30 delta.
pub const SIGNATURE: [u8; 4] = *b"PA30";

/// The values of `DELTA_FILE_TYPE`.
pub mod file_type {
    /// `DELTA_FILE_TYPE_RAW`: any data, with no preprocessing.
    pub const RAW: u64 = 0x1;
    /// `DELTA_FILE_TYPE_I386`: an x86 PE image.
    pub const I386: u64 = 0x2;
    /// `DELTA_FILE_TYPE_IA64`: an Itanium PE image.
    pub const IA64: u64 = 0x4;
    /// `DELTA_FILE_TYPE_AMD64`: an x64 PE image.
    pub const AMD64: u64 = 0x8;
    /// `DELTA_FILE_TYPE_CLI4_I386`: a .NET x86 PE image.
    pub const CLI4_I386: u64 = 0x10;
    /// `DELTA_FILE_TYPE_CLI4_AMD64`: a .NET x64 PE image.
    pub const CLI4_AMD64: u64 = 0x20;
    /// `DELTA_FILE_TYPE_CLI4_ARM`: a .NET ARM PE image.
    pub const CLI4_ARM: u64 = 0x40;
    /// `DELTA_FILE_TYPE_CLI4_ARM64`: a .NET ARM64 PE image.
    pub const CLI4_ARM64: u64 = 0x80;
    /// `DELTA_FILE_TYPE_ARM`: an ARM PE image.
    pub const ARM: u64 = 0x100;
    /// `DELTA_FILE_TYPE_ARM64`: an ARM64 PE image.
    pub const ARM64: u64 = 0x200;
}

/// The `ALG_ID` values of the target hash.
pub mod hash_algorithm {
    /// No target hash.
    pub const NONE: u32 = 0;
    /// `CALG_MD5`.
    pub const MD5: u32 = 0x8003;
    /// `CALG_SHA1`.
    pub const SHA1: u32 = 0x8004;
}

/// The header of a PA30 delta: the fields of `DELTA_HEADER_INFO`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeltaHeader {
    /// `FileTypeSet`: the file types that the creator allowed (see [`file_type`]).
    pub file_type_set: u64,
    /// `FileType`: the file type of the source and the target (see [`file_type`]).
    pub file_type: u64,
    /// `Flags`: the `DELTA_FLAG_*` preprocessing flags.
    pub flags: u64,
    /// `TargetSize`: the size of the target, in bytes.
    pub target_size: u64,
    /// `TargetFileTime`: the file time of the target, in 100-ns units since 1601.
    pub target_file_time: u64,
    /// `TargetHashAlgId`: the `ALG_ID` of the target hash (see [`hash_algorithm`]).
    pub target_hash_algorithm: u32,
    /// `TargetHash`: the hash of the target.
    pub target_hash: Vec<u8>,
}

/// A parsed delta: the header and the two buffers that follow it.
#[derive(Debug, Clone)]
pub(crate) struct Delta<'a> {
    pub(crate) header: DeltaHeader,
    /// The preprocessing buffer. It is empty for raw data.
    pub(crate) preprocess: &'a [u8],
    /// The patch buffer: the base rift table and the compressed target.
    pub(crate) patch: &'a [u8],
}

impl DeltaHeader {
    /// Parse the header of a PA30 delta, as `GetDeltaInfoB` does.
    ///
    /// # Errors
    ///
    /// Returns an error if the signature is not `PA30` or the header is not complete.
    pub fn parse(delta: &[u8]) -> Result<Self> {
        Ok(Delta::parse(delta)?.header)
    }
}

impl<'a> Delta<'a> {
    /// Parse the header and the buffers of a delta.
    pub(crate) fn parse(delta: &'a [u8]) -> Result<Self> {
        let Some((signature, rest)) = delta.split_first_chunk::<4>() else {
            return Err(Error::unexpected_end().in_structure("PA30 signature"));
        };
        if *signature != SIGNATURE {
            return Err(Error::new(ErrorKind::InvalidSignature(*signature)));
        }
        let Some((time, stream)) = rest.split_first_chunk::<8>() else {
            return Err(Error::unexpected_end().in_structure("TargetFileTime"));
        };
        let context = |e: Error| e.in_structure("DELTA_HEADER_INFO");

        let mut reader = BitReader::new(stream).map_err(context)?;
        let file_type_set = reader.number64().map_err(context)?;
        let file_type = reader.number64().map_err(context)?;
        let flags = reader.number64().map_err(context)?;
        let target_size = reader.number64().map_err(context)?;
        let target_hash_algorithm = reader.number().map_err(context)?;
        let target_hash = reader.buffer().map_err(context)?.to_vec();
        let preprocess = reader
            .buffer()
            .map_err(|e| e.in_structure("preprocessing buffer"))?;
        let patch = reader
            .buffer()
            .map_err(|e| e.in_structure("patch buffer"))?;

        Ok(Self {
            header: DeltaHeader {
                file_type_set,
                file_type,
                flags,
                target_size,
                target_file_time: u64::from_le_bytes(*time),
                target_hash_algorithm,
                target_hash,
            },
            preprocess,
            patch,
        })
    }
}
