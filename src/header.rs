//! Parse the header of a PA30 or PA31 delta.
//!
//! A delta starts with the signature `PA30` or `PA31` and the 64-bit target file time. A
//! bitstream follows. In a PA30 delta, the stream has the fields of `DELTA_HEADER_INFO`, the
//! preprocessing buffer and the patch buffer.
//!
//! In a PA31 delta, the stream starts with a buffer that has its own bitstream: the fields of
//! `DELTA_HEADER_INFO`, three numbers and the hash of the source. The preprocessing buffer and
//! the patch buffer follow the buffer. `UpdateCompression.dll` makes PA31 deltas.
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

/// The signature of a PA31 delta.
pub const SIGNATURE_PA31: [u8; 4] = *b"PA31";

/// The signature of the older PA19 format, which the crate does not support.
const SIGNATURE_PA19: [u8; 4] = *b"PA19";

/// The largest hash that a header can hold, in bytes.
const MAX_HASH: usize = 32;

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
    /// `DELTA_FILE_TYPE_CLI4_I386`: an x86 PE image, with the .NET 4 preprocessing.
    pub const CLI4_I386: u64 = 0x10;
    /// `DELTA_FILE_TYPE_CLI4_AMD64`: an x64 PE image, with the .NET 4 preprocessing.
    pub const CLI4_AMD64: u64 = 0x20;
    /// `DELTA_FILE_TYPE_CLI4_ARM`: an ARM PE image, with the .NET 4 preprocessing.
    pub const CLI4_ARM: u64 = 0x40;
    /// `DELTA_FILE_TYPE_CLI4_ARM64`: an ARM64 PE image, with the .NET 4 preprocessing.
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
    /// `CALG_SHA_256`.
    pub const SHA256: u32 = 0x800c;
}

/// The header of a delta: the fields of `DELTA_HEADER_INFO`, and the PA31 fields.
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
    /// The fields of a PA31 delta. `None` for a PA30 delta.
    pub pa31: Option<Pa31Info>,
}

/// The fields that only a PA31 delta has (`DELTA_HEADER_INFO_EX` in `UpdateCompression.dll`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pa31Info {
    /// The size of the header structure of the creator, in bytes (0x88).
    pub info_size: u32,
    /// The version of the delta format (1).
    pub version: u32,
    /// The lowest version of the applier that can apply the delta (0 or 1).
    pub client_min_version: u32,
    /// The `ALG_ID` of the source hash. It is the same as the target hash algorithm.
    pub source_hash_algorithm: u32,
    /// The hash of the source. An empty hash means no source check.
    pub source_hash: Vec<u8>,
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
    /// Parse the header of a PA30 or PA31 delta, as `GetDeltaInfoB` does.
    ///
    /// # Errors
    ///
    /// Returns an error if the signature is not `PA30` or `PA31`, or if the header is not
    /// complete.
    pub fn parse(delta: &[u8]) -> Result<Self> {
        Ok(Delta::parse(delta)?.header)
    }

    /// Return `true` for a PA31 delta.
    #[must_use]
    pub fn is_pa31(&self) -> bool {
        self.pa31.is_some()
    }
}

/// Read a hash buffer of at most 32 bytes.
fn read_hash(reader: &mut BitReader<'_>, name: &str) -> Result<Vec<u8>> {
    let hash = reader.buffer()?;
    if hash.len() > MAX_HASH {
        return Err(Error::invalid_data(format!(
            "the {name} is longer than 32 bytes"
        )));
    }
    Ok(hash.to_vec())
}

/// Read the fields of `DELTA_HEADER_INFO` that the bitstream has.
fn read_info(reader: &mut BitReader<'_>, target_file_time: u64) -> Result<DeltaHeader> {
    let file_type_set = reader.number64()?;
    let file_type = reader.number64()?;
    let flags = reader.number64()?;
    let target_size = reader.number64()?;
    let target_hash_algorithm = reader.number()?;
    let target_hash = read_hash(reader, "target hash")?;
    Ok(DeltaHeader {
        file_type_set,
        file_type,
        flags,
        target_size,
        target_file_time,
        target_hash_algorithm,
        target_hash,
        pa31: None,
    })
}

/// Read the inner header of a PA31 delta.
fn read_pa31(buffer: &[u8], target_file_time: u64) -> Result<DeltaHeader> {
    let mut reader = BitReader::new(buffer)?;
    let mut header = read_info(&mut reader, target_file_time)?;
    let info_size = reader.number()?;
    let version = reader.number()?;
    let client_min_version = reader.number()?;
    if client_min_version > 1 {
        return Err(Error::unsupported(format!(
            "a PA31 delta for applier version {client_min_version}"
        )));
    }
    let source_hash = read_hash(&mut reader, "source hash")?;
    header.pa31 = Some(Pa31Info {
        info_size,
        version,
        client_min_version,
        source_hash_algorithm: header.target_hash_algorithm,
        source_hash,
    });
    Ok(header)
}

impl<'a> Delta<'a> {
    /// Parse the header and the buffers of a delta.
    pub(crate) fn parse(delta: &'a [u8]) -> Result<Self> {
        let Some((signature, rest)) = delta.split_first_chunk::<4>() else {
            return Err(Error::unexpected_end().in_structure("signature"));
        };
        if *signature == SIGNATURE_PA19 {
            return Err(Error::unsupported("the PA19 format"));
        }
        if *signature != SIGNATURE && *signature != SIGNATURE_PA31 {
            return Err(Error::new(ErrorKind::InvalidSignature(*signature)));
        }
        let Some((time, stream)) = rest.split_first_chunk::<8>() else {
            return Err(Error::unexpected_end().in_structure("TargetFileTime"));
        };
        let time = u64::from_le_bytes(*time);
        let context = |e: Error| e.in_structure("DELTA_HEADER_INFO");

        let mut reader = BitReader::new(stream).map_err(context)?;
        let header = if *signature == SIGNATURE {
            read_info(&mut reader, time).map_err(context)?
        } else {
            let inner = reader.buffer().map_err(context)?;
            read_pa31(inner, time).map_err(|e| e.in_structure("PA31 header"))?
        };
        let preprocess = reader
            .buffer()
            .map_err(|e| e.in_structure("preprocessing buffer"))?;
        let patch = reader
            .buffer()
            .map_err(|e| e.in_structure("patch buffer"))?;

        Ok(Self {
            header,
            preprocess,
            patch,
        })
    }
}
