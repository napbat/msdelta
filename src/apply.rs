//! Apply a PA30 or PA31 delta to a source, as `ApplyDeltaB` does.
//!
//! The steps are:
//!
//! 1. Compare the source hash of a PA31 delta with the hash of the source.
//! 2. Preprocess the source. For a PE image, the preprocessing changes the source to look like
//!    the target, and gives a rift table from target positions to source positions.
//! 3. Decompress the target from the patch buffer, or apply a bsdiff patch.
//! 4. Undo the `E8` translation if the delta has `DELTA_FLAG_E8`.
//! 5. Compare the hash of the target with the target hash of the delta.
//!
//! # Example
//!
//! ```no_run
//! # let (source, delta): (&[u8], &[u8]) = (&[], &[]);
//! let target = msdelta::apply(source, delta)?;
//! # Ok::<(), msdelta::Error>(())
//! ```

use crate::header::{Delta, file_type, hash_algorithm};
use crate::prelude::*;
use crate::rift::RiftTable;
use crate::{Error, ErrorKind, Result, bsdiff, e8, lz, pe};
use md5::{Digest, Md5};
use sha1::Sha1;
use sha2::Sha256;

/// `DELTA_FLAG_E8`: undo the x86 `E8` translation after decompression.
const FLAG_E8: u64 = 0x1;
/// The flag of `UpdateCompression.dll` for a bsdiff patch.
const FLAG_BSDIFF: u64 = 0x200_0000;
/// The bit of the file type set that `UpdateCompression.dll` uses for a reverse delta.
const TYPE_SET_REVERSE: u64 = 0x100;

/// Options for [`apply_with`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplyOptions {
    /// The largest target size that the decoder accepts, in bytes. The target size comes from
    /// the delta, so a limit protects against a delta that claims a very large target.
    pub max_target_size: u64,
    /// Compare the hash of the target with the target hash of the delta, and the hash of the
    /// source with the source hash of a PA31 delta.
    pub verify_hash: bool,
}

impl Default for ApplyOptions {
    fn default() -> Self {
        Self {
            max_target_size: (usize::MAX as u64).min(1 << 32),
            verify_hash: true,
        }
    }
}

/// Apply `delta` to `source` with the default [`ApplyOptions`].
///
/// For a delta with no source, give an empty `source`.
///
/// # Errors
///
/// Returns an error if the delta is not valid, uses a feature that the crate does not support,
/// or if a hash is not equal to the hash in the delta.
pub fn apply(source: &[u8], delta: &[u8]) -> Result<Vec<u8>> {
    apply_with(source, delta, &ApplyOptions::default())
}

/// Apply `delta` to `source`.
///
/// # Errors
///
/// Returns the errors of [`apply`], and a `LimitExceeded` error if the target is larger than
/// `options.max_target_size`.
pub fn apply_with(source: &[u8], delta: &[u8], options: &ApplyOptions) -> Result<Vec<u8>> {
    let delta = Delta::parse(delta)?;
    let header = &delta.header;
    if header.target_size > options.max_target_size {
        return Err(Error::new(ErrorKind::LimitExceeded {
            needed: header.target_size,
            limit: options.max_target_size,
        }));
    }
    let target_size = usize::try_from(header.target_size).map_err(|_| {
        Error::new(ErrorKind::LimitExceeded {
            needed: header.target_size,
            limit: usize::MAX as u64,
        })
    })?;
    if let Some(pa31) = &header.pa31 {
        if header.file_type_set & TYPE_SET_REVERSE != 0 {
            return Err(Error::unsupported("a PA31 reverse delta"));
        }
        if options.verify_hash && !pa31.source_hash.is_empty() {
            let algorithm = pa31.source_hash_algorithm;
            if !hash_matches(algorithm, &pa31.source_hash, source)? {
                return Err(Error::new(ErrorKind::SourceHashMismatch { algorithm }));
            }
        }
    }

    let (prepared, rift) = if header.file_type == file_type::RAW {
        (source.to_vec(), RiftTable::new())
    } else {
        pe::preprocess(header.file_type, header.flags, source, delta.preprocess)
            .map_err(|e| e.in_structure("preprocessing"))?
    };

    let mut target = if header.flags & FLAG_BSDIFF != 0 {
        bsdiff::apply(&prepared, delta.patch, header.flags, target_size)?
    } else {
        // The window starts with the source: target positions follow the source.
        let mut window = RiftTable::new();
        let source_size = i64::try_from(source.len())
            .map_err(|_| Error::invalid_data("the source is too large"))?;
        window.add(source_size, 0);
        let mut rift = RiftTable::multiply(&window, &rift);
        rift.reduce();
        lz::decode(delta.patch, &prepared, target_size, &rift)
            .map_err(|e| e.in_structure("patch buffer"))?
    };
    if header.flags & FLAG_E8 != 0 {
        e8::post_process(&mut target);
    }

    if options.verify_hash
        && !hash_matches(header.target_hash_algorithm, &header.target_hash, &target)?
    {
        return Err(Error::new(ErrorKind::HashMismatch {
            algorithm: header.target_hash_algorithm,
        }));
    }
    Ok(target)
}

/// Compare the hash of `data` with `expected`. An empty `expected` hash always matches.
fn hash_matches(algorithm: u32, expected: &[u8], data: &[u8]) -> Result<bool> {
    if expected.is_empty() {
        return Ok(true);
    }
    Ok(match algorithm {
        hash_algorithm::NONE => true,
        hash_algorithm::MD5 => Md5::digest(data).as_slice() == expected,
        hash_algorithm::SHA1 => Sha1::digest(data).as_slice() == expected,
        hash_algorithm::SHA256 => Sha256::digest(data).as_slice() == expected,
        other => {
            return Err(Error::unsupported(format!("hash algorithm {other:#x}")));
        }
    })
}
