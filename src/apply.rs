//! Apply a PA30 delta to a source, as `ApplyDeltaB` does.
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
use crate::{Error, ErrorKind, Result, lz};
use md5::{Digest, Md5};
use sha1::Sha1;

/// Options for [`apply_with`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplyOptions {
    /// The largest target size that the decoder accepts, in bytes. The target size comes from
    /// the delta, so a limit protects against a delta that claims a very large target.
    pub max_target_size: u64,
    /// Compare the hash of the target with the target hash of the delta.
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
/// or if the target hash is not equal to the hash of the output.
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
    if header.file_type != file_type::RAW {
        return Err(Error::unsupported(format!(
            "file type {:#x} needs preprocessing",
            header.file_type
        )));
    }
    if header.flags != 0 {
        return Err(Error::unsupported(format!("flags {:#x}", header.flags)));
    }
    if !delta.preprocess.is_empty() {
        return Err(Error::unsupported("a preprocessing buffer for raw data"));
    }
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

    let target =
        lz::decode(delta.patch, source, target_size).map_err(|e| e.in_structure("patch buffer"))?;

    if options.verify_hash {
        verify_hash(header.target_hash_algorithm, &header.target_hash, &target)?;
    }
    Ok(target)
}

/// Compare the hash of `target` with `expected`.
fn verify_hash(algorithm: u32, expected: &[u8], target: &[u8]) -> Result<()> {
    let matches = match algorithm {
        hash_algorithm::NONE => true,
        hash_algorithm::MD5 => Md5::digest(target).as_slice() == expected,
        hash_algorithm::SHA1 => Sha1::digest(target).as_slice() == expected,
        other => {
            return Err(Error::unsupported(format!("hash algorithm {other:#x}")));
        }
    };
    if matches {
        Ok(())
    } else {
        Err(Error::new(ErrorKind::HashMismatch { algorithm }))
    }
}
