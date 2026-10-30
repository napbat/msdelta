//! # msdelta
//!
//! A `no_std`-friendly decoder for Windows MSDELTA patches in the PA30 format. It works on
//! each platform, with no Windows API.
//!
//! Windows updates store most changed files as PA30 deltas. `msdelta.dll` applies them with
//! `ApplyDeltaB`. This crate applies them with the same result.
//!
//! ## Support
//!
//! - The PA30 header (`GetDeltaInfoB`), with [`DeltaHeader::parse`].
//! - Raw deltas (`DELTA_FILE_TYPE_RAW`), with and without a source.
//! - Target hash verification with MD5 and SHA-1.
//!
//! The crate does not support the preprocessing of PE images or a non-empty base rift table
//! yet. It returns an `Unsupported` error for such a delta.
//!
//! ## Example
//!
//! ```no_run
//! # let (source, delta): (&[u8], &[u8]) = (&[], &[]);
//! let header = msdelta::DeltaHeader::parse(delta)?;
//! println!("target: {} bytes", header.target_size);
//! let target = msdelta::apply(source, delta)?;
//! # Ok::<(), msdelta::Error>(())
//! ```

#![cfg_attr(not(feature = "std"), no_std)]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

/// Internal prelude. Each source file uses `use crate::prelude::*;` to get the `alloc` types
/// and macros that the code needs.
pub(crate) mod prelude {
    pub use alloc::format;
    pub use alloc::string::String;
    pub use alloc::vec;
    pub use alloc::vec::Vec;
}

pub mod apply;
mod bits;
pub mod error;
pub mod header;
mod huffman;
mod lz;

pub use apply::{ApplyOptions, apply, apply_with};
pub use error::{Error, ErrorContext, ErrorKind, Result};
pub use header::DeltaHeader;
