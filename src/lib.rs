//! # msdelta
//!
//! A `no_std`-friendly decoder for Windows MSDELTA patches in the PA30 and PA31 formats. It
//! works on each platform, with no Windows API.
//!
//! Windows updates store most changed files as deltas. `msdelta.dll` and
//! `UpdateCompression.dll` apply them with `ApplyDeltaB`. This crate applies them with the
//! same result.
//!
//! ## Support
//!
//! - The PA30 and PA31 headers (`GetDeltaInfoB`), with [`DeltaHeader::parse`].
//! - Raw deltas (`DELTA_FILE_TYPE_RAW`), with and without a source.
//! - Base rift tables and the rift tables of the PE preprocessing.
//! - The PE preprocessing of x86 and x64 images (`I386`, `AMD64`, `CLI4_I386`, `CLI4_AMD64`)
//!   without .NET metadata.
//! - bsdiff patches of PA31 deltas, with the `lzms` feature.
//! - Target and source hash verification with MD5, SHA-1 and SHA-256.
//!
//! The crate returns an `Unsupported` error for a delta that needs a feature that it does not
//! have, for example the ARM transforms or .NET metadata.
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
mod bsdiff;
mod e8;
pub mod error;
pub mod header;
mod huffman;
mod int_format;
mod lz;
mod pe;
mod rift;

pub use apply::{ApplyOptions, apply, apply_with};
pub use error::{Error, ErrorContext, ErrorKind, Result};
pub use header::{DeltaHeader, Pa31Info};
