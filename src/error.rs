//! Error types for PA30 parsing and patch application.
//!
//! An error can have a context: a bit position in a bitstream, a structure name and details.
//!
//! # Example
//!
//! ```
//! match msdelta::apply(b"", b"PA19") {
//!     Ok(_) => println!("applied"),
//!     Err(e) => eprintln!("Error: {e}"),
//! }
//! ```

use crate::prelude::*;
use core::fmt;

/// Result type alias for msdelta operations.
pub type Result<T, E = Error> = core::result::Result<T, E>;

/// Information about the location of an error.
#[derive(Debug, Clone, Default)]
pub struct ErrorContext {
    /// Byte offset in the delta where the error occurred (if known).
    pub offset: Option<u64>,
    /// Name of the structure that the decoder was reading (if known).
    pub structure: Option<String>,
    /// Additional details about the error.
    pub details: Option<String>,
}

impl ErrorContext {
    /// Return `true` if the context has no information.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.offset.is_none() && self.structure.is_none() && self.details.is_none()
    }
}

impl fmt::Display for ErrorContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut parts = Vec::new();
        if let Some(offset) = self.offset {
            parts.push(format!("offset {offset:#x}"));
        }
        if let Some(structure) = &self.structure {
            parts.push(format!("in {structure}"));
        }
        if let Some(details) = &self.details {
            parts.push(details.clone());
        }
        write!(f, "{}", parts.join(", "))
    }
}

/// An error from parsing or applying a delta.
#[derive(Debug)]
pub struct Error {
    /// The error kind.
    pub kind: ErrorKind,
    /// Optional context about where the error occurred.
    pub context: Option<ErrorContext>,
}

/// The kind of error that occurred.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ErrorKind {
    /// The delta does not start with `PA30`.
    InvalidSignature([u8; 4]),
    /// A bitstream ended before the decoder read all data.
    UnexpectedEnd,
    /// A value in the delta is not valid.
    InvalidData(String),
    /// The delta uses a feature that the crate does not support yet.
    Unsupported(String),
    /// The delta needs more memory than the limit allows.
    LimitExceeded {
        /// The size that the delta needs, in bytes.
        needed: u64,
        /// The limit, in bytes.
        limit: u64,
    },
    /// The target hash in the delta is not equal to the hash of the output.
    HashMismatch {
        /// The `ALG_ID` of the hash.
        algorithm: u32,
    },
}

impl Error {
    /// Create a new error with the given kind.
    #[must_use]
    pub fn new(kind: ErrorKind) -> Self {
        Self {
            kind,
            context: None,
        }
    }

    /// Add offset context.
    #[must_use]
    pub fn at_offset(mut self, offset: u64) -> Self {
        self.context
            .get_or_insert_with(ErrorContext::default)
            .offset = Some(offset);
        self
    }

    /// Add structure name context.
    #[must_use]
    pub fn in_structure(mut self, name: impl Into<String>) -> Self {
        self.context
            .get_or_insert_with(ErrorContext::default)
            .structure = Some(name.into());
        self
    }

    /// Add details.
    #[must_use]
    pub fn with_details(mut self, details: impl Into<String>) -> Self {
        self.context
            .get_or_insert_with(ErrorContext::default)
            .details = Some(details.into());
        self
    }

    /// Get the context if present.
    #[must_use]
    pub fn context(&self) -> Option<&ErrorContext> {
        self.context.as_ref()
    }

    /// Get the error kind.
    #[must_use]
    pub fn kind(&self) -> &ErrorKind {
        &self.kind
    }

    /// Create an `UnexpectedEnd` error.
    #[must_use]
    pub fn unexpected_end() -> Self {
        Self::new(ErrorKind::UnexpectedEnd)
    }

    /// Create an `InvalidData` error.
    pub fn invalid_data(msg: impl Into<String>) -> Self {
        Self::new(ErrorKind::InvalidData(msg.into()))
    }

    /// Create an `Unsupported` error.
    pub fn unsupported(msg: impl Into<String>) -> Self {
        Self::new(ErrorKind::Unsupported(msg.into()))
    }
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ErrorKind::InvalidSignature(sig) => {
                write!(f, "Invalid signature {sig:02x?} (expected 'PA30')")
            }
            ErrorKind::UnexpectedEnd => write!(f, "Unexpected end of bitstream"),
            ErrorKind::InvalidData(msg) => write!(f, "Invalid delta: {msg}"),
            ErrorKind::Unsupported(msg) => write!(f, "Unsupported delta feature: {msg}"),
            ErrorKind::LimitExceeded { needed, limit } => {
                write!(
                    f,
                    "The delta needs {needed} bytes, more than the limit of {limit}"
                )
            }
            ErrorKind::HashMismatch { algorithm } => {
                write!(f, "Target hash mismatch (ALG_ID {algorithm:#x})")
            }
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.kind)?;
        if let Some(ctx) = &self.context
            && !ctx.is_empty()
        {
            write!(f, " ({ctx})")?;
        }
        Ok(())
    }
}

impl core::error::Error for Error {}

impl From<ErrorKind> for Error {
    fn from(kind: ErrorKind) -> Self {
        Self::new(kind)
    }
}
