//! Error and result types for `audit-trail` operations.
//!
//! The crate uses a single [`Error`] enum with a small number of broad
//! categories. The enum is `#[non_exhaustive]` so further variants may be
//! added in minor releases without breaking callers.

use core::fmt;

use crate::record::RecordId;

/// Convenience [`Result`] type alias used throughout the crate.
///
/// # Example
///
/// ```
/// fn do_audit() -> audit_trail::Result<()> {
///     Ok(())
/// }
/// assert!(do_audit().is_ok());
/// ```
pub type Result<T> = core::result::Result<T, Error>;

/// Error categories produced by `audit-trail`.
///
/// Variants are intentionally coarse-grained. Concrete backends communicate
/// finer-grained failures via [`SinkError`] wrapped inside [`Error::Sink`].
///
/// # Example
///
/// ```
/// use audit_trail::Error;
///
/// let err = Error::ChainBroken;
/// assert_eq!(err.to_string(), "audit hash chain broken");
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// A configured sink failed to persist a record.
    Sink(SinkError),
    /// The running hash chain failed a generic integrity check.
    ///
    /// Verification surfaces more specific variants
    /// ([`Error::HashMismatch`], [`Error::LinkMismatch`],
    /// [`Error::IdMismatch`]) when possible.
    ChainBroken,
    /// A fixed-size buffer or counter exceeded its capacity
    /// (for example, the record id counter overflowed).
    Capacity,
    /// The configured clock returned a timestamp that violates monotonicity.
    NonMonotonicClock,
    /// A record's stored `hash` does not match the digest recomputed from
    /// its fields. Carries the failing record's id.
    HashMismatch(RecordId),
    /// A record's `prev_hash` does not equal the previous record's `hash`.
    /// Carries the failing record's id.
    LinkMismatch(RecordId),
    /// A record's id is not the expected next id in the chain. Carries the
    /// id that was found.
    IdMismatch(RecordId),
    /// Input ended before a complete record could be decoded.
    Truncated,
    /// Encoded bytes are present but do not parse as a valid record
    /// (bad magic, bad version, invalid UTF-8, length-prefix mismatch, …).
    InvalidFormat,
    /// Underlying I/O failure (only emitted by `std`-gated readers/sinks).
    /// Detail is suppressed to keep [`Error`] both `Copy` and `no_std`-safe;
    /// callers needing the full [`std::io::Error`] should use the
    /// constructor methods that return [`std::io::Result`] directly.
    Io,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sink(_) => f.write_str("audit sink failure"),
            Self::ChainBroken => f.write_str("audit hash chain broken"),
            Self::Capacity => f.write_str("audit capacity exceeded"),
            Self::NonMonotonicClock => f.write_str("audit clock not monotonic"),
            Self::HashMismatch(id) => write!(f, "audit hash mismatch at record {}", id.as_u64()),
            Self::LinkMismatch(id) => write!(f, "audit link mismatch at record {}", id.as_u64()),
            Self::IdMismatch(id) => write!(f, "audit id mismatch at record {}", id.as_u64()),
            Self::Truncated => f.write_str("audit input truncated"),
            Self::InvalidFormat => f.write_str("audit input invalid format"),
            Self::Io => f.write_str("audit i/o failure"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Sink(inner) => Some(inner),
            _ => None,
        }
    }
}

/// Opaque error returned by [`crate::Sink`] implementations.
///
/// Backends map their internal failures to one of a small set of categories.
/// Categories are deliberately coarse: callers either retry the write or
/// surface the audit failure upstream.
///
/// # Example
///
/// ```
/// use audit_trail::SinkError;
///
/// let err = SinkError::Io;
/// assert_eq!(err.to_string(), "sink i/o failure");
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SinkError {
    /// Underlying I/O failure (disk, socket, etc.).
    Io,
    /// Sink has reached its capacity and cannot accept more records.
    Capacity,
    /// Sink has been closed and will accept no further writes.
    Closed,
    /// Sink-specific failure not covered by the other variants.
    Other,
}

impl fmt::Display for SinkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io => f.write_str("sink i/o failure"),
            Self::Capacity => f.write_str("sink capacity exceeded"),
            Self::Closed => f.write_str("sink closed"),
            Self::Other => f.write_str("sink error"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for SinkError {}

impl From<SinkError> for Error {
    #[inline]
    fn from(value: SinkError) -> Self {
        Self::Sink(value)
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::{Error, SinkError};
    use crate::record::RecordId;

    /// Exercises [`core::fmt::Display`] for every [`Error`] variant. Drives
    /// the format strings so they cannot rot silently.
    #[test]
    fn error_display_covers_all_variants() {
        let id = RecordId::from_u64(7);
        assert_eq!(Error::Sink(SinkError::Io).to_string(), "audit sink failure");
        assert_eq!(Error::ChainBroken.to_string(), "audit hash chain broken");
        assert_eq!(Error::Capacity.to_string(), "audit capacity exceeded");
        assert_eq!(
            Error::NonMonotonicClock.to_string(),
            "audit clock not monotonic"
        );
        assert_eq!(
            Error::HashMismatch(id).to_string(),
            "audit hash mismatch at record 7"
        );
        assert_eq!(
            Error::LinkMismatch(id).to_string(),
            "audit link mismatch at record 7"
        );
        assert_eq!(
            Error::IdMismatch(id).to_string(),
            "audit id mismatch at record 7"
        );
        assert_eq!(Error::Truncated.to_string(), "audit input truncated");
        assert_eq!(
            Error::InvalidFormat.to_string(),
            "audit input invalid format"
        );
        assert_eq!(Error::Io.to_string(), "audit i/o failure");
    }

    /// Exercises [`core::fmt::Display`] for every [`SinkError`] variant.
    #[test]
    fn sink_error_display_covers_all_variants() {
        assert_eq!(SinkError::Io.to_string(), "sink i/o failure");
        assert_eq!(SinkError::Capacity.to_string(), "sink capacity exceeded");
        assert_eq!(SinkError::Closed.to_string(), "sink closed");
        assert_eq!(SinkError::Other.to_string(), "sink error");
    }

    /// [`Error::source`] points at the wrapped [`SinkError`] when present.
    #[test]
    fn error_source_chains_to_sink_error() {
        use std::error::Error as _;
        let err = Error::Sink(SinkError::Closed);
        assert!(err.source().is_some());
        let other = Error::Truncated;
        assert!(other.source().is_none());
    }

    /// `From<SinkError> for Error` wraps the inner value losslessly.
    #[test]
    fn from_sink_error_wraps() {
        let e: Error = SinkError::Capacity.into();
        assert_eq!(e, Error::Sink(SinkError::Capacity));
    }
}
