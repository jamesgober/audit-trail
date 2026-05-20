//! The pluggable [`Sink`] trait that persists audit records.

use crate::error::SinkError;
use crate::record::Record;

/// A target that consumes audit records produced by a [`crate::Chain`].
///
/// Implementations might write to a local append-only file, ship records to
/// a remote logging service, push to a queue, or buffer in memory for tests.
/// Sinks see records in chain order and must persist them durably enough for
/// the deployment's compliance requirements.
///
/// # Example
///
/// ```
/// use audit_trail::{Record, Sink, SinkError};
///
/// /// Counts records without persisting them. Useful for tests.
/// #[derive(Default)]
/// struct CountingSink(usize);
///
/// impl Sink for CountingSink {
///     fn write(&mut self, _record: &Record<'_>) -> Result<(), SinkError> {
///         self.0 += 1;
///         Ok(())
///     }
/// }
///
/// let mut sink = CountingSink::default();
/// // Wire `sink` into a `Chain` and observe the count grow.
/// assert_eq!(sink.0, 0);
/// ```
pub trait Sink {
    /// Persist a single record.
    ///
    /// The record is passed by reference because its string fields are
    /// borrowed from the caller. A sink that needs to retain the record past
    /// the call must copy or encode the relevant bytes before returning.
    ///
    /// # Errors
    ///
    /// Implementations return [`SinkError`] when the underlying backend
    /// cannot accept the record. [`Chain::append`] wraps that error as
    /// [`Error::Sink`] and propagates it without advancing the chain's
    /// internal state, so a failed write leaves the chain in a clean
    /// "as-if-the-call-never-happened" state and the caller can retry.
    ///
    /// [`Chain::append`]: crate::Chain::append
    /// [`Error::Sink`]: crate::Error::Sink
    fn write(&mut self, record: &Record<'_>) -> core::result::Result<(), SinkError>;
}
