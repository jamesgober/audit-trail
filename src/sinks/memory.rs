//! In-memory reference [`Sink`]. Requires the `alloc` feature.

use alloc::vec::Vec;

use crate::error::SinkError;
use crate::owned::OwnedRecord;
use crate::record::Record;
use crate::sink::Sink;

/// In-memory [`Sink`]: appends every record into a `Vec<OwnedRecord>`.
///
/// Intended for tests, prototypes, and short-lived buffering. Holds the
/// entire chain in memory, so it is not suitable for long-running
/// production workloads — use a file-backed or streaming sink instead.
///
/// # Example
///
/// ```
/// use audit_trail::{
///     Action, Actor, Chain, Clock, Digest, Hasher, MemorySink, Outcome, Record, RecordId,
///     SinkError, Target, Timestamp, HASH_LEN,
/// };
///
/// // Minimal hasher / clock for the example.
/// struct XorHasher([u8; HASH_LEN], usize);
/// impl Hasher for XorHasher {
///     fn reset(&mut self) { self.0 = [0u8; HASH_LEN]; self.1 = 0; }
///     fn update(&mut self, bytes: &[u8]) {
///         for b in bytes { self.0[self.1 % HASH_LEN] ^= *b; self.1 = self.1.wrapping_add(1); }
///     }
///     fn finalize(&mut self, out: &mut Digest) { *out = Digest::from_bytes(self.0); }
/// }
/// struct Tick(core::cell::Cell<u64>);
/// impl Clock for Tick {
///     fn now(&self) -> Timestamp {
///         let v = self.0.get(); self.0.set(v + 1); Timestamp::from_nanos(v)
///     }
/// }
///
/// let mut chain = Chain::new(
///     XorHasher([0u8; HASH_LEN], 0),
///     MemorySink::new(),
///     Tick(core::cell::Cell::new(1)),
/// );
/// chain.append(Actor::new("a"), Action::new("x"), Target::new("t"), Outcome::Success).unwrap();
///
/// assert_eq!(chain.sink().len(), 1);
/// ```
#[derive(Clone, Debug, Default)]
pub struct MemorySink {
    records: Vec<OwnedRecord>,
}

impl MemorySink {
    /// Construct an empty [`MemorySink`].
    #[inline]
    pub const fn new() -> Self {
        Self {
            records: Vec::new(),
        }
    }

    /// Construct a [`MemorySink`] with pre-allocated capacity for
    /// `cap` records.
    #[inline]
    pub fn with_capacity(cap: usize) -> Self {
        Self {
            records: Vec::with_capacity(cap),
        }
    }

    /// Number of records currently held.
    #[inline]
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// `true` if no records have been written.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Borrow the recorded log.
    #[inline]
    pub fn records(&self) -> &[OwnedRecord] {
        &self.records
    }

    /// Consume the sink and return its records.
    #[inline]
    pub fn into_records(self) -> Vec<OwnedRecord> {
        self.records
    }

    /// Drop all stored records.
    #[inline]
    pub fn clear(&mut self) {
        self.records.clear();
    }
}

impl Sink for MemorySink {
    fn write(&mut self, record: &Record<'_>) -> core::result::Result<(), SinkError> {
        self.records.push(OwnedRecord::from_record(record));
        Ok(())
    }
}
