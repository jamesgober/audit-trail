//! Owned counterpart to [`Record`] for storage and replay.
//!
//! [`Record`] is intentionally borrowed: its string fields hold `&str`
//! references into caller memory so the append hot path costs nothing on
//! the heap. Once a record leaves the append path — when a sink wants to
//! retain it, when a verifier reads it back, when a test mutates it for a
//! tampering scenario — it needs to own its bytes. [`OwnedRecord`] is that
//! owned form.
//!
//! Requires the `alloc` feature.

use alloc::string::String;

use crate::clock::Timestamp;
use crate::hash::Digest;
use crate::record::{Action, Actor, Outcome, Record, RecordId, Target};

/// Owned counterpart to [`Record`]. Holds `String`-backed fields instead
/// of borrowed `&str`s, so it can outlive the call that produced it.
///
/// Convert to a borrowed [`Record`] with [`OwnedRecord::as_record`].
///
/// # Example
///
/// ```
/// use audit_trail::{Action, Actor, Digest, Outcome, OwnedRecord, Record, RecordId, Target, Timestamp};
///
/// let borrowed = Record::new(
///     RecordId::GENESIS,
///     Timestamp::from_nanos(1),
///     Actor::new("system"),
///     Action::new("chain.init"),
///     Target::new("chain:0"),
///     Outcome::Success,
///     Digest::ZERO,
///     Digest::ZERO,
/// );
/// let owned = OwnedRecord::from_record(&borrowed);
/// assert_eq!(owned.as_record(), borrowed);
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct OwnedRecord {
    /// Record identifier.
    pub id: RecordId,
    /// Record timestamp.
    pub timestamp: Timestamp,
    /// Actor (who).
    pub actor: String,
    /// Action (what).
    pub action: String,
    /// Target (where).
    pub target: String,
    /// Outcome (result).
    pub outcome: Outcome,
    /// Hash of the preceding record in the chain.
    pub prev_hash: Digest,
    /// Hash of this record.
    pub hash: Digest,
}

impl OwnedRecord {
    /// Copy the fields of a borrowed [`Record`] into a new [`OwnedRecord`].
    #[inline]
    pub fn from_record(record: &Record<'_>) -> Self {
        Self {
            id: record.id(),
            timestamp: record.timestamp(),
            actor: String::from(record.actor().as_str()),
            action: String::from(record.action().as_str()),
            target: String::from(record.target().as_str()),
            outcome: record.outcome(),
            prev_hash: record.prev_hash(),
            hash: record.hash(),
        }
    }

    /// Borrow this owned record as a [`Record`] for a single call.
    #[inline]
    pub fn as_record(&self) -> Record<'_> {
        Record::new(
            self.id,
            self.timestamp,
            Actor::new(&self.actor),
            Action::new(&self.action),
            Target::new(&self.target),
            self.outcome,
            self.prev_hash,
            self.hash,
        )
    }
}

impl From<&Record<'_>> for OwnedRecord {
    #[inline]
    fn from(record: &Record<'_>) -> Self {
        Self::from_record(record)
    }
}
