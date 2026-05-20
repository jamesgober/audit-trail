//! The [`Chain`] type: the append-only, hash-linked audit log.
//!
//! `Chain` wires together a [`Hasher`], a [`Sink`], and a [`Clock`] into a
//! single append-only structure. Every successful append:
//!
//! 1. Asks the clock for the current timestamp (enforcing monotonicity).
//! 2. Allocates the next [`RecordId`] (checked for overflow).
//! 3. Computes this record's hash by feeding canonical bytes through the
//!    hasher together with the previous record's hash.
//! 4. Writes the [`Record`] to the sink.
//! 5. Updates the chain's running `last_hash` and `next_id`.
//!
//! The path is allocation-free: every field is borrowed or stack-resident.

use crate::clock::{Clock, Timestamp};
use crate::error::{Error, Result};
use crate::hash::{Digest, Hasher};
use crate::record::{Action, Actor, Outcome, Record, RecordId, Target};
use crate::sink::Sink;

/// Stable separator byte mixed between hashed fields to prevent
/// concatenation-collision attacks (e.g. `"ab" + "c"` vs `"a" + "bc"`).
const FIELD_SEP: u8 = 0x1f;

/// An append-only chain of audit records.
///
/// The chain is generic over its three pluggable components:
///
/// * `H: Hasher` — the cryptographic hash function used to link records.
/// * `S: Sink` — the backend that persists each record.
/// * `C: Clock` — the time source.
///
/// `Chain` is `!Sync` by virtue of holding mutable state on `&mut self`.
/// Concurrent appenders should serialize on the chain or shard their writes
/// across independent chains.
///
/// # Example
///
/// ```
/// use audit_trail::{
///     Action, Actor, Chain, Clock, Digest, Hasher, Outcome, Record, RecordId,
///     Sink, SinkError, Target, Timestamp, HASH_LEN,
/// };
///
/// // Minimal (insecure) Hasher: XOR-fold bytes into a 32-byte buffer.
/// struct XorHasher([u8; HASH_LEN]);
/// impl Hasher for XorHasher {
///     fn reset(&mut self) { self.0 = [0u8; HASH_LEN]; }
///     fn update(&mut self, bytes: &[u8]) {
///         for (i, b) in bytes.iter().enumerate() { self.0[i % HASH_LEN] ^= *b; }
///     }
///     fn finalize(&mut self, out: &mut Digest) { *out = Digest::from_bytes(self.0); }
/// }
///
/// // A clock that ticks one nanosecond per call.
/// struct TickClock(core::cell::Cell<u64>);
/// impl Clock for TickClock {
///     fn now(&self) -> Timestamp {
///         let v = self.0.get(); self.0.set(v + 1); Timestamp::from_nanos(v)
///     }
/// }
///
/// // An in-memory sink that records hashes for verification.
/// #[derive(Default)]
/// struct VecSink(Vec<Digest>);
/// impl Sink for VecSink {
///     fn write(&mut self, r: &Record<'_>) -> Result<(), SinkError> {
///         self.0.push(r.hash()); Ok(())
///     }
/// }
///
/// let mut chain = Chain::new(
///     XorHasher([0u8; HASH_LEN]),
///     VecSink::default(),
///     TickClock(core::cell::Cell::new(1)),
/// );
///
/// let id = chain.append(
///     Actor::new("user-1"),
///     Action::new("user.login"),
///     Target::new("session:abc"),
///     Outcome::Success,
/// ).expect("append");
/// assert_eq!(id, RecordId::GENESIS);
/// ```
#[derive(Debug)]
pub struct Chain<H, S, C>
where
    H: Hasher,
    S: Sink,
    C: Clock,
{
    hasher: H,
    sink: S,
    clock: C,
    next_id: u64,
    last_hash: Digest,
    last_timestamp: Timestamp,
}

impl<H, S, C> Chain<H, S, C>
where
    H: Hasher,
    S: Sink,
    C: Clock,
{
    /// Construct a fresh chain starting from genesis.
    ///
    /// The chain begins with `next_id = 0` and `last_hash = Digest::ZERO`.
    /// To resume a previously persisted chain, use [`Chain::resume`].
    #[inline]
    pub fn new(hasher: H, sink: S, clock: C) -> Self {
        Self {
            hasher,
            sink,
            clock,
            next_id: 0,
            last_hash: Digest::ZERO,
            last_timestamp: Timestamp::EPOCH,
        }
    }

    /// Resume a chain from a previously persisted tail.
    ///
    /// `next_id` is the identifier the next appended record will receive.
    /// `last_hash` is the hash of the most recently persisted record (or
    /// [`Digest::ZERO`] if the chain is empty).
    /// `last_timestamp` is the timestamp of the most recently persisted
    /// record (or [`Timestamp::EPOCH`] if the chain is empty).
    #[inline]
    pub fn resume(
        hasher: H,
        sink: S,
        clock: C,
        next_id: RecordId,
        last_hash: Digest,
        last_timestamp: Timestamp,
    ) -> Self {
        Self {
            hasher,
            sink,
            clock,
            next_id: next_id.as_u64(),
            last_hash,
            last_timestamp,
        }
    }

    /// Identifier the next appended record will receive.
    #[inline]
    pub const fn next_id(&self) -> RecordId {
        RecordId::from_u64(self.next_id)
    }

    /// Hash of the most recently appended record (or [`Digest::ZERO`] if
    /// none).
    #[inline]
    pub const fn last_hash(&self) -> Digest {
        self.last_hash
    }

    /// Timestamp of the most recently appended record (or
    /// [`Timestamp::EPOCH`] if none).
    #[inline]
    pub const fn last_timestamp(&self) -> Timestamp {
        self.last_timestamp
    }

    /// Append a record to the chain.
    ///
    /// Returns the new record's [`RecordId`]. On error the chain state is
    /// left unchanged: the sink is only updated after the hash is computed
    /// and the timestamp/id checks have passed, and `last_hash` /
    /// `last_timestamp` / `next_id` are only updated after the sink write
    /// succeeds.
    ///
    /// # Errors
    ///
    /// * [`Error::NonMonotonicClock`] — the clock returned a timestamp not
    ///   greater than the previously stored timestamp.
    /// * [`Error::Capacity`] — the record id counter would overflow.
    /// * [`Error::Sink`] — the sink rejected the write.
    pub fn append(
        &mut self,
        actor: Actor<'_>,
        action: Action<'_>,
        target: Target<'_>,
        outcome: Outcome,
    ) -> Result<RecordId> {
        let timestamp = self.clock.now();
        if self.next_id > 0 && timestamp <= self.last_timestamp {
            return Err(Error::NonMonotonicClock);
        }

        let id = RecordId::from_u64(self.next_id);
        let next = self.next_id.checked_add(1).ok_or(Error::Capacity)?;
        let prev_hash = self.last_hash;

        self.hasher.reset();
        self.hasher.update(&id.as_u64().to_be_bytes());
        self.hasher.update(&[FIELD_SEP]);
        self.hasher.update(&timestamp.as_nanos().to_be_bytes());
        self.hasher.update(&[FIELD_SEP]);
        self.hasher.update(actor.as_str().as_bytes());
        self.hasher.update(&[FIELD_SEP]);
        self.hasher.update(action.as_str().as_bytes());
        self.hasher.update(&[FIELD_SEP]);
        self.hasher.update(target.as_str().as_bytes());
        self.hasher.update(&[FIELD_SEP]);
        self.hasher.update(&[outcome.as_u8()]);
        self.hasher.update(&[FIELD_SEP]);
        self.hasher.update(prev_hash.as_bytes());

        let mut hash = Digest::ZERO;
        self.hasher.finalize(&mut hash);

        let record = Record::new(
            id, timestamp, actor, action, target, outcome, prev_hash, hash,
        );
        self.sink.write(&record)?;

        self.next_id = next;
        self.last_hash = hash;
        self.last_timestamp = timestamp;
        Ok(id)
    }

    /// Consume the chain and return its three pluggable components.
    #[inline]
    pub fn into_parts(self) -> (H, S, C) {
        (self.hasher, self.sink, self.clock)
    }

    /// Borrow the configured sink.
    #[inline]
    pub const fn sink(&self) -> &S {
        &self.sink
    }

    /// Mutably borrow the configured sink.
    #[inline]
    pub fn sink_mut(&mut self) -> &mut S {
        &mut self.sink
    }
}
