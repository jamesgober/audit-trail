//! Chain verification: replay records and prove the chain is untampered.
//!
//! A [`Verifier`] feeds records back through the same canonical hashing
//! protocol used by [`crate::Chain::append`] and checks three invariants
//! per record:
//!
//! 1. **Id linkage.** The record's id is the expected next id in the chain.
//! 2. **Prev-hash linkage.** The record's `prev_hash` equals the previous
//!    record's `hash` (or [`Digest::ZERO`] for the genesis record).
//! 3. **Hash integrity.** The record's stored `hash` equals the digest
//!    recomputed from `(id, timestamp, actor, action, target, outcome,
//!    prev_hash)` using the same field separator the chain uses.
//!
//! Optionally, a [`Verifier`] also enforces strict timestamp monotonicity
//! (each record's timestamp must be strictly greater than the previous).
//!
//! The verifier is **stateful and sequential**: callers feed records in
//! chain order. A failure leaves the verifier's state at the last record
//! it accepted, so the caller can inspect [`Verifier::next_id`] /
//! [`Verifier::last_hash`] to learn how far verification got.

use crate::canonical;
use crate::clock::Timestamp;
use crate::error::{Error, Result};
use crate::hash::{Digest, Hasher};
use crate::record::{Record, RecordId};

/// Replays a chain of records and proves their hash linkage is intact.
///
/// The verifier is generic over its [`Hasher`]: callers must supply an
/// implementation that produces the same digests the original [`Chain`]
/// produced. Two different hash algorithms will not interoperate.
///
/// [`Chain`]: crate::Chain
///
/// # Example
///
/// ```
/// use audit_trail::{
///     Action, Actor, Chain, Clock, Digest, Hasher, Outcome, Record, RecordId, Sink,
///     SinkError, Target, Timestamp, Verifier, HASH_LEN,
/// };
///
/// // XOR-fold hasher (insecure — for demonstration only).
/// struct XorHasher([u8; HASH_LEN], usize);
/// impl Hasher for XorHasher {
///     fn reset(&mut self) { self.0 = [0u8; HASH_LEN]; self.1 = 0; }
///     fn update(&mut self, bytes: &[u8]) {
///         for b in bytes { self.0[self.1 % HASH_LEN] ^= *b; self.1 = self.1.wrapping_add(1); }
///     }
///     fn finalize(&mut self, out: &mut Digest) { *out = Digest::from_bytes(self.0); }
/// }
///
/// // Capture every record the chain emits.
/// #[derive(Default)]
/// struct CaptureSink { records: Vec<(RecordId, Timestamp, Digest, Digest, Outcome)> }
/// impl Sink for CaptureSink {
///     fn write(&mut self, r: &Record<'_>) -> Result<(), SinkError> {
///         self.records.push((r.id(), r.timestamp(), r.prev_hash(), r.hash(), r.outcome()));
///         Ok(())
///     }
/// }
///
/// struct Tick(core::cell::Cell<u64>);
/// impl Clock for Tick {
///     fn now(&self) -> Timestamp {
///         let v = self.0.get(); self.0.set(v + 1); Timestamp::from_nanos(v)
///     }
/// }
///
/// // Build a 3-record chain.
/// let mut chain = Chain::new(
///     XorHasher([0u8; HASH_LEN], 0),
///     CaptureSink::default(),
///     Tick(core::cell::Cell::new(1)),
/// );
/// chain.append(Actor::new("a"), Action::new("x"), Target::new("t"), Outcome::Success).unwrap();
/// chain.append(Actor::new("a"), Action::new("y"), Target::new("u"), Outcome::Success).unwrap();
/// chain.append(Actor::new("a"), Action::new("z"), Target::new("v"), Outcome::Failure).unwrap();
/// let (_h, sink, _c) = chain.into_parts();
///
/// // Replay every captured record through the verifier.
/// let actors = ["a", "a", "a"];
/// let actions = ["x", "y", "z"];
/// let targets = ["t", "u", "v"];
/// let mut verifier = Verifier::new(XorHasher([0u8; HASH_LEN], 0));
/// for (i, (id, ts, prev, hash, outcome)) in sink.records.iter().enumerate() {
///     let record = Record::new(
///         *id, *ts,
///         Actor::new(actors[i]), Action::new(actions[i]), Target::new(targets[i]),
///         *outcome, *prev, *hash,
///     );
///     verifier.verify(&record).unwrap();
/// }
/// assert_eq!(verifier.next_id(), RecordId::from_u64(3));
/// ```
#[derive(Debug)]
pub struct Verifier<H>
where
    H: Hasher,
{
    hasher: H,
    next_id: u64,
    last_hash: Digest,
    last_timestamp: Timestamp,
    strict_timestamps: bool,
    started: bool,
}

impl<H> Verifier<H>
where
    H: Hasher,
{
    /// Construct a verifier that expects to start from the genesis record.
    ///
    /// Timestamp monotonicity is enforced by default. Disable it with
    /// [`Verifier::with_strict_timestamps`].
    #[inline]
    pub fn new(hasher: H) -> Self {
        Self {
            hasher,
            next_id: 0,
            last_hash: Digest::ZERO,
            last_timestamp: Timestamp::EPOCH,
            strict_timestamps: true,
            started: false,
        }
    }

    /// Construct a verifier that resumes mid-chain.
    ///
    /// `next_id`, `last_hash`, and `last_timestamp` must match the state of
    /// the chain immediately after the most recently verified record.
    #[inline]
    pub fn resume(
        hasher: H,
        next_id: RecordId,
        last_hash: Digest,
        last_timestamp: Timestamp,
    ) -> Self {
        Self {
            hasher,
            next_id: next_id.as_u64(),
            last_hash,
            last_timestamp,
            strict_timestamps: true,
            started: true,
        }
    }

    /// Toggle strict timestamp monotonicity. Default is `true`.
    ///
    /// When `false`, timestamps may be equal or out of order without
    /// triggering [`Error::NonMonotonicClock`]. This is occasionally useful
    /// when verifying chains imported from systems with coarser clocks.
    #[inline]
    pub const fn with_strict_timestamps(mut self, strict: bool) -> Self {
        self.strict_timestamps = strict;
        self
    }

    /// Id the next verified record must carry.
    #[inline]
    pub const fn next_id(&self) -> RecordId {
        RecordId::from_u64(self.next_id)
    }

    /// Hash of the last record this verifier accepted, or [`Digest::ZERO`]
    /// if none yet.
    #[inline]
    pub const fn last_hash(&self) -> Digest {
        self.last_hash
    }

    /// Timestamp of the last record this verifier accepted, or
    /// [`Timestamp::EPOCH`] if none yet.
    #[inline]
    pub const fn last_timestamp(&self) -> Timestamp {
        self.last_timestamp
    }

    /// Verify a single record against the running chain state.
    ///
    /// On success the verifier's internal cursor advances. On failure the
    /// verifier's cursor is left unchanged so callers can inspect
    /// [`Verifier::next_id`] to learn which record failed.
    ///
    /// # Errors
    ///
    /// * [`Error::IdMismatch`] — record id is not the expected next id.
    /// * [`Error::LinkMismatch`] — record's `prev_hash` does not equal the
    ///   previous record's `hash`.
    /// * [`Error::HashMismatch`] — record's stored `hash` does not match
    ///   the digest recomputed from its fields.
    /// * [`Error::NonMonotonicClock`] — record's timestamp is not strictly
    ///   greater than the previous record's (only when strict timestamps
    ///   are enabled).
    pub fn verify(&mut self, record: &Record<'_>) -> Result<()> {
        if record.id().as_u64() != self.next_id {
            return Err(Error::IdMismatch(record.id()));
        }

        if record.prev_hash() != self.last_hash {
            return Err(Error::LinkMismatch(record.id()));
        }

        if self.strict_timestamps && self.started && record.timestamp() <= self.last_timestamp {
            return Err(Error::NonMonotonicClock);
        }

        let recomputed = canonical::compute(&mut self.hasher, record);
        if recomputed != record.hash() {
            return Err(Error::HashMismatch(record.id()));
        }

        self.next_id = self
            .next_id
            .checked_add(1)
            .ok_or_else(|| Error::IdMismatch(record.id()))?;
        self.last_hash = record.hash();
        self.last_timestamp = record.timestamp();
        self.started = true;
        Ok(())
    }

    /// Consume the verifier and return its hasher.
    #[inline]
    pub fn into_hasher(self) -> H {
        self.hasher
    }
}
