//! Smoke tests: end-to-end exercise of the foundation API.
//!
//! These tests use deliberately insecure hash/clock/sink implementations
//! purely to drive the public surface. They are not a security audit of any
//! real backend.

use core::cell::Cell;

use audit_trail::{
    Action, Actor, Chain, Clock, Digest, Error, HASH_LEN, Hasher, Outcome, Record, RecordId, Sink,
    SinkError, Target, Timestamp,
};

/// XOR-fold "hasher" — collisions are trivial, but it is deterministic and
/// 32-bytes wide, which is sufficient for exercising the chain machinery.
#[derive(Default)]
struct XorHasher {
    state: [u8; HASH_LEN],
    pos: usize,
}

impl Hasher for XorHasher {
    fn reset(&mut self) {
        self.state = [0u8; HASH_LEN];
        self.pos = 0;
    }

    fn update(&mut self, bytes: &[u8]) {
        for b in bytes {
            self.state[self.pos % HASH_LEN] ^= *b;
            self.pos = self.pos.wrapping_add(1);
        }
    }

    fn finalize(&mut self, out: &mut Digest) {
        *out = Digest::from_bytes(self.state);
    }
}

/// A monotonic clock that ticks one nanosecond per call.
struct TickClock(Cell<u64>);

impl TickClock {
    fn new(start: u64) -> Self {
        Self(Cell::new(start))
    }
}

impl Clock for TickClock {
    fn now(&self) -> Timestamp {
        let v = self.0.get();
        self.0.set(v.saturating_add(1));
        Timestamp::from_nanos(v)
    }
}

/// A clock that returns a fixed timestamp every call (exercises the
/// non-monotonic error path).
struct StuckClock(u64);

impl Clock for StuckClock {
    fn now(&self) -> Timestamp {
        Timestamp::from_nanos(self.0)
    }
}

#[derive(Default)]
struct VecSink {
    records: Vec<(RecordId, Timestamp, Digest, Digest)>,
}

impl Sink for VecSink {
    fn write(&mut self, record: &Record<'_>) -> Result<(), SinkError> {
        self.records.push((
            record.id(),
            record.timestamp(),
            record.prev_hash(),
            record.hash(),
        ));
        Ok(())
    }
}

#[derive(Default)]
struct FailingSink;

impl Sink for FailingSink {
    fn write(&mut self, _record: &Record<'_>) -> Result<(), SinkError> {
        Err(SinkError::Io)
    }
}

#[test]
fn version_is_set() {
    assert!(!audit_trail::VERSION.is_empty());
}

#[test]
fn chain_appends_genesis_and_links_records() {
    let mut chain = Chain::new(XorHasher::default(), VecSink::default(), TickClock::new(1));

    let g = chain
        .append(
            Actor::new("system"),
            Action::new("chain.init"),
            Target::new("chain:0"),
            Outcome::Success,
        )
        .expect("genesis append");
    assert_eq!(g, RecordId::GENESIS);

    let r1 = chain
        .append(
            Actor::new("user-1"),
            Action::new("user.login"),
            Target::new("session:abc"),
            Outcome::Success,
        )
        .expect("append 1");
    assert_eq!(r1, RecordId::from_u64(1));

    let r2 = chain
        .append(
            Actor::new("user-1"),
            Action::new("record.delete"),
            Target::new("record:42"),
            Outcome::Denied,
        )
        .expect("append 2");
    assert_eq!(r2, RecordId::from_u64(2));

    let (_h, sink, _c) = chain.into_parts();
    let entries = &sink.records;
    assert_eq!(entries.len(), 3);

    assert_eq!(entries[0].2, Digest::ZERO);
    assert_eq!(entries[1].2, entries[0].3);
    assert_eq!(entries[2].2, entries[1].3);

    assert!(entries[0].1 < entries[1].1);
    assert!(entries[1].1 < entries[2].1);
}

#[test]
fn chain_rejects_non_monotonic_clock() {
    let mut chain = Chain::new(XorHasher::default(), VecSink::default(), StuckClock(100));

    let g = chain
        .append(
            Actor::new("a"),
            Action::new("x"),
            Target::new("t"),
            Outcome::Success,
        )
        .expect("genesis append");
    assert_eq!(g, RecordId::GENESIS);

    let err = chain
        .append(
            Actor::new("a"),
            Action::new("x"),
            Target::new("t"),
            Outcome::Success,
        )
        .expect_err("second append must reject equal timestamp");
    assert_eq!(err, Error::NonMonotonicClock);
}

#[test]
fn chain_surfaces_sink_errors_and_preserves_state() {
    let mut chain = Chain::new(XorHasher::default(), FailingSink, TickClock::new(1));

    let err = chain
        .append(
            Actor::new("a"),
            Action::new("x"),
            Target::new("t"),
            Outcome::Failure,
        )
        .expect_err("sink failure must propagate");
    assert_eq!(err, Error::Sink(SinkError::Io));

    assert_eq!(chain.next_id(), RecordId::GENESIS);
    assert_eq!(chain.last_hash(), Digest::ZERO);
    assert_eq!(chain.last_timestamp(), Timestamp::EPOCH);
}

#[test]
fn chain_resumes_from_tail() {
    let resume_hash = Digest::from_bytes([7u8; HASH_LEN]);
    let resume_ts = Timestamp::from_nanos(1_000);

    let mut chain = Chain::resume(
        XorHasher::default(),
        VecSink::default(),
        TickClock::new(2_000),
        RecordId::from_u64(42),
        resume_hash,
        resume_ts,
    );

    let id = chain
        .append(
            Actor::new("a"),
            Action::new("x"),
            Target::new("t"),
            Outcome::Success,
        )
        .expect("resume append");
    assert_eq!(id, RecordId::from_u64(42));

    let (_h, sink, _c) = chain.into_parts();
    assert_eq!(sink.records[0].2, resume_hash);
}
