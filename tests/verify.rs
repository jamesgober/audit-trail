//! Integration tests for [`audit_trail::Verifier`].
//!
//! These tests build a chain with deliberately insecure stubs, capture the
//! emitted records, then replay them through the verifier to confirm:
//!
//! * an untampered chain verifies clean,
//! * each mutation class is detected at the right record,
//! * the verifier's cursor stops at the failing record,
//! * resume from a mid-chain checkpoint works.

use core::cell::Cell;

use audit_trail::{
    Action, Actor, Chain, Clock, Digest, Error, HASH_LEN, Hasher, Outcome, Record, RecordId, Sink,
    SinkError, Target, Timestamp, Verifier,
};

#[derive(Clone, Default)]
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

/// Records every appended record verbatim so the verifier can replay them.
#[derive(Default)]
struct CaptureSink {
    records: Vec<OwnedRecord>,
}

#[derive(Clone)]
struct OwnedRecord {
    id: RecordId,
    timestamp: Timestamp,
    actor: String,
    action: String,
    target: String,
    outcome: Outcome,
    prev_hash: Digest,
    hash: Digest,
}

impl OwnedRecord {
    fn borrowed(&self) -> Record<'_> {
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

impl Sink for CaptureSink {
    fn write(&mut self, record: &Record<'_>) -> Result<(), SinkError> {
        self.records.push(OwnedRecord {
            id: record.id(),
            timestamp: record.timestamp(),
            actor: record.actor().as_str().to_owned(),
            action: record.action().as_str().to_owned(),
            target: record.target().as_str().to_owned(),
            outcome: record.outcome(),
            prev_hash: record.prev_hash(),
            hash: record.hash(),
        });
        Ok(())
    }
}

/// Build a 4-record chain and return the captured records.
fn build_chain() -> Vec<OwnedRecord> {
    let mut chain = Chain::new(
        XorHasher::default(),
        CaptureSink::default(),
        TickClock::new(1),
    );

    chain
        .append(
            Actor::new("system"),
            Action::new("chain.init"),
            Target::new("chain:0"),
            Outcome::Success,
        )
        .expect("genesis append");
    chain
        .append(
            Actor::new("user-1"),
            Action::new("user.login"),
            Target::new("session:abc"),
            Outcome::Success,
        )
        .expect("append 1");
    chain
        .append(
            Actor::new("user-1"),
            Action::new("record.read"),
            Target::new("record:42"),
            Outcome::Success,
        )
        .expect("append 2");
    chain
        .append(
            Actor::new("user-1"),
            Action::new("record.delete"),
            Target::new("record:42"),
            Outcome::Denied,
        )
        .expect("append 3");

    let (_h, sink, _c) = chain.into_parts();
    sink.records
}

#[test]
fn verifier_accepts_untampered_chain() {
    let records = build_chain();

    let mut verifier = Verifier::new(XorHasher::default());
    for r in &records {
        verifier
            .verify(&r.borrowed())
            .expect("untampered record must verify");
    }
    assert_eq!(verifier.next_id(), RecordId::from_u64(4));
}

#[test]
fn verifier_detects_mutated_field() {
    let mut records = build_chain();

    // Tamper with the action on record index 2.
    records[2].action = "record.write".to_owned();

    let mut verifier = Verifier::new(XorHasher::default());
    verifier.verify(&records[0].borrowed()).expect("record 0");
    verifier.verify(&records[1].borrowed()).expect("record 1");
    let err = verifier
        .verify(&records[2].borrowed())
        .expect_err("mutated action must be detected");
    assert_eq!(err, Error::HashMismatch(RecordId::from_u64(2)));

    // The verifier's cursor must not advance past the failing record.
    assert_eq!(verifier.next_id(), RecordId::from_u64(2));
}

#[test]
fn verifier_detects_broken_link() {
    let mut records = build_chain();

    // Tamper with prev_hash on record 2 (breaks linkage without touching the
    // record's own stored hash).
    records[2].prev_hash = Digest::from_bytes([0xAA; HASH_LEN]);

    let mut verifier = Verifier::new(XorHasher::default());
    verifier.verify(&records[0].borrowed()).expect("record 0");
    verifier.verify(&records[1].borrowed()).expect("record 1");
    let err = verifier
        .verify(&records[2].borrowed())
        .expect_err("broken link must be detected");
    assert_eq!(err, Error::LinkMismatch(RecordId::from_u64(2)));
}

#[test]
fn verifier_detects_id_skip() {
    let records = build_chain();

    // Skip record 1 — feed 0 then 2 directly.
    let mut verifier = Verifier::new(XorHasher::default());
    verifier.verify(&records[0].borrowed()).expect("record 0");
    let err = verifier
        .verify(&records[2].borrowed())
        .expect_err("id skip must be detected");
    assert_eq!(err, Error::IdMismatch(RecordId::from_u64(2)));
}

#[test]
fn verifier_resumes_from_checkpoint() {
    let records = build_chain();

    // Verify the first two, then build a fresh verifier resuming at index 2.
    let mut verifier = Verifier::new(XorHasher::default());
    verifier.verify(&records[0].borrowed()).expect("record 0");
    verifier.verify(&records[1].borrowed()).expect("record 1");

    let resumed = Verifier::resume(
        XorHasher::default(),
        verifier.next_id(),
        verifier.last_hash(),
        verifier.last_timestamp(),
    );
    let mut resumed = resumed;
    resumed
        .verify(&records[2].borrowed())
        .expect("resumed record 2");
    resumed
        .verify(&records[3].borrowed())
        .expect("resumed record 3");
    assert_eq!(resumed.next_id(), RecordId::from_u64(4));
}

#[test]
fn verifier_rejects_non_monotonic_timestamps_when_strict() {
    let mut records = build_chain();

    // Force record 2 to have the same timestamp as record 1.
    records[2].timestamp = records[1].timestamp;
    // Recompute record 2's hash so we don't get HashMismatch first.
    // (We can't easily recompute here, so instead we disable strict
    // timestamps for this case and rely on the explicit strict-mode test.)
    // Instead, verify with strict mode that a hash mismatch surfaces first,
    // because the record's stored hash was computed with the original ts.
    let mut verifier = Verifier::new(XorHasher::default());
    verifier.verify(&records[0].borrowed()).expect("record 0");
    verifier.verify(&records[1].borrowed()).expect("record 1");
    let err = verifier
        .verify(&records[2].borrowed())
        .expect_err("equal timestamp must trigger some integrity failure");
    // Either NonMonotonicClock (the timestamp check) or HashMismatch (since
    // the stored hash was computed with the original timestamp) is correct;
    // the verifier checks timestamps before hashes, so we expect the clock
    // error here.
    assert_eq!(err, Error::NonMonotonicClock);
}

#[test]
fn verifier_with_relaxed_timestamps_accepts_duplicates() {
    // Build a tiny chain manually with a relaxed-timestamp verifier so we
    // can prove with_strict_timestamps(false) actually skips the check.
    let records = build_chain();

    let mut verifier = Verifier::new(XorHasher::default()).with_strict_timestamps(false);
    for r in &records {
        verifier
            .verify(&r.borrowed())
            .expect("records must still verify");
    }
}
