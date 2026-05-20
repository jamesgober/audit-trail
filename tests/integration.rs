//! End-to-end integration test using the bundled reference impls.
//!
//! Requires the `sha2` and `alloc` features (both enabled by default
//! transitively via `std`). Builds a real SHA-256-backed chain, drives
//! it through [`MemorySink`], then replays it through a [`Verifier`] and
//! exercises tamper detection.

#![cfg(all(feature = "sha2", feature = "alloc"))]

use core::cell::Cell;

use audit_trail::{
    Action, Actor, Chain, Clock, Digest, Error, HASH_LEN, MemorySink, Outcome, OwnedRecord,
    RecordId, Sha256Hasher, Target, Timestamp, Verifier,
};

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

fn build_sha256_chain() -> Vec<OwnedRecord> {
    let mut chain = Chain::new(
        Sha256Hasher::new(),
        MemorySink::with_capacity(4),
        TickClock::new(1),
    );

    chain
        .append(
            Actor::new("system"),
            Action::new("chain.init"),
            Target::new("chain:0"),
            Outcome::Success,
        )
        .expect("genesis");
    chain
        .append(
            Actor::new("user-1"),
            Action::new("user.login"),
            Target::new("session:abc"),
            Outcome::Success,
        )
        .expect("login");
    chain
        .append(
            Actor::new("user-1"),
            Action::new("record.read"),
            Target::new("record:42"),
            Outcome::Success,
        )
        .expect("read");
    chain
        .append(
            Actor::new("user-1"),
            Action::new("record.delete"),
            Target::new("record:42"),
            Outcome::Denied,
        )
        .expect("delete");

    let (_h, sink, _c) = chain.into_parts();
    sink.into_records()
}

#[test]
fn sha256_chain_verifies_clean() {
    let records = build_sha256_chain();
    assert_eq!(records.len(), 4);

    // Each record's hash must be 32 non-zero bytes (SHA-256 of non-empty
    // input is essentially never all zeros).
    for r in &records {
        assert_ne!(r.hash, Digest::ZERO);
    }

    let mut verifier = Verifier::new(Sha256Hasher::new());
    for r in &records {
        verifier
            .verify(&r.as_record())
            .expect("untampered SHA-256 chain must verify");
    }
    assert_eq!(verifier.next_id(), RecordId::from_u64(4));
}

#[test]
fn sha256_detects_mutation_at_correct_record() {
    let mut records = build_sha256_chain();
    records[2].action = String::from("record.write");

    let mut verifier = Verifier::new(Sha256Hasher::new());
    verifier.verify(&records[0].as_record()).expect("record 0");
    verifier.verify(&records[1].as_record()).expect("record 1");
    let err = verifier
        .verify(&records[2].as_record())
        .expect_err("mutated action must fail");
    assert_eq!(err, Error::HashMismatch(RecordId::from_u64(2)));
}

#[test]
fn sha256_detects_broken_link() {
    let mut records = build_sha256_chain();
    records[2].prev_hash = Digest::from_bytes([0xCC; HASH_LEN]);

    let mut verifier = Verifier::new(Sha256Hasher::new());
    verifier.verify(&records[0].as_record()).expect("record 0");
    verifier.verify(&records[1].as_record()).expect("record 1");
    let err = verifier
        .verify(&records[2].as_record())
        .expect_err("broken link must fail");
    assert_eq!(err, Error::LinkMismatch(RecordId::from_u64(2)));
}

#[test]
fn memory_sink_roundtrips_owned_records() {
    let records = build_sha256_chain();

    // OwnedRecord -> Record -> OwnedRecord should be a fixed point.
    for r in &records {
        let borrowed = r.as_record();
        let roundtripped = OwnedRecord::from_record(&borrowed);
        assert_eq!(r, &roundtripped);
    }
}
