//! The hashed bytes of a record: pinned by a known digest, and free of
//! field-boundary ambiguity.

#![cfg(feature = "sha2")]

use core::cell::Cell;

use audit_trail::{
    Action, Actor, Chain, Clock, Digest, Error, Hasher, MemorySink, Outcome, Record, RecordId,
    Sha256Hasher, Target, Timestamp, Verifier,
};

struct TickClock(Cell<u64>);

impl Clock for TickClock {
    fn now(&self) -> Timestamp {
        let v = self.0.get();
        self.0.set(v.saturating_add(1));
        Timestamp::from_nanos(v)
    }
}

/// The documented canonical bytes, hashed by hand: `id`, `timestamp`,
/// `actor`, `action`, `target`, `outcome`, `prev_hash`, separated by
/// `0x1f`.
fn by_hand(record: &Record<'_>) -> Digest {
    let mut hasher = Sha256Hasher::new();
    hasher.reset();
    hasher.update(&record.id().as_u64().to_be_bytes());
    hasher.update(&[0x1f]);
    hasher.update(&record.timestamp().as_nanos().to_be_bytes());
    hasher.update(&[0x1f]);
    hasher.update(record.actor().as_str().as_bytes());
    hasher.update(&[0x1f]);
    hasher.update(record.action().as_str().as_bytes());
    hasher.update(&[0x1f]);
    hasher.update(record.target().as_str().as_bytes());
    hasher.update(&[0x1f]);
    hasher.update(&[record.outcome().as_u8()]);
    hasher.update(&[0x1f]);
    hasher.update(record.prev_hash().as_bytes());
    let mut out = Digest::ZERO;
    hasher.finalize(&mut out);
    out
}

fn hex(digest: Digest) -> String {
    format!("{digest:x}")
}

#[test]
fn the_hashed_bytes_are_unchanged() {
    let mut chain = Chain::new(
        Sha256Hasher::new(),
        MemorySink::new(),
        TickClock(Cell::new(1_700_000_000_000_000_000)),
    );
    let _ = chain
        .append(
            Actor::new("admin:42"),
            Action::new("user.delete"),
            Target::new("user:1009"),
            Outcome::Denied,
        )
        .unwrap();
    let _ = chain
        .append(
            Actor::new("système"),
            Action::new("chain.rotate"),
            Target::new(""),
            Outcome::Success,
        )
        .unwrap();
    let (_, sink, _) = chain.into_parts();
    let records = sink.into_records();
    for record in &records {
        assert_eq!(record.hash, by_hand(&record.as_record()));
    }
    // Pinned digests: a change here is a break of every chain on disk.
    assert_eq!(hex(records[0].hash), GENESIS);
    assert_eq!(hex(records[1].hash), SECOND);
}

const GENESIS: &str = "4e7d2c667ae4c904c0c45f79ad2d63baad305255cba639745239259fee124e9a";
const SECOND: &str = "32ebcea004c07c30dc6f2c1510ba1a6d08791f8ed13f493b4fc982e4edc96d4c";

#[test]
fn a_field_with_the_separator_byte_is_refused_on_append() {
    let mut chain = Chain::new(
        Sha256Hasher::new(),
        MemorySink::new(),
        TickClock(Cell::new(1)),
    );
    for (actor, action, target) in [
        ("eve\u{1f}admin", "x", "t"),
        ("eve", "admin\u{1f}x", "t"),
        ("eve", "x", "\u{1f}"),
    ] {
        let error = chain
            .append(
                Actor::new(actor),
                Action::new(action),
                Target::new(target),
                Outcome::Success,
            )
            .err();
        assert_eq!(error, Some(Error::InvalidFormat));
    }
    assert_eq!(chain.next_id(), RecordId::GENESIS);
    assert!(chain.sink().is_empty());
}

#[test]
fn moving_text_across_a_separator_does_not_verify() {
    // Two records whose fields differ but whose hashed bytes are the same:
    // "eve" + 0x1f + "admin" 0x1f "x"  versus  "eve" 0x1f "admin" + 0x1f + "x".
    let first = Record::new(
        RecordId::GENESIS,
        Timestamp::from_nanos(5),
        Actor::new("eve\u{1f}admin"),
        Action::new("x"),
        Target::new("t"),
        Outcome::Success,
        Digest::ZERO,
        Digest::ZERO,
    );
    let first = first.with_hash(by_hand(&first));
    let moved = Record::new(
        RecordId::GENESIS,
        Timestamp::from_nanos(5),
        Actor::new("eve"),
        Action::new("admin\u{1f}x"),
        Target::new("t"),
        Outcome::Success,
        Digest::ZERO,
        first.hash(),
    );
    assert_eq!(by_hand(&moved), first.hash(), "the bytes are ambiguous");

    for record in [first, moved] {
        let mut verifier = Verifier::new(Sha256Hasher::new());
        assert_eq!(verifier.verify(&record), Err(Error::InvalidFormat));
        assert_eq!(verifier.next_id(), RecordId::GENESIS);
    }
}
