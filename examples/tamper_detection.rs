//! Tamper detection demonstration.
//!
//! Builds a small chain, captures the records, mutates one of them,
//! then proves the `Verifier` rejects the mutated record with the
//! exact `RecordId` of the offending entry.
//!
//! This is the value proposition of the crate: the chain itself does
//! not prevent tampering, but it makes any tampering trivially
//! detectable on replay.
//!
//! Run with:
//!
//! ```text
//! cargo run --example tamper_detection --features sha2
//! ```

use audit_trail::{
    Action, Actor, Chain, Error, MemorySink, Outcome, OwnedRecord, Sha256Hasher, SystemClock,
    Target, Verifier,
};

fn build_chain() -> Vec<OwnedRecord> {
    let mut chain = Chain::new(Sha256Hasher::new(), MemorySink::new(), SystemClock::new());
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
            Target::new("session:a"),
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
        .expect("denied delete");
    let (_, sink, _) = chain.into_parts();
    sink.into_records()
}

fn main() {
    let mut records = build_chain();
    println!("Built {} records.", records.len());

    // Clean replay first — establishes the baseline.
    let mut verifier = Verifier::new(Sha256Hasher::new());
    for r in &records {
        verifier
            .verify(&r.as_record())
            .expect("clean chain must verify");
    }
    println!("Clean chain verified.\n");

    // Now tamper with record 2 — change "record.read" to "record.write".
    println!("Tampering with record id 2 (changing action to record.write)...");
    records[2].action = String::from("record.write");

    // Replay again. The verifier must detect the mismatch.
    let mut verifier = Verifier::new(Sha256Hasher::new());
    for r in &records {
        match verifier.verify(&r.as_record()) {
            Ok(()) => continue,
            Err(Error::HashMismatch(id)) => {
                println!(
                    "  Detected: hash mismatch at record {} (cursor stopped at id {})",
                    id.as_u64(),
                    verifier.next_id().as_u64(),
                );
                return;
            }
            Err(other) => {
                println!("  Unexpected error: {other}");
                return;
            }
        }
    }

    // Reaching here would mean tampering went undetected — the chain is broken.
    println!("  CHAIN BROKEN: tampered record went undetected");
}
