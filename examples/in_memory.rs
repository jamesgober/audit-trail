//! Minimal "first audit chain" example.
//!
//! Builds an in-memory hash-linked log with SHA-256 + `MemorySink` +
//! `SystemClock`, appends three records, prints them, then proves the
//! whole chain verifies untampered.
//!
//! Run with:
//!
//! ```text
//! cargo run --example in_memory --features sha2
//! ```

use audit_trail::{
    Action, Actor, Chain, MemorySink, Outcome, Sha256Hasher, SystemClock, Target, Verifier,
};

fn main() {
    let mut chain = Chain::new(Sha256Hasher::new(), MemorySink::new(), SystemClock::new());

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
            Actor::new("user-42"),
            Action::new("user.login"),
            Target::new("session:abc"),
            Outcome::Success,
        )
        .expect("login");

    chain
        .append(
            Actor::new("user-42"),
            Action::new("record.delete"),
            Target::new("record:1337"),
            Outcome::Denied,
        )
        .expect("denied delete");

    let (_, sink, _) = chain.into_parts();

    println!("--- {} records ---", sink.len());
    for r in sink.records() {
        println!(
            "  id={:>3}  ts={}  {:?}  {} -> {} ({})",
            r.id.as_u64(),
            r.timestamp.as_nanos(),
            r.outcome,
            r.actor,
            r.target,
            r.action,
        );
    }

    let mut verifier = Verifier::new(Sha256Hasher::new());
    for r in sink.records() {
        verifier
            .verify(&r.as_record())
            .expect("untampered chain must verify");
    }

    println!(
        "\nChain verified: {} records, last hash {:x}",
        sink.len(),
        verifier.last_hash(),
    );
}
