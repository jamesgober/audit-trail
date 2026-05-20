//! Append-throughput benchmarks for the audit chain.
//!
//! Three configurations exercise different cost profiles:
//!
//! * `append_xor` — chain with the deliberately-trivial XOR hasher.
//!   Measures the *non-hash* overhead of `Chain::append` (canonical
//!   encoding, sink dispatch, state update).
//! * `append_sha2` — same chain with `Sha256Hasher`. Requires the
//!   `sha2` feature.
//! * `append_blake3` — same chain with `Blake3Hasher`. Requires the
//!   `blake3` feature.
//!
//! Run with `cargo bench --bench append --features sha2,blake3`.

use std::cell::Cell;

use audit_trail::{
    Action, Actor, Chain, Clock, Digest, HASH_LEN, Hasher, MemorySink, Outcome, Target, Timestamp,
};
use criterion::{Criterion, black_box, criterion_group, criterion_main};

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

struct TickClock(Cell<u64>);

impl Clock for TickClock {
    fn now(&self) -> Timestamp {
        let v = self.0.get();
        self.0.set(v.wrapping_add(1));
        Timestamp::from_nanos(v)
    }
}

fn bench_append_xor(c: &mut Criterion) {
    let _ = c.bench_function("append_xor", |b| {
        let mut chain = Chain::new(
            XorHasher::default(),
            MemorySink::with_capacity(1024),
            TickClock(Cell::new(1)),
        );
        b.iter(|| {
            let _ = chain.append(
                black_box(Actor::new("user-42")),
                black_box(Action::new("record.delete")),
                black_box(Target::new("record:1337")),
                black_box(Outcome::Denied),
            );
        });
    });
}

#[cfg(feature = "sha2")]
fn bench_append_sha2(c: &mut Criterion) {
    use audit_trail::Sha256Hasher;
    let _ = c.bench_function("append_sha2", |b| {
        let mut chain = Chain::new(
            Sha256Hasher::new(),
            MemorySink::with_capacity(1024),
            TickClock(Cell::new(1)),
        );
        b.iter(|| {
            let _ = chain.append(
                black_box(Actor::new("user-42")),
                black_box(Action::new("record.delete")),
                black_box(Target::new("record:1337")),
                black_box(Outcome::Denied),
            );
        });
    });
}

#[cfg(feature = "blake3")]
fn bench_append_blake3(c: &mut Criterion) {
    use audit_trail::Blake3Hasher;
    let _ = c.bench_function("append_blake3", |b| {
        let mut chain = Chain::new(
            Blake3Hasher::new(),
            MemorySink::with_capacity(1024),
            TickClock(Cell::new(1)),
        );
        b.iter(|| {
            let _ = chain.append(
                black_box(Actor::new("user-42")),
                black_box(Action::new("record.delete")),
                black_box(Target::new("record:1337")),
                black_box(Outcome::Denied),
            );
        });
    });
}

#[cfg(all(feature = "sha2", feature = "blake3"))]
criterion_group!(
    benches,
    bench_append_xor,
    bench_append_sha2,
    bench_append_blake3
);

#[cfg(all(feature = "sha2", not(feature = "blake3")))]
criterion_group!(benches, bench_append_xor, bench_append_sha2);

#[cfg(all(not(feature = "sha2"), feature = "blake3"))]
criterion_group!(benches, bench_append_xor, bench_append_blake3);

#[cfg(not(any(feature = "sha2", feature = "blake3")))]
criterion_group!(benches, bench_append_xor);

criterion_main!(benches);
