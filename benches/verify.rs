//! Verify-throughput benchmarks.
//!
//! Builds a 1 000-record chain once at start-up, then measures the cost
//! of replaying it through `Verifier::verify`.
//!
//! Run with `cargo bench --bench verify --features sha2,blake3`.

use std::cell::Cell;

use audit_trail::{
    Action, Actor, Chain, Clock, Digest, HASH_LEN, Hasher, MemorySink, Outcome, OwnedRecord,
    Target, Timestamp, Verifier,
};
use criterion::{Criterion, black_box, criterion_group, criterion_main};

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

impl Clock for TickClock {
    fn now(&self) -> Timestamp {
        let v = self.0.get();
        self.0.set(v.wrapping_add(1));
        Timestamp::from_nanos(v)
    }
}

const CHAIN_LEN: usize = 1_000;

fn build_chain<H: Hasher + Default>() -> Vec<OwnedRecord> {
    let mut chain = Chain::new(
        H::default(),
        MemorySink::with_capacity(CHAIN_LEN),
        TickClock(Cell::new(1)),
    );
    for i in 0..CHAIN_LEN {
        let actor = format!("user-{i}");
        let target = format!("record:{i}");
        let _ = chain.append(
            Actor::new(&actor),
            Action::new("record.read"),
            Target::new(&target),
            Outcome::Success,
        );
    }
    let (_h, sink, _c) = chain.into_parts();
    sink.into_records()
}

fn bench_verify_xor(c: &mut Criterion) {
    let records = build_chain::<XorHasher>();
    let _ = c.bench_function("verify_xor_1000", |b| {
        b.iter(|| {
            let mut v = Verifier::new(XorHasher::default());
            for r in &records {
                let _ = v.verify(black_box(&r.as_record()));
            }
        });
    });
}

#[cfg(feature = "sha2")]
fn bench_verify_sha2(c: &mut Criterion) {
    use audit_trail::Sha256Hasher;
    let records = build_chain::<Sha256Hasher>();
    let _ = c.bench_function("verify_sha2_1000", |b| {
        b.iter(|| {
            let mut v = Verifier::new(Sha256Hasher::new());
            for r in &records {
                let _ = v.verify(black_box(&r.as_record()));
            }
        });
    });
}

#[cfg(feature = "blake3")]
fn bench_verify_blake3(c: &mut Criterion) {
    use audit_trail::Blake3Hasher;
    let records = build_chain::<Blake3Hasher>();
    let _ = c.bench_function("verify_blake3_1000", |b| {
        b.iter(|| {
            let mut v = Verifier::new(Blake3Hasher::new());
            for r in &records {
                let _ = v.verify(black_box(&r.as_record()));
            }
        });
    });
}

#[cfg(all(feature = "sha2", feature = "blake3"))]
criterion_group!(
    benches,
    bench_verify_xor,
    bench_verify_sha2,
    bench_verify_blake3
);

#[cfg(all(feature = "sha2", not(feature = "blake3")))]
criterion_group!(benches, bench_verify_xor, bench_verify_sha2);

#[cfg(all(not(feature = "sha2"), feature = "blake3"))]
criterion_group!(benches, bench_verify_xor, bench_verify_blake3);

#[cfg(not(any(feature = "sha2", feature = "blake3")))]
criterion_group!(benches, bench_verify_xor);

criterion_main!(benches);
