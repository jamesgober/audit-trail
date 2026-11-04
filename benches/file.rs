//! File-backed chain benchmarks.
//!
//! * `file_append` - `Chain::append` into a `FileSink` over a buffered
//!   file, no sync (the record reaches the `BufWriter`).
//! * `file_append_sync` - append, then `FileSink::sync` (flush and
//!   `sync_data`): the cost of a record that is on disk when the call
//!   returns.
//! * `open_file_10k` - `Chain::open_file` on a 10 000-record chain: read,
//!   decode and verify every record, then resume at the tail.
//! * `reader_verify_10k` - the same file replayed with `FileReader` and a
//!   `Verifier` (the path for callers that inspect each record).
//!
//! Run with `cargo bench --bench file --features sha2`.

#![cfg(feature = "sha2")]

use std::cell::Cell;
use std::fs;
use std::path::PathBuf;

use audit_trail::{
    Action, Actor, Chain, Clock, FileReader, Outcome, Sha256Hasher, Target, Timestamp, Verifier,
};
use criterion::{Criterion, black_box, criterion_group, criterion_main};

struct TickClock(Cell<u64>);

impl Clock for TickClock {
    fn now(&self) -> Timestamp {
        let v = self.0.get();
        self.0.set(v.wrapping_add(1));
        Timestamp::from_nanos(v)
    }
}

fn scratch(label: &str) -> PathBuf {
    let dir =
        std::env::temp_dir().join(format!("audit-trail-bench-{label}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn bench_append(c: &mut Criterion) {
    let dir = scratch("append");
    let (mut chain, _report) = Chain::open_file(
        dir.join("chain.audit"),
        Sha256Hasher::new(),
        TickClock(Cell::new(1)),
    )
    .unwrap();
    let _ = c.bench_function("file_append", |b| {
        b.iter(|| {
            let _ = chain.append(
                Actor::new(black_box("admin:42")),
                Action::new(black_box("user.update")),
                Target::new(black_box("user:1009")),
                Outcome::Success,
            );
        });
    });
    drop(chain);
    let _ = fs::remove_dir_all(&dir);
}

fn bench_append_sync(c: &mut Criterion) {
    let dir = scratch("sync");
    let (mut chain, _report) = Chain::open_file(
        dir.join("chain.audit"),
        Sha256Hasher::new(),
        TickClock(Cell::new(1)),
    )
    .unwrap();
    let mut group = c.benchmark_group("sync");
    let _ = group.sample_size(20);
    let _ = group.bench_function("file_append_sync", |b| {
        b.iter(|| {
            let _ = chain.append(
                Actor::new(black_box("admin:42")),
                Action::new(black_box("user.update")),
                Target::new(black_box("user:1009")),
                Outcome::Success,
            );
            chain.sink_mut().sync().unwrap();
        });
    });
    group.finish();
    drop(chain);
    let _ = fs::remove_dir_all(&dir);
}

const RECORDS: usize = 10_000;

fn build_file(dir: &std::path::Path) -> PathBuf {
    let path = dir.join("chain.audit");
    let (mut chain, _report) =
        Chain::open_file(&path, Sha256Hasher::new(), TickClock(Cell::new(1))).unwrap();
    for i in 0..RECORDS {
        let target = format!("user:{i}");
        let _ = chain
            .append(
                Actor::new("admin:42"),
                Action::new("user.update"),
                Target::new(&target),
                Outcome::Success,
            )
            .unwrap();
    }
    chain.sink_mut().sync().unwrap();
    path
}

fn bench_open(c: &mut Criterion) {
    let dir = scratch("open");
    let path = build_file(&dir);
    let mut group = c.benchmark_group("open");
    let _ = group.sample_size(20);
    let _ = group.bench_function("open_file_10k", |b| {
        b.iter(|| {
            let (chain, report) = Chain::open_file(
                black_box(&path),
                Sha256Hasher::new(),
                TickClock(Cell::new(u64::MAX / 2)),
            )
            .unwrap();
            assert_eq!(report.records(), RECORDS as u64);
            drop(chain);
        });
    });
    let _ = group.bench_function("reader_verify_10k", |b| {
        b.iter(|| {
            let mut verifier = Verifier::new(Sha256Hasher::new());
            for record in FileReader::open(black_box(&path)).unwrap() {
                verifier.verify(&record.unwrap().as_record()).unwrap();
            }
        });
    });
    group.finish();
    let _ = fs::remove_dir_all(&dir);
}

criterion_group!(benches, bench_append, bench_append_sync, bench_open);
criterion_main!(benches);
