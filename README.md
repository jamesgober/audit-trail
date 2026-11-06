<h1 align="center">
    <img width="99" alt="Rust logo" src="https://raw.githubusercontent.com/jamesgober/rust-collection/72baabd71f00e14aa9184efcb16fa3deddda3a0a/assets/rust-logo.svg">
    <br>
    <strong>audit-trail</strong>
    <br>
    <sup><sub>TAMPER-EVIDENT AUDIT LOGGING</sub></sup>
</h1>

<p align="center">
    <a href="https://crates.io/crates/audit-trail"><img alt="crates.io" src="https://img.shields.io/crates/v/audit-trail.svg"></a>
    <a href="https://crates.io/crates/audit-trail"><img alt="downloads" src="https://img.shields.io/crates/d/audit-trail.svg?color=0099ff"></a>
    <a href="https://docs.rs/audit-trail"><img alt="docs.rs" src="https://docs.rs/audit-trail/badge.svg"></a>
    <a href="https://github.com/jamesgober/audit-trail/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/jamesgober/audit-trail/actions/workflows/ci.yml/badge.svg"></a>
    <a href="https://github.com/rust-lang/rfcs/blob/master/text/2495-min-rust-version.md" title="MSRV"><img alt="MSRV" src="https://img.shields.io/badge/MSRV-1.85%2B-blue"></a>
</p>

<p align="center">Cryptographically chained records (who, what, when, where, result). Compliance-grade output for HIPAA, SOC 2, PCI-DSS. Pluggable backends.</p>

## What it does

Structured audit logging with tamper-evident chaining. Every write produces a cryptographically linked record (hash chain). Compliance-grade output (who, what, when, where, result). Pluggable backends. Foundation for HIPAA, SOC 2, and PCI-DSS compliance.

---

## Quick start

```toml
[dependencies]
audit-trail = { version = "1", features = ["sha2"] }
```

```rust
use audit_trail::{
    Action, Actor, Chain, MemorySink, Outcome, Sha256Hasher, SystemClock, Target, Verifier,
};

let mut chain = Chain::new(Sha256Hasher::new(), MemorySink::new(), SystemClock::new());

chain.append(
    Actor::new("user-42"),
    Action::new("record.delete"),
    Target::new("record:1337"),
    Outcome::Denied,
).expect("append");

// Later, prove the chain is untampered.
let (_, sink, _) = chain.into_parts();
let mut verifier = Verifier::new(Sha256Hasher::new());
for r in sink.records() {
    verifier.verify(&r.as_record()).expect("chain must verify");
}
```

### Persisting to a file

```rust
use audit_trail::{
    Action, Actor, Chain, MonotonicClock, Outcome, Sha256Hasher, SystemClock, Target,
};

// Create the file, or open it and verify every record in it.
let clock = MonotonicClock::new(SystemClock::new());
let (mut chain, report) =
    Chain::open_file("audit.log", Sha256Hasher::new(), clock).expect("open and verify");
chain.clock().advance_past(chain.last_timestamp());
println!("{} records verified", report.records());

chain.append(
    Actor::new("user-42"),
    Action::new("user.login"),
    Target::new("session:a"),
    Outcome::Success,
).expect("append");
chain.sink_mut().sync().expect("sync"); // on disk now
```

`Chain::open_file` creates the file owner-only (Unix), refuses a symbolic
link or a file others can write, locks it against a second writer (when
built with Rust 1.89 or later), and tells a crash-cut last record
(`Error::Truncated`, repairable with `open_file_repairing_tail`) apart from
tampering. The file holds a versioned 16-byte header, then
length-prefixed records in the stable [`codec`] encoding; `FileReader`
streams them back.

### What a chain proves

Verification proves that every record read is the one the chain
appended, in order. On its own it cannot see records removed from the
*end*, or a file rewritten by someone able to recompute the (unkeyed)
hashes. Keep the tail (`chain.next_id()`, `chain.last_hash()`) somewhere
the file's writer cannot change and compare it on open, or plug in a
keyed `Hasher`. See [docs/API.md](docs/API.md#what-a-chain-proves).

### Features

| Feature   | Default | What it adds                                              |
|-----------|---------|-----------------------------------------------------------|
| `std`     | yes     | `FileSink`, `FileReader`, `std::error::Error` impls. Implies `alloc`. |
| `alloc`   | yes (via `std`) | `OwnedRecord`, `MemorySink`, `codec` module       |
| `sha2`    | no      | `Sha256Hasher` (reference SHA-256, FIPS 180-4)            |
| `blake3`  | no      | `Blake3Hasher` (reference BLAKE3, faster on modern CPUs)  |

For `no_std` use `default-features = false` and supply your own hasher,
sink, and clock.

### Examples

Runnable demonstrations under [`examples/`](examples/):

```
cargo run --example in_memory --features sha2
cargo run --example file_log --features sha2
cargo run --example tamper_detection --features sha2
```

- [`examples/in_memory.rs`](examples/in_memory.rs) - build a SHA-256 chain in memory, print it, verify it.
- [`examples/file_log.rs`](examples/file_log.rs) - write a chain to a file with `FileSink`, replay it with `FileReader`.
- [`examples/tamper_detection.rs`](examples/tamper_detection.rs) - build a chain, mutate one record, see the `Verifier` reject it with the exact failing `RecordId`.

### Documentation

- [`docs/API.md`](docs/API.md) - full public API reference: every type, trait, function, with descriptions and code examples.
- [docs.rs/audit-trail](https://docs.rs/audit-trail) - generated rustdoc.

### Benchmarks

```
cargo bench --features sha2,blake3
```

Two suites are provided:

- `benches/append.rs` - chain append throughput per hasher (XOR / SHA-256 / BLAKE3).
- `benches/verify.rs` - 1 000-record chain replay through `Verifier`.

---

## Standards

- **REPS** governs every decision. See [REPS.md](REPS.md).
- **MSRV:** Rust 1.85.
- **Edition:** 2024.
- **Cross-platform:** Linux, macOS, Windows.

---

## License

Dual-licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT License ([LICENSE-MIT](LICENSE-MIT))

at your option.



<!-- FOOT COPYRIGHT
################################################# -->
<div align="center">
  <h2></h2>
  <sup>COPYRIGHT <small>&copy;</small> 2026 <strong>JAMES GOBER.</strong></sup>
</div>