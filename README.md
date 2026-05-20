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
use audit_trail::{Chain, FileSink, FileReader, Sha256Hasher, SystemClock, Verifier};

let sink = FileSink::open_or_create("audit.log").expect("open");
let mut chain = Chain::new(Sha256Hasher::new(), sink, SystemClock::new());
// ... chain.append(...) ...

// Replay and verify the on-disk log.
let mut verifier = Verifier::new(Sha256Hasher::new());
for record in FileReader::open("audit.log").expect("open") {
    let r = record.expect("decode");
    verifier.verify(&r.as_record()).expect("verify");
}
```

`FileSink` writes a versioned 16-byte header on a fresh file, then
length-prefixed records using the stable [`codec`] encoding. Reopening
the same path appends after validating the header.

### Features

| Feature   | Default | What it adds                                              |
|-----------|---------|-----------------------------------------------------------|
| `std`     | yes     | `FileSink`, `FileReader`, `std::error::Error` impls. Implies `alloc`. |
| `alloc`   | yes (via `std`) | `OwnedRecord`, `MemorySink`, `codec` module       |
| `sha2`    | no      | `Sha256Hasher` (reference SHA-256, FIPS 180-4)            |
| `blake3`  | no      | `Blake3Hasher` (reference BLAKE3, faster on modern CPUs)  |

For `no_std` use `default-features = false` and supply your own hasher,
sink, and clock.

### Benchmarks

```
cargo bench --features sha2,blake3
```

Two suites are provided:

- `benches/append.rs` — chain append throughput per hasher (XOR / SHA-256 / BLAKE3).
- `benches/verify.rs` — 1 000-record chain replay through `Verifier`.

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