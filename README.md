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
audit-trail = { version = "0.4", features = ["sha2"] }
```

```rust,no_run
use audit_trail::{
    Action, Actor, Chain, Clock, MemorySink, Outcome, Sha256Hasher, Target, Timestamp, Verifier,
};

// Plug in any monotonic time source.
struct SystemClock;
impl Clock for SystemClock {
    fn now(&self) -> Timestamp {
        let ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        Timestamp::from_nanos(ns)
    }
}

let mut chain = Chain::new(Sha256Hasher::new(), MemorySink::new(), SystemClock);

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

### Features

| Feature   | Default | What it adds                                      |
|-----------|---------|---------------------------------------------------|
| `std`     | yes     | `std::error::Error` impls; implies `alloc`        |
| `alloc`   | yes (via `std`) | `OwnedRecord`, `MemorySink`                  |
| `sha2`    | no      | `Sha256Hasher` (reference SHA-256 implementation) |

For `no_std` use `default-features = false` and supply your own hasher,
sink, and clock.

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