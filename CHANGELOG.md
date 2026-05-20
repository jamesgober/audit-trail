# Changelog

All notable changes to `audit-trail` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Added

### Changed

### Fixed

### Security

---

## [0.3.0] - 2026-05-20

### Added

- `Verifier<H>` — replays a chain of records and proves the chain is
  untampered. Detects mutated fields, broken hash links, skipped or
  reordered ids, and (optionally) non-monotonic timestamps. Exposes
  `Verifier::new`, `Verifier::resume`, `Verifier::with_strict_timestamps`,
  `Verifier::next_id`, `Verifier::last_hash`, `Verifier::last_timestamp`,
  `Verifier::verify`, and `Verifier::into_hasher`.
- `Record::with_hash(self, Digest) -> Self` — return a copy of a record
  with the hash field swapped. Supports the draft-then-hash construction
  pattern that the chain and external storage layers use.
- `Error::HashMismatch(RecordId)` — record's stored hash does not match
  the digest recomputed from its fields.
- `Error::LinkMismatch(RecordId)` — record's `prev_hash` does not equal
  the previous record's hash.
- `Error::IdMismatch(RecordId)` — record's id is not the expected next id
  in the chain.
- `tests/verify.rs` — 7 integration tests covering the verifier across
  the clean-chain path, each mutation class (field, link, id skip,
  timestamp regression), checkpoint resume, and relaxed-timestamp mode.

### Changed

- Internalised the canonical record encoding (`id || ts || actor ||
  action || target || outcome || prev_hash`, `0x1f`-separated) in a new
  crate-private `canonical` module. `Chain::append` and `Verifier::verify`
  now both call into the same encoder, so the producer and consumer of
  the hash cannot drift apart.
- CI workflow: bumped `actions/cache@v4` → `@v5` to clear the GitHub
  Node 20 deprecation annotation. `actions/checkout@v5` and
  `actions/setup-node@v5` were already on Node 24.

[Unreleased]: https://github.com/jamesgober/audit-trail/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/jamesgober/audit-trail/releases/tag/v0.3.0

---

## [0.2.1] - 2026-05-20

### Fixed

- CI fmt step failed on GitHub's Windows runner because its default
  `core.autocrlf=true` rewrote LF-committed sources to CRLF on checkout,
  which `rustfmt`'s `newline_style = "Unix"` then rejected. Added a
  `.gitattributes` enforcing LF on checkout for every text source
  (`*.rs`, `*.toml`, `*.md`, `*.yml`, `*.yaml`, `*.json`, `*.sh`) and
  explicitly marking common binary types, so the Windows job formats
  cleanly without changing committed bytes.

---

## [0.2.0] - 2026-05-20

### Added

- Public API surface for the Foundation milestone.
- `Record` type with the 5W tuple (`Actor`, `Action`, `Target`, `Outcome`,
  `Timestamp`) plus chain links (`prev_hash`, `hash`).
- `RecordId` newtype with `GENESIS` constant.
- `Digest` fixed-size hash output (`HASH_LEN = 32`) with `ZERO`,
  `from_bytes`, `as_bytes`, `into_bytes`, and `LowerHex` rendering.
- `Hasher` trait — pluggable, allocation-free hash function.
- `Sink` trait — pluggable persistence backend.
- `Clock` trait + `Timestamp` newtype (nanoseconds since Unix epoch).
- `Chain<H, S, C>` — append-only, hash-linked log generic over its three
  pluggable components, with `new`, `resume`, `append`, `next_id`,
  `last_hash`, `last_timestamp`, `sink`, `sink_mut`, and `into_parts`.
- `Error` enum (`Sink`, `ChainBroken`, `Capacity`, `NonMonotonicClock`)
  and `SinkError` enum (`Io`, `Capacity`, `Closed`, `Other`); both
  `#[non_exhaustive]`. `std::error::Error` impls under the `std` feature.
- Smoke tests covering genesis, chain linkage, clock monotonicity, sink
  failure propagation, and chain resume.
- Doc-tested rustdoc examples on every public item.

### Changed

- Bumped MSRV to 1.85 (required by `edition = "2024"`).
- CI matrix updated to `1.85.0` alongside `stable`.
- README MSRV badge and `Quick start` version updated.

---

## [0.1.0] - 2026-05-18

### Added

- Initial scaffold and repository bootstrap.
- REPS compliance baseline.
- CI for Linux/macOS/Windows on stable and MSRV.

[0.2.1]: https://github.com/jamesgober/audit-trail/releases/tag/v0.2.1
[0.2.0]: https://github.com/jamesgober/audit-trail/releases/tag/v0.2.0
