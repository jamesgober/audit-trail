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

## [0.5.0] - 2026-05-20

### Added

- `codec` module (feature `alloc`) — stable binary record encoding.
  - `FORMAT_MAGIC` (`b"AUDTRAIL"`), `FORMAT_VERSION` (`0x01`),
    `FILE_HEADER_LEN` constants.
  - `write_file_header`, `verify_file_header` for the 16-byte file
    header.
  - `encode_record`, `decode_record` for length-prefixed record frames.
- `FileSink` (feature `std`) — append-only file-backed `Sink`.
  - `FileSink::open_or_create` writes the header on a fresh file,
    validates it on an existing file, and positions at end-of-file for
    appends.
  - `FileSink::new`, `FileSink::flush`, `FileSink::into_writer` for
    manual writer management.
- `FileReader` (feature `std`) — `Iterator<Item = Result<OwnedRecord>>`
  over a chain file. Validates the header lazily on the first call to
  `next()`, terminates cleanly on EOF, terminates on the first decode
  error.
- `Error::Truncated`, `Error::InvalidFormat`, `Error::Io` — new
  `#[non_exhaustive]`-safe variants for codec and I/O failures.
- `tests/codec.rs` — 11 round-trip and error-path tests covering record
  encode/decode, file header, truncated input, bad magic, bad version,
  bad UTF-8, invalid outcome byte, multi-record streams, empty fields.
- `tests/file_sink.rs` — 4 end-to-end tests: round-trip with verifier,
  reopen + resume across restart, bad-header rejection, mid-record
  truncation detection.
- README quick-start updated with a file-persistence example and a
  feature-matrix update.

### Changed

- `src/sinks.rs` restructured into `src/sinks/{mod, memory, file}.rs`
  to make room for `FileSink` alongside `MemorySink`. The `MemorySink`
  public API is unchanged.
- New `src/readers/{mod, file}.rs` module for streaming readers.
- README quick-start version bumped from `"0.4"` to `"0.5"`.
- Crate version bumped to `0.5.0`.

[Unreleased]: https://github.com/jamesgober/audit-trail/compare/v0.5.0...HEAD
[0.5.0]: https://github.com/jamesgober/audit-trail/releases/tag/v0.5.0

---

## [0.4.0] - 2026-05-20

### Added

- New `alloc` feature flag. `std` now implies `alloc`. `OwnedRecord` and
  `MemorySink` are available with either `alloc` or `std`.
- New `sha2` feature flag. Adds `Sha256Hasher`, a reference SHA-256
  implementation backed by the `sha2` crate (`default-features = false`).
- `OwnedRecord` — owned counterpart to `Record<'a>` with `String`-backed
  fields. `OwnedRecord::from_record`, `OwnedRecord::as_record`, and
  `From<&Record<'_>>` for ergonomic round-tripping.
- `MemorySink` — in-memory reference `Sink` backed by `Vec<OwnedRecord>`.
  Exposes `new`, `with_capacity`, `len`, `is_empty`, `records`,
  `into_records`, `clear`.
- `Sha256Hasher` — reference `Hasher` for the most common compliance
  primitive (FIPS 180-4 SHA-256). 32-byte output, allocation-free, reuses
  internal state across records via `finalize_reset`.
- `tests/integration.rs` — end-to-end real-SHA-256 chain + verifier
  roundtrip (4 tests) covering clean verification, mutation detection,
  link tampering, and `OwnedRecord` round-trip.
- README quick-start now shows a real end-to-end usage example with
  `Sha256Hasher` + `MemorySink` + `Verifier`, plus a feature matrix.

### Changed

- README quick-start version bumped from `"0.2"` to
  `{ version = "0.4", features = ["sha2"] }`.
- `[features]` table: `default = ["std"]`, `std = ["alloc"]`,
  new `alloc = []`, new `sha2 = ["dep:sha2"]`.
- `docs.rs` metadata already builds with `all-features = true` — the new
  feature-gated items render under their feature labels via
  `#[cfg_attr(docsrs, doc(cfg(feature = "...")))]`.

[0.4.0]: https://github.com/jamesgober/audit-trail/releases/tag/v0.4.0

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
