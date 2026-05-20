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

[Unreleased]: https://github.com/jamesgober/audit-trail/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/jamesgober/audit-trail/releases/tag/v0.2.0
[0.1.0]: https://github.com/jamesgober/audit-trail/releases/tag/v0.1.0
