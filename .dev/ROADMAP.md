# audit-trail - Roadmap to 1.0

Fast-track. No slow-stepping.

---

## Phase 0.1.0 - Scaffold (done)

- [x] Repository created
- [x] Cargo.toml, README, LICENSE x2, CHANGELOG
- [x] REPS.md
- [x] CI workflow (Linux/macOS/Windows on stable + MSRV, Node 24)
- [x] Initial commit pushed

---

## Phase 0.2.0 - Foundation (done)

Define the public API surface.

Skill areas in scope:

  - hash chaining
  - audit log integrity
  - compliance frameworks
  - structured logging

- [x] Public types defined
- [x] Public traits defined
- [x] Module structure laid out
- [x] Error type defined
- [x] First end-to-end smoke test passing
- [x] CHANGELOG updated
- [x] `.dev/release/v0.2.0.md` written

---

## Phase 0.5.0 - Implementation

- [ ] All public API methods implemented (no `todo!()`)
- [ ] Property tests for state machines / invariants
- [ ] Integration tests
- [ ] Basic benchmarks
- [ ] Documentation drafted
- [ ] No `unwrap` / `expect` outside of tests
- [ ] CHANGELOG updated
- [ ] `.dev/release/v0.5.0.md` written

---

## Phase 0.9.0 - Hardening + Audit (done; CI re-validation pending)

Feature freeze. Quality focus.

### Audit checklist (mandatory)

#### Feature completeness
- [x] Every roadmap item delivered
- [x] Every README claim verified

#### Code cleanliness
- [x] No dead code
- [x] No commented-out code
- [x] No TODO/FIXME without tracking issue
- [x] No `#[allow(...)]` without justification

#### Error hardening
- [x] Every public function: all error paths documented
- [x] Every error variant: documented + tested
- [x] No panics in shipping code paths
- [x] Error messages actionable

#### API stability
- [x] Every public item reviewed for 1.0
- [x] Sealed traits where appropriate (none — pluggability is the point)
- [x] `#[non_exhaustive]` on growth-likely enums

#### Documentation
- [x] Every public item: rustdoc with example
- [x] README accurate
- [x] CHANGELOG complete
- [x] `cargo doc` zero warnings (both default and `--all-features`)

#### Tests
- [x] Unit test coverage on all public functions
- [x] Integration tests
- [x] Property tests for invariants
- [ ] Cross-platform CI green (pending push)
- [ ] Both stable and MSRV green (pending push)

#### Performance
- [x] Hot paths benchmarked
- [x] Allocation profile checked
- [x] No regressions (no prior baseline; this release captures one)
- [x] Benchmark baselines saved (`.dev/benchmarks/v0.9.0-baseline.md`)

#### Final
- [x] `cargo fmt --all -- --check` clean
- [x] `cargo clippy --all-targets --all-features -- -D warnings` clean
- [x] `cargo test --all-features` clean
- [x] `cargo doc` clean with `RUSTDOCFLAGS=-D warnings`

### Output
- [x] `.dev/release/v0.9.0.md` written
- [x] Audit findings logged (in the release note)
- [x] All findings resolved (no items deferred to 1.x)

---

## Phase 0.9.x - Audit fixes (skipped)

The `v0.9.0` audit closed cleanly — no audit findings required a
`0.9.x` follow-up. Proceeded directly to `1.0.0`.

- [x] All 0.9.0 blockers resolved (no blockers found)
- [x] No new features (0.9.0 was feature-frozen and stayed that way)
- [x] Final benchmarks recorded (`.dev/benchmarks/v0.9.0-baseline.md`)
- [x] Final API freeze

---

## Phase 1.0.0 - Stable release (done; tag + publish pending)

- [x] All 0.9.x findings resolved (none to resolve)
- [x] Final API freeze
- [x] Final benchmarks captured
- [x] `.dev/release/v1.0.0.md` written
- [ ] Tag `v1.0.0` on main (pending CI green on this commit)
- [ ] Publish to crates.io (pending tag)