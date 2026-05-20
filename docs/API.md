<h1 align="center">
    <img width="99" alt="Rust logo" src="https://raw.githubusercontent.com/jamesgober/rust-collection/72baabd71f00e14aa9184efcb16fa3deddda3a0a/assets/rust-logo.svg">
    <br>
    <strong>audit-trail</strong>
    <br>
    <sup><sub>API REFERENCE</sub></sup>
</h1>

<p align="center">
    <a href="../README.md">HOME</a> &nbsp;|&nbsp;
    <a href="./API.md">API</a> &nbsp;|&nbsp;
    <a href="./releases/">RELEASES</a> &nbsp;|&nbsp;
    <a href="../REPS.md">REPS</a>
</p>

---

#### Example Pointers

Runnable end-to-end demonstrations. Each is a single self-contained
file under [`examples/`](../examples/) — run with
`cargo run --example <name> --features sha2`.

- [`examples/in_memory.rs`](../examples/in_memory.rs) — build a SHA-256
  hash-chained log in memory, print it, verify it.
- [`examples/file_log.rs`](../examples/file_log.rs) — write a chain to
  a file via `FileSink`, close, reopen, replay through `Verifier`.
- [`examples/tamper_detection.rs`](../examples/tamper_detection.rs) —
  build a chain, mutate one record, prove the `Verifier` rejects it
  with the exact `RecordId` of the offending entry.

---

## Table of Contents

- [Installation](#installation)
- [Feature flags](#feature-flags)
- [Core types](#core-types)
  - [`Record<'a>`](#recorda)
  - [`OwnedRecord`](#ownedrecord)
  - [`RecordId`](#recordid)
  - [`Actor<'a>` / `Action<'a>` / `Target<'a>`](#actora--actiona--targeta)
  - [`Outcome`](#outcome)
  - [`Timestamp`](#timestamp)
  - [`Digest`](#digest)
  - [`HASH_LEN`](#hash_len)
- [Pluggable traits](#pluggable-traits)
  - [`Hasher`](#hasher)
  - [`Sink`](#sink)
  - [`Clock`](#clock)
- [Chain and Verifier](#chain-and-verifier)
  - [`Chain<H, S, C>`](#chainh-s-c)
  - [`Verifier<H>`](#verifierh)
- [Codec module](#codec-module)
  - [Format constants](#format-constants)
  - [`codec::write_file_header`](#codecwrite_file_header)
  - [`codec::verify_file_header`](#codecverify_file_header)
  - [`codec::encode_record`](#codecencode_record)
  - [`codec::decode_record`](#codecdecode_record)
- [Reference implementations](#reference-implementations)
  - [`MemorySink`](#memorysink)
  - [`FileSink<W>`](#filesinkw)
  - [`FileReader<R>`](#filereaderr)
  - [`Sha256Hasher`](#sha256hasher)
  - [`Blake3Hasher`](#blake3hasher)
  - [`SystemClock`](#systemclock)
- [Errors](#errors)
  - [`Error`](#error)
  - [`SinkError`](#sinkerror)
  - [`Result<T>`](#resultt)
- [Patterns](#patterns)
- [Notes](#notes)

---

## Installation

```toml
[dependencies]
audit-trail = { version = "1", features = ["sha2"] }
```

For `no_std`:

```toml
[dependencies]
audit-trail = { version = "1", default-features = false }
```

## Feature flags

| Feature   | Default | What it adds                                                          |
|-----------|---------|-----------------------------------------------------------------------|
| `std`     | yes     | `FileSink`, `FileReader`, `SystemClock`, `std::error::Error` impls. Implies `alloc`. |
| `alloc`   | via `std` | `OwnedRecord`, `MemorySink`, `codec` module.                        |
| `sha2`    | no      | `Sha256Hasher` (FIPS 180-4 reference SHA-256).                        |
| `blake3`  | no      | `Blake3Hasher` (BLAKE3 reference).                                    |

---

## Core types

### `Record<'a>`

Source: `src/record.rs`

  • `Record::new(id, ts, actor, action, target, outcome, prev_hash, hash) -> Self`
    Construct a record from its constituent parts.
  • `Record::with_hash(self, Digest) -> Self`
    Return a copy with the `hash` field replaced.
  • `Record::id(&self) -> RecordId`
  • `Record::timestamp(&self) -> Timestamp`
  • `Record::actor(&self) -> Actor<'a>`
  • `Record::action(&self) -> Action<'a>`
  • `Record::target(&self) -> Target<'a>`
  • `Record::outcome(&self) -> Outcome`
  • `Record::prev_hash(&self) -> Digest`
  • `Record::hash(&self) -> Digest`

A single audited event in the chain — the canonical
`who / what / when / where / result` tuple plus the chain links
(`prev_hash`, `hash`). `Record` is intentionally **borrowed**: its string
fields hold `&str` references rather than owning allocations, so the
append hot path costs nothing on the heap. Sinks that need to retain a
record past the call must encode it (see [`codec::encode_record`]) or
convert it to an [`OwnedRecord`].

`Record` is `Copy`, `Clone`, `Debug`, `PartialEq`, and `Eq`.

Example:
```rust
use audit_trail::{Action, Actor, Digest, Outcome, Record, RecordId, Target, Timestamp};

let record = Record::new(
    RecordId::GENESIS,
    Timestamp::from_nanos(0),
    Actor::new("system"),
    Action::new("chain.init"),
    Target::new("chain:0"),
    Outcome::Success,
    Digest::ZERO,
    Digest::ZERO,
);
assert_eq!(record.actor().as_str(), "system");
```

[`codec::encode_record`]: #codecencode_record
[`OwnedRecord`]: #ownedrecord

---

### `OwnedRecord`

Source: `src/owned.rs` &nbsp; (requires `alloc`)

  • `OwnedRecord::from_record(&Record<'_>) -> Self`
  • `OwnedRecord::as_record(&self) -> Record<'_>`
  • `impl From<&Record<'_>> for OwnedRecord`

Owned counterpart to [`Record`]. Holds `String`-backed `actor`,
`action`, and `target` fields plus the rest of the chain links so it
can outlive the call that produced it.

All eight fields are `pub` — their shape is stable for `1.x` and
mirrors `Record`'s field layout exactly. Construct an `OwnedRecord`
either by converting a borrowed `Record` (via `from_record` /
`From<&Record<'_>>`) or by struct-literal syntax when reconstructing
records from external storage.

`OwnedRecord` is `Clone`, `Debug`, `PartialEq`, `Eq`, and `Hash`.

Example — round-trip:
```rust
# use audit_trail::*;
let borrowed = Record::new(
    RecordId::from_u64(1),
    Timestamp::from_nanos(100),
    Actor::new("u"), Action::new("a"), Target::new("t"),
    Outcome::Success, Digest::ZERO, Digest::ZERO,
);
let owned = OwnedRecord::from_record(&borrowed);
assert_eq!(owned.as_record(), borrowed);
```

Example — reconstructing from a database row:
```rust,no_run
# use audit_trail::*;
# fn row_value<T>(_: &str) -> T { unimplemented!() }
let r = OwnedRecord {
    id: row_value::<RecordId>("id"),
    timestamp: row_value::<Timestamp>("ts"),
    actor: row_value::<String>("actor"),
    action: row_value::<String>("action"),
    target: row_value::<String>("target"),
    outcome: row_value::<Outcome>("outcome"),
    prev_hash: row_value::<Digest>("prev_hash"),
    hash: row_value::<Digest>("hash"),
};
```

[`Record`]: #recorda

---

### `RecordId`

Source: `src/record.rs`

  • `RecordId::GENESIS` — `const`, the first id (`0`).
  • `RecordId::from_u64(u64) -> Self`
  • `RecordId::as_u64(self) -> u64`

`u64` newtype identifying a record. Ids start at `0` for the genesis
record and increment by one for every successful `Chain::append`.

`RecordId` is `Copy`, `Clone`, `Debug`, `PartialEq`, `Eq`, `PartialOrd`,
`Ord`, `Hash`, and `Default` (`Default = GENESIS`).

Example:
```rust
use audit_trail::RecordId;

assert_eq!(RecordId::GENESIS.as_u64(), 0);
assert_eq!(RecordId::from_u64(42), RecordId::from_u64(42));
```

---

### `Actor<'a>` / `Action<'a>` / `Target<'a>`

Source: `src/record.rs`

Three borrowed `&str` newtypes for the "who / what / where" fields of a
record:

  • `Actor::new(&'a str) -> Self` &nbsp;/&nbsp; `Actor::as_str(&self) -> &'a str`
  • `Action::new(&'a str) -> Self` &nbsp;/&nbsp; `Action::as_str(&self) -> &'a str`
  • `Target::new(&'a str) -> Self` &nbsp;/&nbsp; `Target::as_str(&self) -> &'a str`

Each is a `Copy`-by-value wrapper around `&str`. The newtype pattern
prevents argument-order mistakes at the `Chain::append` call site (you
can't accidentally pass an `action` where an `actor` is expected).

Conventionally:
- `Actor` is a user id, service principal, or session token.
- `Action` is a dotted verb, e.g. `"user.login"`, `"record.delete"`.
- `Target` is a resource identifier, e.g. `"record:42"`,
  `"tenant:acme/user:1"`.

Example:
```rust
use audit_trail::{Action, Actor, Target};

let actor = Actor::new("user-42");
let action = Action::new("record.delete");
let target = Target::new("record:1337");

assert_eq!(actor.as_str(), "user-42");
```

---

### `Outcome`

Source: `src/record.rs`

```rust,ignore
#[non_exhaustive]
#[repr(u8)]
pub enum Outcome {
    Success = 0,
    Failure = 1,
    Denied  = 2,
    Error   = 3,
}
```

  • `Outcome::as_u8(self) -> u8` — stable numeric encoding for the codec.

Outcome of an audited action. `#[non_exhaustive]` so additional outcomes
may be added in `1.x` without a major bump. The numeric encoding via
`as_u8()` is part of the on-disk wire format and is frozen — new
variants will use values 4+.

Example:
```rust
use audit_trail::Outcome;

assert_eq!(Outcome::Success.as_u8(), 0);
assert_eq!(Outcome::Denied.as_u8(), 2);
```

---

### `Timestamp`

Source: `src/clock.rs`

  • `Timestamp::EPOCH` — `const`, the Unix epoch as a timestamp (`0`).
  • `Timestamp::from_nanos(u64) -> Self`
  • `Timestamp::as_nanos(self) -> u64`

`u64` newtype storing nanoseconds since the Unix epoch. The
representable range extends well past the year 2554. `Copy`, `Clone`,
`Debug`, `PartialEq`, `Eq`, `PartialOrd`, `Ord`, `Hash`, `Default`.

Example:
```rust
use audit_trail::Timestamp;

let t = Timestamp::from_nanos(1_700_000_000_000_000_000);
assert_eq!(t.as_nanos(), 1_700_000_000_000_000_000);
assert!(t > Timestamp::EPOCH);
```

---

### `Digest`

Source: `src/hash.rs`

  • `Digest::ZERO` — `const`, all-zero 32-byte digest.
  • `Digest::from_bytes([u8; HASH_LEN]) -> Self`
  • `Digest::as_bytes(&self) -> &[u8; HASH_LEN]`
  • `Digest::into_bytes(self) -> [u8; HASH_LEN]`
  • `impl LowerHex for Digest` — hex rendering via `{:x}`
  • `impl AsRef<[u8]> for Digest`

Fixed-size 32-byte hash output. Used as the `prev_hash` and `hash`
fields on every `Record`. `Copy`, `Clone`, `Debug` (prints as a hex
string), `PartialEq`, `Eq`, `Hash`, `Default` (`Default = ZERO`).

Example:
```rust
use audit_trail::{Digest, HASH_LEN};

let d = Digest::from_bytes([0xAB; HASH_LEN]);
assert_eq!(d.as_bytes()[0], 0xAB);
println!("digest = {d:x}");
```

---

### `HASH_LEN`

Source: `src/hash.rs`

```rust,ignore
pub const HASH_LEN: usize = 32;
```

Length, in bytes, of a hash output produced by a `Hasher`. Fixed at 32
to cover SHA-256, BLAKE3, SHA3-256, KangarooTwelve-256, and any other
modern 32-byte hash. This constant is part of the `1.x` API and will
not change.

---

## Pluggable traits

### `Hasher`

Source: `src/hash.rs`

```rust,ignore
pub trait Hasher {
    fn reset(&mut self);
    fn update(&mut self, bytes: &[u8]);
    fn finalize(&mut self, out: &mut Digest);
}
```

Pluggable hash function used to chain records. Implementations must be
**deterministic** and **collision-resistant**. The trait is hot-path
friendly: no allocations, no boxed trait objects, no `dyn`.

Method semantics:

- **`reset(&mut self)`** — return the hasher to its initial state.
  Called at the start of each record's hashing.
- **`update(&mut self, bytes: &[u8])`** — absorb a byte slice into the
  hash state. Called multiple times per record (once per field).
- **`finalize(&mut self, out: &mut Digest)`** — write the digest into
  `out`. After finalization the hasher is left in an unspecified state
  and must be `reset` before being used again.

The trait is **intentionally open**: external crates implement it to
plug in any hash function. The crate ships two reference impls —
[`Sha256Hasher`](#sha256hasher) and [`Blake3Hasher`](#blake3hasher).

Example — implementing a custom hasher:
```rust
use audit_trail::{Digest, Hasher, HASH_LEN};

/// Trivially-insecure XOR-fold hasher. Deterministic and 32 bytes
/// wide — enough to drive `Chain::append` in tests.
struct XorHasher([u8; HASH_LEN], usize);

impl Hasher for XorHasher {
    fn reset(&mut self) { self.0 = [0u8; HASH_LEN]; self.1 = 0; }
    fn update(&mut self, bytes: &[u8]) {
        for b in bytes {
            self.0[self.1 % HASH_LEN] ^= *b;
            self.1 = self.1.wrapping_add(1);
        }
    }
    fn finalize(&mut self, out: &mut Digest) {
        *out = Digest::from_bytes(self.0);
    }
}
```

---

### `Sink`

Source: `src/sink.rs`

```rust,ignore
pub trait Sink {
    fn write(&mut self, record: &Record<'_>) -> Result<(), SinkError>;
}
```

Pluggable backend that persists each record. Implementations might
write to a file, ship records to a remote logging service, push to a
queue, or buffer in memory. Sinks see records in chain order.

**Error contract:** if `write` returns `Err(SinkError)`, `Chain::append`
wraps the error as `Error::Sink` and propagates it **without advancing
the chain's internal state**. The caller may retry — the next `append`
will produce the same `RecordId` and `prev_hash`.

The trait is **intentionally open** for users to implement. The crate
ships two reference impls — [`MemorySink`](#memorysink) and
[`FileSink<W>`](#filesinkw).

Example — implementing a counting sink:
```rust
use audit_trail::{Record, Sink, SinkError};

#[derive(Default)]
struct CountingSink(usize);

impl Sink for CountingSink {
    fn write(&mut self, _record: &Record<'_>) -> Result<(), SinkError> {
        self.0 += 1;
        Ok(())
    }
}
```

Example — implementing a sink that drops records past a capacity limit:
```rust
use audit_trail::{Record, Sink, SinkError};

struct BoundedSink { records: Vec<String>, cap: usize }

impl Sink for BoundedSink {
    fn write(&mut self, record: &Record<'_>) -> Result<(), SinkError> {
        if self.records.len() >= self.cap {
            return Err(SinkError::Capacity);
        }
        self.records.push(format!("{}: {}", record.id().as_u64(), record.action().as_str()));
        Ok(())
    }
}
```

---

### `Clock`

Source: `src/clock.rs`

```rust,ignore
pub trait Clock {
    fn now(&self) -> Timestamp;
}
```

Pluggable time source. Implementations are expected to be **monotonic
with respect to successive calls**. `Chain::append` enforces strict
monotonicity and returns `Error::NonMonotonicClock` if a regression is
observed.

The trait is **intentionally open**. The crate ships one reference
impl — [`SystemClock`](#systemclock).

Example — a tick-by-one clock useful for tests:
```rust
use std::cell::Cell;
use audit_trail::{Clock, Timestamp};

struct TickClock(Cell<u64>);

impl Clock for TickClock {
    fn now(&self) -> Timestamp {
        let v = self.0.get();
        self.0.set(v.saturating_add(1));
        Timestamp::from_nanos(v)
    }
}
```

Example — a clock backed by `std::time::Instant` for strict monotonicity:
```rust,no_run
use std::time::Instant;
use audit_trail::{Clock, Timestamp};

struct InstantClock { start: Instant, epoch_offset: u64 }

impl Clock for InstantClock {
    fn now(&self) -> Timestamp {
        let nanos = self.start.elapsed().as_nanos() as u64;
        Timestamp::from_nanos(self.epoch_offset + nanos)
    }
}
```

---

## Chain and Verifier

### `Chain<H, S, C>`

Source: `src/chain.rs`

  • `Chain::new(H, S, C) -> Self`
    Build a fresh chain starting from genesis.
  • `Chain::resume(H, S, C, next_id, last_hash, last_timestamp) -> Self`
    Pick up a chain mid-stream from a previously persisted tail.
  • `Chain::append(actor, action, target, outcome) -> Result<RecordId>`
    Append one record. Errors leave the chain state unchanged.
  • `Chain::next_id(&self) -> RecordId`
  • `Chain::last_hash(&self) -> Digest`
  • `Chain::last_timestamp(&self) -> Timestamp`
  • `Chain::sink(&self) -> &S` &nbsp;/&nbsp; `Chain::sink_mut(&mut self) -> &mut S`
  • `Chain::into_parts(self) -> (H, S, C)`

The append-only, hash-linked audit log. Generic over its three
pluggable components — a `Hasher`, a `Sink`, and a `Clock`. Every
successful `append`:

1. Asks the clock for the current timestamp (enforces strict monotonicity).
2. Allocates the next `RecordId` (overflow-checked).
3. Hashes the canonical encoding of `(id, ts, actor, action, target,
   outcome, prev_hash)` together with the previous record's hash.
4. Writes the constructed `Record` to the sink.
5. Updates the running `last_hash`, `last_timestamp`, `next_id`.

`Chain` is **not** `Sync` by virtue of `&mut self` methods. Concurrent
appenders should serialize on the chain or shard across independent
chains.

Errors from `append`:

- `Error::NonMonotonicClock` — clock returned a timestamp not strictly
  greater than the previous record's.
- `Error::Capacity` — id counter would overflow `u64` (unreachable in
  practice).
- `Error::Sink(_)` — the sink rejected the write. State is preserved;
  the caller may retry.

Example — minimal usage with the bundled reference impls:
```rust,no_run
use audit_trail::{
    Action, Actor, Chain, MemorySink, Outcome, Sha256Hasher, SystemClock, Target,
};

let mut chain = Chain::new(Sha256Hasher::new(), MemorySink::new(), SystemClock::new());
let id = chain.append(
    Actor::new("user-42"),
    Action::new("record.delete"),
    Target::new("record:1337"),
    Outcome::Denied,
).expect("append");
println!("Appended record id {}", id.as_u64());
```

Example — resuming after restart:
```rust,no_run
use audit_trail::*;

# fn restore_tail() -> (RecordId, Digest, Timestamp) { todo!() }
# fn open_sink() -> MemorySink { unimplemented!() }
# fn open_hasher() -> Sha256Hasher { unimplemented!() }
let (next_id, last_hash, last_ts) = restore_tail();
let mut chain = Chain::resume(
    open_hasher(),
    open_sink(),
    SystemClock::new(),
    next_id,
    last_hash,
    last_ts,
);
```

---

### `Verifier<H>`

Source: `src/verify.rs`

  • `Verifier::new(H) -> Self` — verify from genesis.
  • `Verifier::resume(H, next_id, last_hash, last_timestamp) -> Self`
  • `Verifier::with_strict_timestamps(self, bool) -> Self`
  • `Verifier::verify(&Record<'_>) -> Result<()>`
  • `Verifier::next_id(&self) -> RecordId`
  • `Verifier::last_hash(&self) -> Digest`
  • `Verifier::last_timestamp(&self) -> Timestamp`
  • `Verifier::into_hasher(self) -> H`

Replays a chain of records and proves its hash linkage is intact. The
verifier is **stateful and sequential** — feed records in chain order.
A failure leaves the verifier's cursor at the last accepted record;
inspect `next_id` / `last_hash` to learn how far verification got.

Per record, four invariants are checked:

1. **Id linkage** — the record's id is the expected next id.
2. **Prev-hash linkage** — `prev_hash` equals the previous record's
   `hash` (or `Digest::ZERO` for the genesis record).
3. **Timestamp monotonicity** — strict by default; toggle with
   `with_strict_timestamps(false)`.
4. **Hash integrity** — the stored `hash` equals the digest recomputed
   from the record's fields.

Errors:

- `Error::IdMismatch(RecordId)` — id is not the expected next.
- `Error::LinkMismatch(RecordId)` — `prev_hash` does not chain.
- `Error::HashMismatch(RecordId)` — stored `hash` ≠ recomputed.
- `Error::NonMonotonicClock` — timestamp regression (strict mode only).

Each variant carries the failing record's id (or, for clock errors,
the verifier's cursor identifies it).

Example — verify a stored chain:
```rust,no_run
use audit_trail::{FileReader, Sha256Hasher, Verifier};

let mut verifier = Verifier::new(Sha256Hasher::new());
for record in FileReader::open("audit.log").expect("open") {
    let r = record.expect("decode");
    verifier.verify(&r.as_record()).expect("chain must verify");
}
println!("Verified {} records", verifier.next_id().as_u64());
```

Example — relaxed-mode verification of a chain with coarser
timestamps:
```rust,no_run
# use audit_trail::*;
# let records: Vec<OwnedRecord> = vec![];
let mut verifier = Verifier::new(Sha256Hasher::new())
    .with_strict_timestamps(false);
for r in &records {
    verifier.verify(&r.as_record()).expect("verify");
}
```

---

## Codec module

Source: `src/codec.rs` &nbsp; (requires `alloc`)

Stable binary codec for serialising records to bytes. The byte layout
is **frozen for `1.x`**. `FileSink` and `FileReader` use this codec
under the hood; custom backends (database / S3 / network) use it
directly.

### Format constants

  • `codec::FORMAT_MAGIC: &[u8; 8] = b"AUDTRAIL"`
  • `codec::FORMAT_VERSION: u8 = 0x01`
  • `codec::FILE_HEADER_LEN: usize = 16`

File header layout (16 bytes):

```text
0..8    magic "AUDTRAIL"
8       format version (0x01)
9..16   reserved, zero
```

Record frame layout (length-prefixed):

```text
0..4    body length (u32 big-endian)
4..     body = id || ts || outcome || prev_hash || hash
                || len+actor || len+action || len+target
```

---

### `codec::write_file_header`

```rust,ignore
pub fn write_file_header(out: &mut Vec<u8>);
```

Append the 16-byte format header to `out`. Always writes exactly
`FILE_HEADER_LEN` bytes.

Example:
```rust
use audit_trail::codec;

let mut buf = Vec::new();
codec::write_file_header(&mut buf);
assert_eq!(buf.len(), 16);
```

---

### `codec::verify_file_header`

```rust,ignore
pub fn verify_file_header(bytes: &[u8]) -> Result<()>;
```

Verify that `bytes` begins with a valid format header.

Errors:
- `Error::Truncated` — `bytes.len() < FILE_HEADER_LEN`.
- `Error::InvalidFormat` — bad magic or unknown format version.

Example:
```rust
use audit_trail::codec::{verify_file_header, write_file_header};

let mut buf = Vec::new();
write_file_header(&mut buf);
verify_file_header(&buf).expect("header round-trips");
```

---

### `codec::encode_record`

```rust,ignore
pub fn encode_record(record: &Record<'_>, out: &mut Vec<u8>) -> Result<()>;
```

Encode `record` into a length-prefixed frame appended to `out`. Writes
`4 + body_len` bytes.

Errors:
- `Error::InvalidFormat` — any string field's UTF-8 length, or the
  resulting body length, would not fit in a `u32`.

Example:
```rust
use audit_trail::{codec, Action, Actor, Digest, Outcome, Record, RecordId, Target, Timestamp};

let r = Record::new(
    RecordId::GENESIS, Timestamp::EPOCH,
    Actor::new("u"), Action::new("a"), Target::new("t"),
    Outcome::Success, Digest::ZERO, Digest::ZERO,
);
let mut buf = Vec::new();
codec::encode_record(&r, &mut buf).expect("encode");
```

---

### `codec::decode_record`

```rust,ignore
pub fn decode_record(bytes: &[u8]) -> Result<(OwnedRecord, usize)>;
```

Decode a single length-prefixed record from the front of `bytes`.
Returns the decoded `OwnedRecord` plus the number of bytes consumed,
so the caller can decode a stream by advancing past each frame.

Errors:
- `Error::Truncated` — input ended before a complete frame.
- `Error::InvalidFormat` — bad length prefix, fixed-field shortfall,
  invalid UTF-8, or body length / sum-of-parts mismatch.

Example — sequential stream decode:
```rust
# use audit_trail::*;
# let buf: Vec<u8> = Vec::new();
let mut cursor = 0;
while cursor < buf.len() {
    let (record, consumed) = audit_trail::codec::decode_record(&buf[cursor..])
        .expect("decode");
    cursor += consumed;
    let _ = record;
}
```

---

## Reference implementations

### `MemorySink`

Source: `src/sinks/memory.rs` &nbsp; (requires `alloc`)

  • `MemorySink::new() -> Self` &nbsp;(`const fn`)
  • `MemorySink::with_capacity(usize) -> Self`
  • `MemorySink::len(&self) -> usize`
  • `MemorySink::is_empty(&self) -> bool`
  • `MemorySink::records(&self) -> &[OwnedRecord]`
  • `MemorySink::into_records(self) -> Vec<OwnedRecord>`
  • `MemorySink::clear(&mut self)`

In-memory sink backed by `Vec<OwnedRecord>`. Intended for tests,
prototypes, and short-lived buffering. Holds the entire chain in
memory — not suitable for long-running production workloads.

Example:
```rust,no_run
use audit_trail::*;

let mut chain = Chain::new(Sha256Hasher::new(), MemorySink::new(), SystemClock::new());
chain.append(Actor::new("a"), Action::new("x"), Target::new("t"), Outcome::Success)
    .expect("append");
let (_, sink, _) = chain.into_parts();
assert_eq!(sink.len(), 1);
```

---

### `FileSink<W>`

Source: `src/sinks/file.rs` &nbsp; (requires `std`)

  • `FileSink::open_or_create(impl AsRef<Path>) -> io::Result<Self>`
    Open a file for append; create with format header if absent.
  • `FileSink::new(W) -> Self`
    Wrap an arbitrary `W: io::Write` already positioned correctly.
  • `FileSink::flush(&mut self) -> io::Result<()>`
  • `FileSink::into_writer(self) -> W`

Append-only file-backed sink. Wraps any `W: io::Write` and serialises
records through the stable [`codec`](#codec-module). The format header
is written exactly once — by `open_or_create` when the target file is
empty. Reopening an existing path validates the header and positions
the writer at end-of-file.

Writes are **not** auto-flushed. Call `flush` at appropriate
checkpoints, or wrap the inner writer in a `BufWriter` (which
`open_or_create` does) and rely on `Drop`.

Errors:
- `open_or_create` surfaces `std::io::Error` for file-system failures;
  an invalid header is reported as `io::ErrorKind::InvalidData`.
- `Sink::write` maps internal errors to `SinkError::Io` /
  `SinkError::Other`.

Example:
```rust,no_run
use audit_trail::{Action, Actor, Chain, FileSink, Outcome, Sha256Hasher, SystemClock, Target};

let sink = FileSink::open_or_create("audit.log").expect("open");
let mut chain = Chain::new(Sha256Hasher::new(), sink, SystemClock::new());
chain.append(Actor::new("u"), Action::new("a"), Target::new("t"), Outcome::Success)
    .expect("append");
let (_, mut sink, _) = chain.into_parts();
sink.flush().expect("flush");
```

---

### `FileReader<R>`

Source: `src/readers/file.rs` &nbsp; (requires `std`)

  • `FileReader::open(impl AsRef<Path>) -> io::Result<Self>`
  • `FileReader::new(R) -> Self`
  • `FileReader::into_reader(self) -> R`
  • `impl<R: Read> Iterator for FileReader<R>` with
    `type Item = Result<OwnedRecord>`

Streaming iterator over a chain file written by `FileSink`. The format
header is validated **lazily** on the first call to `next()`. On any
error the iterator terminates: subsequent calls return `None`.

The reader reuses a single internal scratch buffer across records, so
iteration costs three `String` allocations per record (for `actor`,
`action`, `target`) plus the frame buffer's amortised zero-cost reuse.

Errors yielded by `next()`:
- `Error::Truncated` — input ended mid-record.
- `Error::InvalidFormat` — bad magic, version, or body bytes.
- `Error::Io` — underlying I/O failure (detail suppressed for `Copy` /
  `no_std` compatibility).

Example — replay-and-verify:
```rust,no_run
use audit_trail::{FileReader, Sha256Hasher, Verifier};

let mut verifier = Verifier::new(Sha256Hasher::new());
for record in FileReader::open("audit.log").expect("open") {
    verifier.verify(&record.expect("decode").as_record())
        .expect("verify");
}
```

---

### `Sha256Hasher`

Source: `src/hashers/sha256.rs` &nbsp; (requires `sha2` feature)

  • `Sha256Hasher::new() -> Self`
  • `impl Default for Sha256Hasher`
  • `impl Clone for Sha256Hasher`
  • `impl Hasher for Sha256Hasher`

SHA-256 reference hasher, backed by the `sha2` crate
(`default-features = false`). FIPS 180-4 standard, 32-byte output,
hardware-accelerated on most modern x86_64 platforms. **The recommended
hasher for typical audit-trail use cases.**

Example:
```rust
use audit_trail::{Digest, Hasher, Sha256Hasher};

let mut h = Sha256Hasher::new();
h.update(b"audit-trail");
let mut out = Digest::ZERO;
h.finalize(&mut out);
assert_ne!(out, Digest::ZERO);
```

---

### `Blake3Hasher`

Source: `src/hashers/blake3.rs` &nbsp; (requires `blake3` feature)

  • `Blake3Hasher::new() -> Self`
  • `impl Default for Blake3Hasher`
  • `impl Clone for Blake3Hasher`
  • `impl Hasher for Blake3Hasher`

BLAKE3 reference hasher, backed by the `blake3` crate
(`default-features = false`). 32-byte output, drops in wherever
`Sha256Hasher` would.

> **Performance note:** for the small inputs typical of audit records
> (~100 bytes), `Sha256Hasher` is generally **faster** than
> `Blake3Hasher` on x86_64 thanks to SHA-NI hardware acceleration.
> BLAKE3's tree-parallelism wins on kilobyte+ payloads. See
> [`docs/benchmarks/v0.9.0-baseline.md`](./benchmarks/v0.9.0-baseline.md).

Example:
```rust
use audit_trail::{Blake3Hasher, Digest, Hasher};

let mut h = Blake3Hasher::new();
h.update(b"audit-trail");
let mut out = Digest::ZERO;
h.finalize(&mut out);
assert_ne!(out, Digest::ZERO);
```

---

### `SystemClock`

Source: `src/clock.rs` &nbsp; (requires `std`)

  • `SystemClock::new() -> Self` &nbsp;(`const fn`)
  • `impl Default for SystemClock`
  • `impl Clock for SystemClock`

Wall-clock time source backed by `std::time::SystemTime`. Returns
nanoseconds since the Unix epoch. Saturates at `u64::MAX` for
far-future timestamps (year ~2554+); returns `Timestamp::EPOCH` if the
host clock is pre-epoch (highly unusual).

> **Monotonicity caveat:** `SystemTime` is **not** strictly monotonic.
> A deliberate operator clock-back will trigger
> `Error::NonMonotonicClock` on the next `Chain::append`. Deployments
> that need strict monotonicity should wrap `std::time::Instant`
> themselves (see the [`Clock`](#clock) examples).

Example:
```rust
use audit_trail::{Clock, SystemClock};

let clock = SystemClock::new();
let t = clock.now();
assert!(t.as_nanos() > 0);
```

---

## Errors

### `Error`

Source: `src/error.rs`

```rust,ignore
#[non_exhaustive]
pub enum Error {
    Sink(SinkError),
    ChainBroken,
    Capacity,
    NonMonotonicClock,
    HashMismatch(RecordId),
    LinkMismatch(RecordId),
    IdMismatch(RecordId),
    Truncated,
    InvalidFormat,
    Io,
}
```

Crate-wide error type, `#[non_exhaustive]` so further variants may be
added in `1.x`. `Copy`, `Clone`, `Debug`, `PartialEq`, `Eq`. Implements
`std::error::Error` under the `std` feature, with `source()` chaining
to the inner `SinkError` for the `Sink` variant.

Variant guide:

| Variant | When raised |
|---|---|
| `Sink(SinkError)` | A `Sink::write` call returned `Err`. |
| `ChainBroken` | Reserved fallback for generic chain integrity errors. |
| `Capacity` | A counter or buffer overflowed (e.g. `u64` id overflow). |
| `NonMonotonicClock` | A clock returned a timestamp not strictly greater than the previous. |
| `HashMismatch(id)` | A record's stored `hash` did not match the recomputed digest. |
| `LinkMismatch(id)` | A record's `prev_hash` did not chain to the previous record. |
| `IdMismatch(id)` | A record's id was not the expected next id. |
| `Truncated` | Input ended before a complete record could be decoded. |
| `InvalidFormat` | Encoded bytes did not parse (bad magic/version/UTF-8/length). |
| `Io` | Underlying I/O failure (detail suppressed). |

Example — handling specific variants:
```rust,no_run
# use audit_trail::*;
# fn append() -> Result<RecordId> { unimplemented!() }
match append() {
    Ok(id) => println!("ok {}", id.as_u64()),
    Err(Error::NonMonotonicClock) => eprintln!("clock went backwards"),
    Err(Error::Sink(SinkError::Capacity)) => eprintln!("sink full"),
    Err(other) => eprintln!("audit error: {other}"),
}
```

---

### `SinkError`

Source: `src/error.rs`

```rust,ignore
#[non_exhaustive]
pub enum SinkError { Io, Capacity, Closed, Other }
```

Coarse-grained error category returned by `Sink::write`. Concrete
backends map their internal failures to one of these. Implements
`std::error::Error` under the `std` feature.

Variant guide:

| Variant | When raised |
|---|---|
| `Io` | Underlying I/O failure (disk, socket, …). |
| `Capacity` | Sink has reached its capacity. |
| `Closed` | Sink has been closed and will accept no more writes. |
| `Other` | Sink-specific failure not covered by the above. |

`From<SinkError> for Error` wraps a `SinkError` as `Error::Sink`.

---

### `Result<T>`

Source: `src/error.rs`

```rust,ignore
pub type Result<T> = core::result::Result<T, Error>;
```

Convenience alias used throughout the crate.

---

## Patterns

### Persisting and resuming across restarts

```rust,no_run
use audit_trail::*;

// Writer session.
{
    let sink = FileSink::open_or_create("audit.log").expect("open");
    let mut chain = Chain::new(Sha256Hasher::new(), sink, SystemClock::new());
    chain.append(Actor::new("u"), Action::new("login"), Target::new("session:a"), Outcome::Success)
        .expect("append");
    let (_, mut sink, _) = chain.into_parts();
    sink.flush().expect("flush");
}

// Reader session — discover the tail to resume from.
let mut last: Option<OwnedRecord> = None;
for record in FileReader::open("audit.log").expect("open") {
    last = Some(record.expect("decode"));
}
let last = last.expect("at least one record");
let next_id = RecordId::from_u64(last.id.as_u64() + 1);

// Writer session 2 — resume.
let sink = FileSink::open_or_create("audit.log").expect("reopen");
let mut chain = Chain::resume(
    Sha256Hasher::new(), sink, SystemClock::new(),
    next_id, last.hash, last.timestamp,
);
let _ = chain;
```

### Verifying an externally-produced log

```rust,no_run
use audit_trail::{FileReader, Sha256Hasher, Verifier};

let mut verifier = Verifier::new(Sha256Hasher::new());
let mut count = 0usize;
for record in FileReader::open("audit.log").expect("open") {
    verifier.verify(&record.expect("decode").as_record()).expect("verify");
    count += 1;
}
println!("Chain intact: {count} records, last hash {:x}", verifier.last_hash());
```

### Custom database-backed sink

```rust,no_run
use audit_trail::{codec, Record, Sink, SinkError};

struct PgSink { /* connection, prepared stmt, etc. */ }

impl Sink for PgSink {
    fn write(&mut self, record: &Record<'_>) -> Result<(), SinkError> {
        // Stable codec — write the encoded bytes into a `BYTEA` column.
        let mut buf = Vec::with_capacity(256);
        codec::encode_record(record, &mut buf).map_err(|_| SinkError::Other)?;
        // exec("INSERT INTO audit (id, ts, payload) VALUES ($1, $2, $3)", …)
        let _ = buf;
        Ok(())
    }
}
```

### Tamper-detection demo

See [`examples/tamper_detection.rs`](../examples/tamper_detection.rs)
for a full runnable demonstration of the `Verifier` rejecting a mutated
record with the exact `RecordId` of the offending entry.

---

## Notes

- **Stability:** every public item in this document is part of the
  `1.x` semver contract. Additions are allowed; renames, removals, or
  signature changes are reserved for `2.0`.
- **Wire stability:** any `1.x` reader decodes any `1.x` writer's
  output. `FORMAT_VERSION = 0x01` is permanently reserved for this
  encoding. Future incompatible formats would bump the version byte.
- **MSRV:** Rust 1.85, fixed for the `1.x` line.
- **REPS compliance:** zero-allocation hot path; no `unsafe`; no
  panics in shipping code; no required heavy dependencies; `no_std`
  capable. See [`REPS.md`](../REPS.md).
- **Audit summary:** the pre-1.0 audit pass is documented in
  [`docs/releases/v0.9.0.md`](./releases/v0.9.0.md). Performance
  baseline at
  [`docs/benchmarks/v0.9.0-baseline.md`](./benchmarks/v0.9.0-baseline.md).
