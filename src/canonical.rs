//! Canonical record encoding used by both [`crate::Chain::append`] and
//! [`crate::Verifier::verify`].
//!
//! Centralising the encoding here guarantees that the producer (the
//! `Chain`) and the consumer (the `Verifier`) never drift apart. The byte
//! layout is **stable** — changing it is a breaking change to the on-disk
//! hash, even if no public API changes.

use crate::hash::{Digest, Hasher};
use crate::record::Record;

/// Stable separator byte mixed between hashed fields to prevent
/// concatenation-collision ambiguity (e.g. `"ab" + "c"` vs `"a" + "bc"`).
pub(crate) const FIELD_SEP: u8 = 0x1f;

/// Feed a record's canonical bytes through `hasher` and return the digest.
///
/// The record's own `hash` field is intentionally **not** part of the
/// input — it is the *output* of this function. The `prev_hash` field is
/// part of the input, which is what links records into a chain.
///
/// Field order (each separated by [`FIELD_SEP`]):
/// `id` (`u64` big-endian) → `timestamp` (`u64` big-endian nanos) →
/// `actor` (UTF-8) → `action` (UTF-8) → `target` (UTF-8) →
/// `outcome` (`u8`) → `prev_hash` (32 bytes).
pub(crate) fn compute<H: Hasher>(hasher: &mut H, record: &Record<'_>) -> Digest {
    hasher.reset();
    hasher.update(&record.id().as_u64().to_be_bytes());
    hasher.update(&[FIELD_SEP]);
    hasher.update(&record.timestamp().as_nanos().to_be_bytes());
    hasher.update(&[FIELD_SEP]);
    hasher.update(record.actor().as_str().as_bytes());
    hasher.update(&[FIELD_SEP]);
    hasher.update(record.action().as_str().as_bytes());
    hasher.update(&[FIELD_SEP]);
    hasher.update(record.target().as_str().as_bytes());
    hasher.update(&[FIELD_SEP]);
    hasher.update(&[record.outcome().as_u8()]);
    hasher.update(&[FIELD_SEP]);
    hasher.update(record.prev_hash().as_bytes());

    let mut out = Digest::ZERO;
    hasher.finalize(&mut out);
    out
}
