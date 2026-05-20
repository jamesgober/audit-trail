//! Stable binary codec for serialising audit records to bytes.
//!
//! Requires the `alloc` feature. `std`-gated readers and sinks
//! ([`crate::FileSink`], [`crate::FileReader`]) use this codec under the
//! hood.
//!
//! # Stability promise
//!
//! The byte layout defined here is **stable**. Changing it is a breaking
//! change to any on-disk audit log. The format embeds a one-byte version
//! ([`FORMAT_VERSION`]) so future incompatible formats can coexist by
//! bumping it.
//!
//! # File layout
//!
//! ```text
//! ┌────────────────────────────────────────────────────────────────┐
//! │ FILE HEADER (16 bytes)                                         │
//! ├────────────────────────────────────────────────────────────────┤
//! │ 0..8   "AUDTRAIL" magic                                        │
//! │ 8      format version (currently 0x01)                         │
//! │ 9..16  reserved, zero                                          │
//! ├────────────────────────────────────────────────────────────────┤
//! │ RECORD FRAME (one per record, repeated)                        │
//! ├────────────────────────────────────────────────────────────────┤
//! │ 0..4   record body length (u32 big-endian)                     │
//! │ 4..    record body                                             │
//! └────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Record body layout
//!
//! ```text
//! 0..8    id           u64 big-endian
//! 8..16   timestamp    u64 big-endian (nanoseconds since Unix epoch)
//! 16      outcome      u8
//! 17..49  prev_hash    32 bytes
//! 49..81  hash         32 bytes
//! 81..85  actor_len    u32 big-endian
//! 85..    actor        UTF-8 bytes
//! ...     action_len   u32 big-endian
//! ...     action       UTF-8 bytes
//! ...     target_len   u32 big-endian
//! ...     target       UTF-8 bytes
//! ```

use alloc::string::String;
use alloc::vec::Vec;

use crate::clock::Timestamp;
use crate::error::{Error, Result};
use crate::hash::{Digest, HASH_LEN};
use crate::owned::OwnedRecord;
use crate::record::{Outcome, Record, RecordId};

/// File-format magic bytes. Appear at the start of every chain file.
pub const FORMAT_MAGIC: &[u8; 8] = b"AUDTRAIL";

/// Current file-format version.
pub const FORMAT_VERSION: u8 = 0x01;

/// Length of the file header in bytes.
pub const FILE_HEADER_LEN: usize = 16;

/// Length of a record's fixed prefix in bytes
/// (`id || timestamp || outcome || prev_hash || hash`).
const RECORD_FIXED_LEN: usize = 8 + 8 + 1 + HASH_LEN + HASH_LEN;

/// Write the file header into `out`.
///
/// Always writes exactly [`FILE_HEADER_LEN`] bytes.
pub fn write_file_header(out: &mut Vec<u8>) {
    out.extend_from_slice(FORMAT_MAGIC);
    out.push(FORMAT_VERSION);
    out.extend_from_slice(&[0u8; 7]);
}

/// Verify that `bytes` begins with a valid file header.
///
/// # Errors
///
/// * [`Error::Truncated`] — `bytes.len() < FILE_HEADER_LEN`.
/// * [`Error::InvalidFormat`] — bad magic or unknown version.
pub fn verify_file_header(bytes: &[u8]) -> Result<()> {
    if bytes.len() < FILE_HEADER_LEN {
        return Err(Error::Truncated);
    }
    if &bytes[0..8] != FORMAT_MAGIC {
        return Err(Error::InvalidFormat);
    }
    if bytes[8] != FORMAT_VERSION {
        return Err(Error::InvalidFormat);
    }
    Ok(())
}

/// Encode `record` into a length-prefixed frame appended to `out`.
///
/// Writes `4 + body_len` bytes. The 4-byte prefix is the body length as a
/// big-endian `u32`; the body follows the layout documented in the module
/// rustdoc.
///
/// # Errors
///
/// * [`Error::InvalidFormat`] — any string field's UTF-8 byte length, or
///   the resulting body length, would not fit in a `u32`. In practice
///   audit fields are tiny; the check is here so that absurd inputs
///   produce a typed error rather than silent truncation.
pub fn encode_record(record: &Record<'_>, out: &mut Vec<u8>) -> Result<()> {
    let actor_bytes = record.actor().as_str().as_bytes();
    let action_bytes = record.action().as_str().as_bytes();
    let target_bytes = record.target().as_str().as_bytes();

    if actor_bytes.len() > u32::MAX as usize
        || action_bytes.len() > u32::MAX as usize
        || target_bytes.len() > u32::MAX as usize
    {
        return Err(Error::InvalidFormat);
    }

    let body_len =
        RECORD_FIXED_LEN + 4 + actor_bytes.len() + 4 + action_bytes.len() + 4 + target_bytes.len();
    if body_len > u32::MAX as usize {
        return Err(Error::InvalidFormat);
    }

    out.reserve(4 + body_len);

    out.extend_from_slice(&(body_len as u32).to_be_bytes());
    out.extend_from_slice(&record.id().as_u64().to_be_bytes());
    out.extend_from_slice(&record.timestamp().as_nanos().to_be_bytes());
    out.push(record.outcome().as_u8());
    out.extend_from_slice(record.prev_hash().as_bytes());
    out.extend_from_slice(record.hash().as_bytes());

    out.extend_from_slice(&(actor_bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(actor_bytes);
    out.extend_from_slice(&(action_bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(action_bytes);
    out.extend_from_slice(&(target_bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(target_bytes);

    Ok(())
}

/// Decode a single length-prefixed record frame from the front of
/// `bytes`. Returns the decoded record plus the number of bytes consumed.
///
/// # Errors
///
/// * [`Error::Truncated`] — input ended before a full frame could be read.
/// * [`Error::InvalidFormat`] — length prefix would overflow, fixed
///   fields are short, UTF-8 fields are invalid, or the body length does
///   not match the sum of its parts.
pub fn decode_record(bytes: &[u8]) -> Result<(OwnedRecord, usize)> {
    if bytes.len() < 4 {
        return Err(Error::Truncated);
    }
    let body_len = read_u32(&bytes[0..4]) as usize;
    let frame_end = 4usize.checked_add(body_len).ok_or(Error::InvalidFormat)?;
    if bytes.len() < frame_end {
        return Err(Error::Truncated);
    }

    let body = &bytes[4..frame_end];
    if body.len() < RECORD_FIXED_LEN {
        return Err(Error::InvalidFormat);
    }

    let id = RecordId::from_u64(read_u64(&body[0..8]));
    let timestamp = Timestamp::from_nanos(read_u64(&body[8..16]));
    let outcome = decode_outcome(body[16])?;
    let mut prev_hash = [0u8; HASH_LEN];
    prev_hash.copy_from_slice(&body[17..17 + HASH_LEN]);
    let mut hash = [0u8; HASH_LEN];
    hash.copy_from_slice(&body[17 + HASH_LEN..17 + HASH_LEN + HASH_LEN]);

    let mut cursor = RECORD_FIXED_LEN;
    let actor = read_string_field(body, &mut cursor)?;
    let action = read_string_field(body, &mut cursor)?;
    let target = read_string_field(body, &mut cursor)?;

    if cursor != body.len() {
        return Err(Error::InvalidFormat);
    }

    let record = OwnedRecord {
        id,
        timestamp,
        actor,
        action,
        target,
        outcome,
        prev_hash: Digest::from_bytes(prev_hash),
        hash: Digest::from_bytes(hash),
    };
    Ok((record, frame_end))
}

fn decode_outcome(byte: u8) -> Result<Outcome> {
    match byte {
        0 => Ok(Outcome::Success),
        1 => Ok(Outcome::Failure),
        2 => Ok(Outcome::Denied),
        3 => Ok(Outcome::Error),
        _ => Err(Error::InvalidFormat),
    }
}

fn read_string_field(body: &[u8], cursor: &mut usize) -> Result<String> {
    if body.len() < cursor.checked_add(4).ok_or(Error::InvalidFormat)? {
        return Err(Error::InvalidFormat);
    }
    let len = read_u32(&body[*cursor..*cursor + 4]) as usize;
    *cursor += 4;
    let end = cursor.checked_add(len).ok_or(Error::InvalidFormat)?;
    if body.len() < end {
        return Err(Error::InvalidFormat);
    }
    let bytes = &body[*cursor..end];
    let s = core::str::from_utf8(bytes).map_err(|_| Error::InvalidFormat)?;
    *cursor = end;
    Ok(String::from(s))
}

fn read_u32(bytes: &[u8]) -> u32 {
    let mut buf = [0u8; 4];
    buf.copy_from_slice(&bytes[0..4]);
    u32::from_be_bytes(buf)
}

fn read_u64(bytes: &[u8]) -> u64 {
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&bytes[0..8]);
    u64::from_be_bytes(buf)
}
