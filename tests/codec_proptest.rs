//! Property tests for the codec.
//!
//! Generates random valid records and asserts:
//! * `encode_record` followed by `decode_record` is the identity,
//! * the entire encoded buffer is consumed,
//! * mutating any single byte after the length prefix and decoding never
//!   panics (it may produce an error, or a different valid record, but
//!   must never crash).

#![cfg(feature = "alloc")]

use audit_trail::codec::{decode_record, encode_record};
use audit_trail::{Digest, Error, HASH_LEN, Outcome, OwnedRecord, RecordId, Timestamp};
use proptest::collection::vec;
use proptest::prelude::*;

fn outcome_from_byte(b: u8) -> Outcome {
    match b % 4 {
        0 => Outcome::Success,
        1 => Outcome::Failure,
        2 => Outcome::Denied,
        _ => Outcome::Error,
    }
}

prop_compose! {
    fn arb_record()(
        id in any::<u64>(),
        ts in any::<u64>(),
        actor in "[\\x20-\\x7E]{0,64}",
        action in "[\\x20-\\x7E]{0,64}",
        target in "[\\x20-\\x7E]{0,128}",
        outcome_byte in any::<u8>(),
        prev_hash in any::<[u8; HASH_LEN]>(),
        hash in any::<[u8; HASH_LEN]>(),
    ) -> OwnedRecord {
        OwnedRecord {
            id: RecordId::from_u64(id),
            timestamp: Timestamp::from_nanos(ts),
            actor,
            action,
            target,
            outcome: outcome_from_byte(outcome_byte),
            prev_hash: Digest::from_bytes(prev_hash),
            hash: Digest::from_bytes(hash),
        }
    }
}

proptest! {
    /// `encode_record` then `decode_record` is the identity for any
    /// well-formed record.
    #[test]
    fn encode_decode_roundtrip(record in arb_record()) {
        let mut buf = Vec::new();
        encode_record(&record.as_record(), &mut buf).expect("encode");
        let (decoded, consumed) = decode_record(&buf).expect("decode");
        prop_assert_eq!(consumed, buf.len());
        prop_assert_eq!(decoded, record);
    }

    /// Multiple records concatenated decode back to the same sequence,
    /// in order, with no leftover bytes.
    #[test]
    fn multi_record_roundtrip(records in vec(arb_record(), 0..16)) {
        let mut buf = Vec::new();
        for r in &records {
            encode_record(&r.as_record(), &mut buf).expect("encode");
        }
        let mut cursor = 0;
        let mut decoded = Vec::with_capacity(records.len());
        while cursor < buf.len() {
            let (r, n) = decode_record(&buf[cursor..]).expect("decode");
            cursor += n;
            decoded.push(r);
        }
        prop_assert_eq!(cursor, buf.len());
        prop_assert_eq!(decoded, records);
    }

    /// Mutating one byte after the length prefix never panics. The
    /// decoder must always return either `Ok(...)` or `Err(...)`.
    #[test]
    fn single_byte_mutation_never_panics(
        record in arb_record(),
        byte_offset in 4usize..256,
        new_byte in any::<u8>(),
    ) {
        let mut buf = Vec::new();
        encode_record(&record.as_record(), &mut buf).expect("encode");
        if byte_offset >= buf.len() {
            return Ok(());
        }
        buf[byte_offset] = new_byte;
        // We don't care about the result; we care that decoding terminates
        // without panicking.
        match decode_record(&buf) {
            Ok(_) | Err(_) => {}
        }
    }

    /// Truncating the buffer at any offset never panics.
    #[test]
    fn arbitrary_truncation_never_panics(
        record in arb_record(),
        truncate_to in 0usize..256,
    ) {
        let mut buf = Vec::new();
        encode_record(&record.as_record(), &mut buf).expect("encode");
        let cut = truncate_to.min(buf.len());
        buf.truncate(cut);
        match decode_record(&buf) {
            Ok(_) => {} // can happen if cut == full frame
            Err(Error::Truncated | Error::InvalidFormat) => {}
            Err(other) => prop_assert!(false, "unexpected error: {other:?}"),
        }
    }
}
