//! Codec tests: round-trip a record through `encode_record` /
//! `decode_record`, validate file-header round-trip, and exercise the
//! error paths (truncated input, bad magic, bad version, bad UTF-8).

use audit_trail::codec::{
    self, FILE_HEADER_LEN, FORMAT_MAGIC, FORMAT_VERSION, decode_record, encode_record,
    verify_file_header, write_file_header,
};
use audit_trail::{
    Action, Actor, Digest, Error, HASH_LEN, Outcome, OwnedRecord, Record, RecordId, Target,
    Timestamp,
};

fn sample_record() -> OwnedRecord {
    OwnedRecord {
        id: RecordId::from_u64(42),
        timestamp: Timestamp::from_nanos(1_700_000_000_000_000_000),
        actor: String::from("user-1"),
        action: String::from("record.delete"),
        target: String::from("record:1337"),
        outcome: Outcome::Denied,
        prev_hash: Digest::from_bytes([0xAA; HASH_LEN]),
        hash: Digest::from_bytes([0xBB; HASH_LEN]),
    }
}

#[test]
fn record_round_trips() {
    let original = sample_record();
    let mut buf = Vec::new();
    encode_record(&original.as_record(), &mut buf).expect("encode");
    let (decoded, consumed) = decode_record(&buf).expect("decode");
    assert_eq!(consumed, buf.len());
    assert_eq!(decoded, original);
}

#[test]
fn file_header_round_trips() {
    let mut buf = Vec::new();
    write_file_header(&mut buf);
    assert_eq!(buf.len(), FILE_HEADER_LEN);
    assert_eq!(&buf[0..8], FORMAT_MAGIC);
    assert_eq!(buf[8], FORMAT_VERSION);
    verify_file_header(&buf).expect("valid header round-trips");
}

#[test]
fn header_short_input_is_truncated() {
    let short = [0u8; 4];
    assert_eq!(verify_file_header(&short), Err(Error::Truncated));
}

#[test]
fn header_bad_magic_is_invalid_format() {
    let mut buf = Vec::new();
    write_file_header(&mut buf);
    buf[0] = b'X';
    assert_eq!(verify_file_header(&buf), Err(Error::InvalidFormat));
}

#[test]
fn header_bad_version_is_invalid_format() {
    let mut buf = Vec::new();
    write_file_header(&mut buf);
    buf[8] = 0xFF;
    assert_eq!(verify_file_header(&buf), Err(Error::InvalidFormat));
}

#[test]
fn truncated_record_is_truncated_error() {
    let original = sample_record();
    let mut buf = Vec::new();
    encode_record(&original.as_record(), &mut buf).expect("encode");

    // Drop the last byte of the frame.
    let _ = buf.pop();
    assert_eq!(decode_record(&buf), Err(Error::Truncated));

    // Drop all but the first 2 bytes (less than the 4-byte length prefix).
    let mut tiny = buf;
    tiny.truncate(2);
    assert_eq!(decode_record(&tiny), Err(Error::Truncated));
}

#[test]
fn invalid_outcome_byte_is_invalid_format() {
    let original = sample_record();
    let mut buf = Vec::new();
    encode_record(&original.as_record(), &mut buf).expect("encode");

    // Outcome byte sits at offset 4 (skip length prefix) + 8 (id) + 8 (ts).
    let outcome_idx = 4 + 8 + 8;
    buf[outcome_idx] = 0xFF;
    assert_eq!(decode_record(&buf), Err(Error::InvalidFormat));
}

#[test]
fn invalid_utf8_in_string_field_is_invalid_format() {
    let original = sample_record();
    let mut buf = Vec::new();
    encode_record(&original.as_record(), &mut buf).expect("encode");

    // Actor starts right after the fixed prefix (offset 4 + 8 + 8 + 1 + 32 + 32 = 85)
    // plus its own 4-byte length prefix.
    let actor_start = 4 + 8 + 8 + 1 + HASH_LEN + HASH_LEN + 4;
    // Replace the first actor byte with a continuation byte (invalid as a
    // UTF-8 start byte).
    buf[actor_start] = 0x80;
    assert_eq!(decode_record(&buf), Err(Error::InvalidFormat));
}

#[test]
fn many_records_can_be_decoded_sequentially() {
    let mut buf = Vec::new();
    let originals: Vec<OwnedRecord> = (0..5)
        .map(|i| OwnedRecord {
            id: RecordId::from_u64(i),
            timestamp: Timestamp::from_nanos(i * 1000),
            actor: format!("user-{i}"),
            action: String::from("test.action"),
            target: format!("target:{i}"),
            outcome: Outcome::Success,
            prev_hash: Digest::from_bytes([i as u8; HASH_LEN]),
            hash: Digest::from_bytes([(i + 1) as u8; HASH_LEN]),
        })
        .collect();

    for r in &originals {
        encode_record(&r.as_record(), &mut buf).expect("encode");
    }

    let mut cursor = 0;
    let mut decoded = Vec::new();
    while cursor < buf.len() {
        let (record, consumed) = decode_record(&buf[cursor..]).expect("decode");
        cursor += consumed;
        decoded.push(record);
    }
    assert_eq!(cursor, buf.len());
    assert_eq!(decoded, originals);
}

#[test]
fn empty_string_fields_are_legal() {
    let record = OwnedRecord {
        id: RecordId::GENESIS,
        timestamp: Timestamp::EPOCH,
        actor: String::new(),
        action: String::new(),
        target: String::new(),
        outcome: Outcome::Success,
        prev_hash: Digest::ZERO,
        hash: Digest::ZERO,
    };
    let mut buf = Vec::new();
    encode_record(&record.as_record(), &mut buf).expect("encode");
    let (decoded, _) = decode_record(&buf).expect("decode");
    assert_eq!(decoded, record);
}

#[test]
fn borrowed_record_round_trips_without_owned_intermediate() {
    let borrowed = Record::new(
        RecordId::from_u64(7),
        Timestamp::from_nanos(99),
        Actor::new("u"),
        Action::new("a"),
        Target::new("t"),
        Outcome::Failure,
        Digest::from_bytes([1; HASH_LEN]),
        Digest::from_bytes([2; HASH_LEN]),
    );
    let mut buf = Vec::new();
    encode_record(&borrowed, &mut buf).expect("encode");
    let (decoded, _) = codec::decode_record(&buf).expect("decode");
    assert_eq!(decoded.as_record(), borrowed);
}
