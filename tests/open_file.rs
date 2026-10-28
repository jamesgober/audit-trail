//! `Chain::open_file`: verify on open, resume at the tail, report a cut
//! last record apart from tampering, and keep cut bytes as evidence.
//! Also `FileSink::sync`, `Chain::flush`, and `MonotonicClock`.

#![cfg(all(feature = "sha2", feature = "std"))]

use std::cell::Cell;
use std::env;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;

use audit_trail::{
    Action, Actor, Chain, Clock, Error, FileReader, MonotonicClock, Outcome, Sha256Hasher, Target,
    Timestamp, Verifier,
};

struct TickClock(Cell<u64>);

impl Clock for TickClock {
    fn now(&self) -> Timestamp {
        let v = self.0.get();
        self.0.set(v.saturating_add(1));
        Timestamp::from_nanos(v)
    }
}

fn tick(start: u64) -> TickClock {
    TickClock(Cell::new(start))
}

/// A private directory per test, removed when dropped.
struct Dir(PathBuf);

impl Dir {
    fn new(label: &str) -> Dir {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let dir =
            env::temp_dir().join(format!("audit-open-{label}-{}-{nanos}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        Dir(dir)
    }

    fn file(&self) -> PathBuf {
        self.0.join("chain.audit")
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn append<C: Clock>(
    chain: &mut Chain<Sha256Hasher, audit_trail::FileSink<std::io::BufWriter<fs::File>>, C>,
    n: usize,
) {
    for i in 0..n {
        let target = format!("item:{i}");
        let _id = chain
            .append(
                Actor::new("admin"),
                Action::new("item.update"),
                Target::new(&target),
                Outcome::Success,
            )
            .unwrap();
    }
    chain.sink_mut().sync().unwrap();
}

fn verify_all(path: &PathBuf) -> usize {
    let mut verifier = Verifier::new(Sha256Hasher::new());
    let mut count = 0;
    for record in FileReader::open(path).unwrap() {
        verifier.verify(&record.unwrap().as_record()).unwrap();
        count += 1;
    }
    count
}

#[test]
fn creates_then_resumes_at_the_tail() {
    let dir = Dir::new("resume");
    let path = dir.file();
    let (mut chain, report) = Chain::open_file(&path, Sha256Hasher::new(), tick(1)).unwrap();
    assert!(report.created());
    assert_eq!(report.records(), 0);
    append(&mut chain, 3);
    drop(chain);

    let (mut chain, report) = Chain::open_file(&path, Sha256Hasher::new(), tick(100)).unwrap();
    assert!(!report.created());
    assert_eq!(report.records(), 3);
    assert_eq!(chain.next_id().as_u64(), 3);
    assert_eq!(chain.last_timestamp().as_nanos(), 3);
    append(&mut chain, 2);
    drop(chain);
    assert_eq!(verify_all(&path), 5);
}

#[cfg(unix)]
#[test]
fn a_created_file_is_owner_only() {
    use std::os::unix::fs::PermissionsExt as _;

    let dir = Dir::new("mode");
    let path = dir.file();
    let (chain, _report) = Chain::open_file(&path, Sha256Hasher::new(), tick(1)).unwrap();
    drop(chain);
    let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);

    let other = dir.0.join("sink.audit");
    let sink = audit_trail::FileSink::open_or_create_private(&other).unwrap();
    drop(sink);
    let mode = fs::metadata(&other).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
}

#[test]
fn a_changed_record_is_tampering_not_truncation() {
    let dir = Dir::new("tamper");
    let path = dir.file();
    let (mut chain, _report) = Chain::open_file(&path, Sha256Hasher::new(), tick(1)).unwrap();
    append(&mut chain, 3);
    drop(chain);

    let mut bytes = fs::read(&path).unwrap();
    let position = bytes.windows(6).position(|w| w == b"item:1").unwrap();
    bytes[position + 5] = b'7';
    fs::write(&path, &bytes).unwrap();

    let error = Chain::open_file(&path, Sha256Hasher::new(), tick(10)).err();
    assert!(matches!(error, Some(Error::HashMismatch(_))), "{error:?}");
    // The repairing variant never cuts records that fail verification.
    let error = Chain::open_file_repairing_tail(&path, Sha256Hasher::new(), tick(10)).err();
    assert!(matches!(error, Some(Error::HashMismatch(_))), "{error:?}");
    assert_eq!(fs::read(&path).unwrap(), bytes);
}

#[test]
fn a_cut_last_record_is_reported_and_can_be_repaired_with_evidence_kept() {
    for cut in [1_usize, 3, 10] {
        let dir = Dir::new("truncated");
        let path = dir.file();
        let (mut chain, _report) = Chain::open_file(&path, Sha256Hasher::new(), tick(1)).unwrap();
        append(&mut chain, 3);
        drop(chain);
        let full = fs::read(&path).unwrap();
        let good_len = {
            // The length of the file with two records.
            let dir2 = Dir::new("reference");
            let (mut chain, _r) =
                Chain::open_file(dir2.file(), Sha256Hasher::new(), tick(1)).unwrap();
            append(&mut chain, 2);
            drop(chain);
            fs::metadata(dir2.file()).unwrap().len() as usize
        };
        // Keep the two first records and a part of the third.
        let keep = good_len + cut;
        assert!(keep < full.len());
        fs::write(&path, &full[..keep]).unwrap();

        let error = Chain::open_file(&path, Sha256Hasher::new(), tick(10)).err();
        assert_eq!(error, Some(Error::Truncated));
        assert_eq!(
            fs::read(&path).unwrap().len(),
            keep,
            "open_file changed the file"
        );

        let (mut chain, report) =
            Chain::open_file_repairing_tail(&path, Sha256Hasher::new(), tick(10)).unwrap();
        assert_eq!(report.records(), 2);
        let (bytes, kept) = report.cut().unwrap();
        assert_eq!(bytes as usize, cut);
        assert_eq!(fs::read(kept).unwrap(), full[good_len..keep].to_vec());
        append(&mut chain, 1);
        drop(chain);
        assert_eq!(verify_all(&path), 3);
    }
}

#[test]
fn a_corrupt_length_cannot_allocate_past_the_file() {
    let dir = Dir::new("length");
    let path = dir.file();
    let (mut chain, _report) = Chain::open_file(&path, Sha256Hasher::new(), tick(1)).unwrap();
    append(&mut chain, 1);
    drop(chain);
    let mut file = OpenOptions::new().append(true).open(&path).unwrap();
    file.write_all(&[0xFF, 0xFF, 0xFF, 0xF0, 1, 2, 3]).unwrap();
    drop(file);
    let error = Chain::open_file(&path, Sha256Hasher::new(), tick(10)).err();
    assert_eq!(error, Some(Error::Truncated));
}

#[test]
fn a_bad_header_is_invalid_format() {
    let dir = Dir::new("header");
    let path = dir.file();
    fs::write(&path, b"NOTAUDITxxxxxxxxxxxx").unwrap();
    let error = Chain::open_file(&path, Sha256Hasher::new(), tick(1)).err();
    assert_eq!(error, Some(Error::InvalidFormat));
}

#[test]
fn chain_flush_reaches_the_file() {
    let dir = Dir::new("flush");
    let path = dir.file();
    let (mut chain, _report) = Chain::open_file(&path, Sha256Hasher::new(), tick(1)).unwrap();
    let _id = chain
        .append(
            Actor::new("a"),
            Action::new("b"),
            Target::new("c"),
            Outcome::Success,
        )
        .unwrap();
    chain.flush().unwrap();
    assert_eq!(verify_all(&path), 1);
}

/// A wall clock that steps back by an hour after its first reading.
struct SteppingBack(Cell<u64>);

impl Clock for SteppingBack {
    fn now(&self) -> Timestamp {
        let t = self.0.get();
        self.0.set(t.saturating_sub(3_600_000_000_000));
        Timestamp::from_nanos(t)
    }
}

#[test]
fn a_monotonic_clock_keeps_the_chain_appendable_through_a_step_back() {
    let dir = Dir::new("clock");
    let path = dir.file();
    let start = 10_000_000_000_000_u64;

    // Without the adapter a step back stops the chain.
    let (mut chain, _r) =
        Chain::open_file(&path, Sha256Hasher::new(), SteppingBack(Cell::new(start))).unwrap();
    append(&mut chain, 1);
    let error = chain
        .append(
            Actor::new("a"),
            Action::new("b"),
            Target::new("c"),
            Outcome::Success,
        )
        .err();
    assert_eq!(error, Some(Error::NonMonotonicClock));
    let last = chain.last_timestamp();
    drop(chain);

    // With it, after advancing past the resumed tail, appends continue.
    let clock = MonotonicClock::new(SteppingBack(Cell::new(start - 1)));
    let (mut chain, report) = Chain::open_file(&path, Sha256Hasher::new(), clock).unwrap();
    assert_eq!(report.records(), 1);
    chain.clock().advance_past(chain.last_timestamp());
    let (_, _, clock) = {
        append(&mut chain, 3);
        chain.into_parts()
    };
    assert!(clock.now() > last);
    assert_eq!(verify_all(&path), 4);
}

#[test]
fn monotonic_clock_advance_past_moves_it_forward() {
    let clock = MonotonicClock::new(tick(5));
    clock.advance_past(Timestamp::from_nanos(1_000));
    assert_eq!(clock.now().as_nanos(), 1_001);
    assert_eq!(clock.now().as_nanos(), 1_002);
}
