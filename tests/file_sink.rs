//! End-to-end FileSink + FileReader test.
//!
//! Writes a SHA-256-backed chain to a temp file, reads it back via
//! `FileReader`, replays it through a `Verifier`, and exercises
//! append-mode reopen.

#![cfg(all(feature = "sha2", feature = "std"))]

use std::cell::Cell;
use std::env;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::PathBuf;

use audit_trail::{
    Action, Actor, Chain, Clock, Error, FileReader, FileSink, Outcome, RecordId, Sha256Hasher,
    SinkError, Target, Timestamp, Verifier,
};

struct TickClock(Cell<u64>);

impl TickClock {
    fn new(start: u64) -> Self {
        Self(Cell::new(start))
    }
}

impl Clock for TickClock {
    fn now(&self) -> Timestamp {
        let v = self.0.get();
        self.0.set(v.saturating_add(1));
        Timestamp::from_nanos(v)
    }
}

/// Unique temp path per test (no `tempfile` dep yet).
fn temp_path(label: &str) -> PathBuf {
    let mut p = env::temp_dir();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    p.push(format!("audit-trail-{label}-{nanos}.log"));
    p
}

fn append_three(chain: &mut Chain<Sha256Hasher, FileSink<std::io::BufWriter<File>>, TickClock>) {
    chain
        .append(
            Actor::new("system"),
            Action::new("chain.init"),
            Target::new("chain:0"),
            Outcome::Success,
        )
        .expect("genesis");
    chain
        .append(
            Actor::new("user-1"),
            Action::new("user.login"),
            Target::new("session:abc"),
            Outcome::Success,
        )
        .expect("login");
    chain
        .append(
            Actor::new("user-1"),
            Action::new("record.delete"),
            Target::new("record:42"),
            Outcome::Denied,
        )
        .expect("delete");
}

#[test]
fn file_sink_round_trip_with_verifier() {
    let path = temp_path("round-trip");
    let _ = std::fs::remove_file(&path);

    let sink = FileSink::open_or_create(&path).expect("open new file");
    let mut chain = Chain::new(Sha256Hasher::new(), sink, TickClock::new(1));
    append_three(&mut chain);

    let (_, mut sink, _) = chain.into_parts();
    sink.flush().expect("flush");
    drop(sink);

    let reader = FileReader::open(&path).expect("open for read");
    let mut verifier = Verifier::new(Sha256Hasher::new());
    let mut count = 0;
    for record in reader {
        let r = record.expect("decode");
        verifier.verify(&r.as_record()).expect("verify");
        count += 1;
    }
    assert_eq!(count, 3);
    assert_eq!(verifier.next_id(), RecordId::from_u64(3));

    let _ = std::fs::remove_file(&path);
}

#[test]
fn file_sink_reopens_and_appends_after_restart() {
    let path = temp_path("reopen");
    let _ = std::fs::remove_file(&path);

    // First session: write two records.
    {
        let sink = FileSink::open_or_create(&path).expect("create");
        let mut chain = Chain::new(Sha256Hasher::new(), sink, TickClock::new(1));
        chain
            .append(
                Actor::new("a"),
                Action::new("x"),
                Target::new("t"),
                Outcome::Success,
            )
            .expect("r0");
        chain
            .append(
                Actor::new("a"),
                Action::new("y"),
                Target::new("u"),
                Outcome::Success,
            )
            .expect("r1");
        let (_, mut sink, _) = chain.into_parts();
        sink.flush().expect("flush");
    }

    // Capture the last record's hash + timestamp so the second session can
    // resume the chain cleanly.
    let (resume_id, resume_hash, resume_ts) = {
        let reader = FileReader::open(&path).expect("read");
        let records: Vec<_> = reader.map(|r| r.expect("decode")).collect();
        assert_eq!(records.len(), 2);
        (
            RecordId::from_u64(records[1].id.as_u64() + 1),
            records[1].hash,
            records[1].timestamp,
        )
    };

    // Second session: reopen and append a third record.
    {
        let sink = FileSink::open_or_create(&path).expect("reopen");
        let mut chain = Chain::resume(
            Sha256Hasher::new(),
            sink,
            TickClock::new(resume_ts.as_nanos() + 100),
            resume_id,
            resume_hash,
            resume_ts,
        );
        chain
            .append(
                Actor::new("a"),
                Action::new("z"),
                Target::new("v"),
                Outcome::Failure,
            )
            .expect("r2");
        let (_, mut sink, _) = chain.into_parts();
        sink.flush().expect("flush");
    }

    // Verify the full chain.
    let reader = FileReader::open(&path).expect("read final");
    let mut verifier = Verifier::new(Sha256Hasher::new());
    let mut count = 0;
    for record in reader {
        let r = record.expect("decode");
        verifier.verify(&r.as_record()).expect("verify");
        count += 1;
    }
    assert_eq!(count, 3);

    let _ = std::fs::remove_file(&path);
}

#[test]
fn file_reader_rejects_bad_header() {
    let path = temp_path("bad-header");
    let _ = std::fs::remove_file(&path);

    // Write a junk header.
    let mut f = File::create(&path).expect("create");
    f.write_all(b"NOTAUDIT\x00\x00\x00\x00\x00\x00\x00\x00")
        .expect("write");
    drop(f);

    let mut reader = FileReader::open(&path).expect("open");
    let err = reader
        .next()
        .expect("yielded something")
        .expect_err("bad header must surface");
    assert_eq!(err, Error::InvalidFormat);
    assert!(reader.next().is_none(), "iterator terminates after error");

    let _ = std::fs::remove_file(&path);
}

#[test]
fn file_reader_handles_truncated_tail() {
    let path = temp_path("truncated");
    let _ = std::fs::remove_file(&path);

    // Write a valid file then truncate mid-record.
    let sink = FileSink::open_or_create(&path).expect("create");
    let mut chain = Chain::new(Sha256Hasher::new(), sink, TickClock::new(1));
    chain
        .append(
            Actor::new("a"),
            Action::new("x"),
            Target::new("t"),
            Outcome::Success,
        )
        .expect("write");
    let (_, mut sink, _) = chain.into_parts();
    sink.flush().expect("flush");
    drop(sink);

    let full_len = std::fs::metadata(&path).expect("stat").len();
    assert!(full_len > 20);
    let truncated = OpenOptions::new().write(true).open(&path).expect("reopen");
    truncated.set_len(full_len - 5).expect("truncate");

    let mut reader = FileReader::open(&path).expect("open");
    let result = reader.next().expect("yielded something");
    assert!(matches!(result, Err(Error::Truncated)), "got {result:?}");

    let _ = std::fs::remove_file(&path);
}

#[test]
fn file_reader_reports_a_file_cut_inside_a_length_prefix() {
    for extra in 1..4_usize {
        let path = temp_path(&format!("cut-prefix-{extra}"));
        let _ = std::fs::remove_file(&path);
        let sink = FileSink::open_or_create(&path).expect("create");
        let mut chain = Chain::new(Sha256Hasher::new(), sink, TickClock::new(1));
        append_three(&mut chain);
        let (_, mut sink, _) = chain.into_parts();
        sink.flush().expect("flush");
        drop(sink);
        // The first bytes of a fourth record's length prefix.
        let mut file = OpenOptions::new().append(true).open(&path).expect("reopen");
        file.write_all(&[0, 0, 0][..extra]).expect("write");
        drop(file);

        let items: Vec<_> = FileReader::open(&path).expect("open").collect();
        assert_eq!(items.len(), 4, "three records and the error");
        assert!(items[..3].iter().all(Result::is_ok));
        assert_eq!(items[3], Err(Error::Truncated));
        let _ = std::fs::remove_file(&path);
    }
}

/// A writer that accepts `budget` bytes, then fails every write.
struct FailingAfter {
    written: Vec<u8>,
    budget: usize,
}

impl Write for FailingAfter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if self.written.len() >= self.budget {
            return Err(std::io::Error::other("disk full"));
        }
        let n = buf.len().min(self.budget - self.written.len());
        self.written.extend_from_slice(&buf[..n]);
        Ok(n)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn a_file_sink_refuses_to_write_after_a_torn_record() {
    let sink = FileSink::new(FailingAfter {
        written: Vec::new(),
        budget: 150,
    });
    let mut chain = Chain::new(Sha256Hasher::new(), sink, TickClock::new(1));
    let append = |chain: &mut Chain<_, _, _>| {
        chain.append(
            Actor::new("admin"),
            Action::new("item.update"),
            Target::new("item:1"),
            Outcome::Success,
        )
    };
    assert!(append(&mut chain).is_ok());
    // The second record only partly fits.
    assert_eq!(append(&mut chain), Err(Error::Sink(SinkError::Io)));
    // Nothing more is written behind the torn record: the sink refuses
    // before it reaches the writer (`Closed`, not the writer's `Io`).
    assert_eq!(append(&mut chain), Err(Error::Sink(SinkError::Closed)));
    assert_eq!(chain.flush(), Err(Error::Sink(SinkError::Closed)));
    assert!(chain.sink_mut().flush().is_err());
    assert_eq!(chain.next_id(), RecordId::from_u64(1));
    let (_, sink, _) = chain.into_parts();
    assert_eq!(sink.into_writer().written.len(), 150);
}

#[cfg(unix)]
#[test]
fn a_private_file_sink_does_not_follow_a_symbolic_link() {
    let target = temp_path("link-target");
    let link = temp_path("link");
    let _ = std::fs::remove_file(&target);
    let _ = std::fs::remove_file(&link);
    std::os::unix::fs::symlink(&target, &link).expect("symlink");
    assert!(FileSink::open_or_create_private(&link).is_err());
    assert!(!target.exists(), "the link's target was created");
    let _ = std::fs::remove_file(&link);
}
