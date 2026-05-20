//! File-backed chain example.
//!
//! Writes an audit log to a file in the system temp dir, then closes
//! the writer, reopens the file for reading via `FileReader`, and
//! replays every record through the `Verifier`. Demonstrates that a
//! chain written by one process can be verified by another.
//!
//! Run with:
//!
//! ```text
//! cargo run --example file_log --features sha2
//! ```

use std::env;
use std::path::PathBuf;

use audit_trail::{
    Action, Actor, Chain, FileReader, FileSink, Outcome, Sha256Hasher, SystemClock, Target,
    Verifier,
};

fn temp_log_path() -> PathBuf {
    let mut p = env::temp_dir();
    p.push("audit-trail-example.log");
    p
}

fn main() {
    let path = temp_log_path();
    let _ = std::fs::remove_file(&path);

    // --- Writer session ---
    {
        let sink = FileSink::open_or_create(&path).expect("open audit log");
        let mut chain = Chain::new(Sha256Hasher::new(), sink, SystemClock::new());

        let events = [
            ("system", "chain.init", "chain:0", Outcome::Success),
            ("user-1", "user.login", "session:a", Outcome::Success),
            ("user-1", "record.read", "record:42", Outcome::Success),
            ("user-1", "record.delete", "record:42", Outcome::Denied),
            ("user-1", "user.logout", "session:a", Outcome::Success),
        ];
        for (who, what, where_, result) in events {
            chain
                .append(
                    Actor::new(who),
                    Action::new(what),
                    Target::new(where_),
                    result,
                )
                .expect("append");
        }

        let (_, mut sink, _) = chain.into_parts();
        sink.flush().expect("flush");
        println!("Wrote {} ...", path.display());
    }

    // --- Reader / verifier session ---
    let mut verifier = Verifier::new(Sha256Hasher::new());
    let mut count = 0usize;
    for record in FileReader::open(&path).expect("open for read") {
        let r = record.expect("decode");
        verifier.verify(&r.as_record()).expect("chain must verify");
        count += 1;
    }

    println!("Verified {count} records from {}", path.display());
    let _ = std::fs::remove_file(&path);
}
