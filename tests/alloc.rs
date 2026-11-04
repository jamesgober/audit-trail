//! Heap use, counted with a global allocator: allocations per appended
//! record, per record verified on open, and the memory a hostile length
//! prefix can make a reader reserve.

#![cfg(all(feature = "sha2", feature = "std"))]

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;

use audit_trail::{
    Action, Actor, Chain, Clock, Error, FileReader, Outcome, Sha256Hasher, Target, Timestamp,
};

/// Counts allocations and the largest single request, per thread, so the
/// tests in this file can run in parallel.
struct Counting;

thread_local! {
    static ALLOCATIONS: Cell<usize> = const { Cell::new(0) };
    static LARGEST: Cell<usize> = const { Cell::new(0) };
}

fn note(size: usize) {
    // `try_with`: the thread-local may already be gone while a thread exits.
    let _ = ALLOCATIONS.try_with(|count| count.set(count.get() + 1));
    let _ = LARGEST.try_with(|largest| largest.set(largest.get().max(size)));
}

// SAFETY: every call is forwarded unchanged to the system allocator; the
// counters are plain thread-local cells that never allocate.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        note(layout.size());
        // SAFETY: the caller upholds `GlobalAlloc::alloc`'s contract.
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        note(layout.size());
        // SAFETY: as for `alloc`.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: `ptr` came from this allocator with `layout`.
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        note(new_size);
        // SAFETY: as for `dealloc`; `new_size` is the caller's request.
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

fn counted<T>(f: impl FnOnce() -> T) -> (T, usize, usize) {
    ALLOCATIONS.with(|c| c.set(0));
    LARGEST.with(|c| c.set(0));
    let out = f();
    (out, ALLOCATIONS.with(Cell::get), LARGEST.with(Cell::get))
}

struct TickClock(Cell<u64>);

impl Clock for TickClock {
    fn now(&self) -> Timestamp {
        let v = self.0.get();
        self.0.set(v.saturating_add(1));
        Timestamp::from_nanos(v)
    }
}

fn dir(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "audit-alloc-{label}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

const RECORDS: usize = 1_000;

fn write_chain(path: &PathBuf) {
    let (mut chain, _report) =
        Chain::open_file(path, Sha256Hasher::new(), TickClock(Cell::new(1))).unwrap();
    let targets: Vec<String> = (0..RECORDS).map(|i| format!("user:{i}")).collect();
    // Warm up the sink's scratch buffer and the `BufWriter`.
    let _ = chain
        .append(
            Actor::new("admin:42"),
            Action::new("user.update"),
            Target::new("warm-up"),
            Outcome::Success,
        )
        .unwrap();
    let ((), allocations, _) = counted(|| {
        for target in &targets {
            let _ = chain
                .append(
                    Actor::new("admin:42"),
                    Action::new("user.update"),
                    Target::new(target),
                    Outcome::Success,
                )
                .unwrap();
        }
    });
    assert_eq!(allocations, 0, "append allocated");
    chain.sink_mut().sync().unwrap();
}

#[test]
fn appending_to_a_file_does_not_allocate() {
    let dir = dir("append");
    write_chain(&dir.join("chain.audit"));
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn opening_a_chain_allocates_a_fixed_amount_not_per_record() {
    let dir = dir("open");
    let path = dir.join("chain.audit");
    write_chain(&path);
    let (opened, allocations, _) =
        counted(|| Chain::open_file(&path, Sha256Hasher::new(), TickClock(Cell::new(1))));
    let (chain, report) = opened.unwrap();
    assert_eq!(report.records(), RECORDS as u64 + 1);
    drop(chain);
    // Buffers for the reader, the writer and the scratch frame; not one
    // per record.
    assert!(allocations < 32, "{allocations} allocations for open_file");
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn a_hostile_length_prefix_does_not_make_the_reader_reserve_it() {
    let dir = dir("hostile");
    let path = dir.join("chain.audit");
    write_chain(&path);
    // A frame that claims 4 GiB, followed by a few bytes.
    let mut file = OpenOptions::new().append(true).open(&path).unwrap();
    file.write_all(&[0xff, 0xff, 0xff, 0xff, 1, 2, 3, 4])
        .unwrap();
    drop(file);

    let (last, _, largest) = counted(|| FileReader::open(&path).unwrap().last());
    assert_eq!(last, Some(Err(Error::Truncated)));
    assert!(largest < 1 << 20, "the reader reserved {largest} bytes");
    let _ = fs::remove_dir_all(&dir);
}
