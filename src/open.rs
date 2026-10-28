//! Opening a chain file: verify every record, then resume at the tail.

use std::fs::{File, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use crate::chain::Chain;
use crate::clock::Clock;
use crate::codec;
use crate::error::{Error, Result};
use crate::hash::Hasher;
use crate::sinks::FileSink;
use crate::verify::Verifier;

/// What [`Chain::open_file`] found in the file.
///
/// # Example
///
/// ```
/// # #[cfg(feature = "sha2")] {
/// use audit_trail::{Chain, Sha256Hasher, SystemClock};
///
/// let path = std::env::temp_dir().join(format!("audit-open-doc-{}.log", std::process::id()));
/// # let _ = std::fs::remove_file(&path);
/// let (chain, report) = Chain::open_file(&path, Sha256Hasher::new(), SystemClock::new())?;
/// assert!(report.created());
/// assert_eq!(report.records(), 0);
/// assert_eq!(chain.next_id().as_u64(), 0);
/// # drop(chain);
/// # let _ = std::fs::remove_file(&path);
/// # }
/// # Ok::<(), audit_trail::Error>(())
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenReport {
    records: u64,
    created: bool,
    cut: Option<(u64, PathBuf)>,
}

impl OpenReport {
    /// How many records were verified.
    #[must_use]
    pub const fn records(&self) -> u64 {
        self.records
    }

    /// Whether the file did not exist (or was empty) and was created.
    #[must_use]
    pub const fn created(&self) -> bool {
        self.created
    }

    /// When [`Chain::open_file_repairing_tail`] cut an incomplete last
    /// record: how many bytes were cut, and the file they were moved to.
    #[must_use]
    pub fn cut(&self) -> Option<(u64, &Path)> {
        self.cut
            .as_ref()
            .map(|(bytes, path)| (*bytes, path.as_path()))
    }
}

/// A chain appending to a buffered file.
type FileChain<H, C> = Chain<H, FileSink<BufWriter<File>>, C>;

/// How a scan of the file ended.
struct Scan<H: Hasher> {
    verifier: Verifier<H>,
    records: u64,
    /// The offset just after the last complete, verified record.
    good_end: u64,
}

impl<H, C> Chain<H, FileSink<BufWriter<File>>, C>
where
    H: Hasher,
    C: Clock,
{
    /// Open the chain file at `path`, verify every record in it, and
    /// return a chain that appends after the last one.
    ///
    /// A missing or empty file is created with the format header; on Unix
    /// a created file is owner-only (`0o600`). The hasher must be the one
    /// the chain was written with.
    ///
    /// A clock that can step back (a wall clock under NTP) should be a
    /// [`MonotonicClock`](crate::MonotonicClock), advanced past
    /// [`Chain::last_timestamp`] after opening.
    ///
    /// # Errors
    ///
    /// * [`Error::Truncated`] - the file ends inside a record: a crash
    ///   while writing, or a cut file. Nothing is changed;
    ///   [`Chain::open_file_repairing_tail`] can cut the incomplete record.
    /// * [`Error::HashMismatch`], [`Error::LinkMismatch`],
    ///   [`Error::IdMismatch`], [`Error::NonMonotonicClock`] - a record was
    ///   changed, removed, or reordered: the chain does not verify.
    /// * [`Error::InvalidFormat`] - the header or a record does not decode.
    /// * [`Error::Io`] - the file cannot be opened, read, or written.
    pub fn open_file(path: impl AsRef<Path>, hasher: H, clock: C) -> Result<(Self, OpenReport)> {
        open(path.as_ref(), hasher, clock, false)
    }

    /// As [`Chain::open_file`], but an incomplete last record is cut off
    /// instead of refused: the bytes after the last complete record are
    /// first copied to `<path>.cut-<offset>` (owner-only on Unix, synced),
    /// then removed from the chain file. Records that verify are never
    /// touched, and nothing is cut when verification fails.
    ///
    /// The bytes cannot be told apart from a record whose length was
    /// tampered with, which is why they are kept rather than deleted and
    /// why the caller should report [`OpenReport::cut`] prominently.
    ///
    /// # Errors
    ///
    /// As for [`Chain::open_file`], except [`Error::Truncated`].
    pub fn open_file_repairing_tail(
        path: impl AsRef<Path>,
        hasher: H,
        clock: C,
    ) -> Result<(Self, OpenReport)> {
        open(path.as_ref(), hasher, clock, true)
    }
}

fn open<H, C>(
    path: &Path,
    hasher: H,
    clock: C,
    repair: bool,
) -> Result<(FileChain<H, C>, OpenReport)>
where
    H: Hasher,
    C: Clock,
{
    let mut file = private_options()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
        .map_err(|_| Error::Io)?;
    let len = file.metadata().map_err(|_| Error::Io)?.len();
    if len == 0 {
        let mut header = Vec::with_capacity(codec::FILE_HEADER_LEN);
        codec::write_file_header(&mut header);
        file.write_all(&header).map_err(|_| Error::Io)?;
        file.sync_data().map_err(|_| Error::Io)?;
        let sink = FileSink::new(BufWriter::new(file));
        let report = OpenReport {
            records: 0,
            created: true,
            cut: None,
        };
        return Ok((Chain::new(hasher, sink, clock), report));
    }

    let scan = scan(&file, len, hasher)?;
    let mut cut = None;
    if scan.good_end < len {
        if !repair {
            return Err(Error::Truncated);
        }
        cut = Some(cut_tail(&mut file, path, scan.good_end, len)?);
    }
    let _end = file.seek(SeekFrom::End(0)).map_err(|_| Error::Io)?;

    let next_id = scan.verifier.next_id();
    let last_hash = scan.verifier.last_hash();
    let last_timestamp = scan.verifier.last_timestamp();
    let hasher = scan.verifier.into_hasher();
    let sink = FileSink::new(BufWriter::new(file));
    let chain = if scan.records == 0 {
        Chain::new(hasher, sink, clock)
    } else {
        Chain::resume(hasher, sink, clock, next_id, last_hash, last_timestamp)
    };
    let report = OpenReport {
        records: scan.records,
        created: false,
        cut,
    };
    Ok((chain, report))
}

/// Reads and verifies every complete record. Stops at the end of the file
/// or at an incomplete last record; fails on anything that does not verify.
fn scan<H: Hasher>(file: &File, len: u64, hasher: H) -> Result<Scan<H>> {
    let mut reader = BufReader::new(file);
    let _start = reader.seek(SeekFrom::Start(0)).map_err(|_| Error::Io)?;
    let header_len = codec::FILE_HEADER_LEN as u64;
    if len < header_len {
        return Err(Error::Truncated);
    }
    let mut header = [0u8; codec::FILE_HEADER_LEN];
    reader.read_exact(&mut header).map_err(|_| Error::Io)?;
    codec::verify_file_header(&header)?;

    let mut verifier = Verifier::new(hasher);
    let mut records = 0_u64;
    let mut offset = header_len;
    let mut scratch: Vec<u8> = Vec::with_capacity(256);
    loop {
        let remaining = len - offset;
        if remaining == 0 {
            break;
        }
        if remaining < 4 {
            // Part of a length prefix: an incomplete last record.
            break;
        }
        let mut len_buf = [0u8; 4];
        reader.read_exact(&mut len_buf).map_err(|_| Error::Io)?;
        let frame_len = 4 + u64::from(u32::from_be_bytes(len_buf));
        if frame_len > remaining {
            // The record claims more bytes than the file holds. Checked
            // before allocating, so a corrupt length cannot exhaust memory.
            break;
        }
        let frame = usize::try_from(frame_len).map_err(|_| Error::Capacity)?;
        scratch.clear();
        scratch.resize(frame, 0);
        scratch[0..4].copy_from_slice(&len_buf);
        reader
            .read_exact(&mut scratch[4..])
            .map_err(|_| Error::Io)?;
        let (record, consumed) = codec::decode_record(&scratch)?;
        if consumed != frame {
            return Err(Error::InvalidFormat);
        }
        verifier.verify(&record.as_record())?;
        records += 1;
        offset += frame_len;
    }
    Ok(Scan {
        verifier,
        records,
        good_end: offset,
    })
}

/// Copies `[good_end, len)` to `<path>.cut-<good_end>`, syncs it, then cuts
/// the chain file at `good_end`.
fn cut_tail(file: &mut File, path: &Path, good_end: u64, len: u64) -> Result<(u64, PathBuf)> {
    let mut tail = Vec::new();
    let _pos = file
        .seek(SeekFrom::Start(good_end))
        .map_err(|_| Error::Io)?;
    let _read = Read::by_ref(file)
        .take(len - good_end)
        .read_to_end(&mut tail)
        .map_err(|_| Error::Io)?;
    let mut name = path.as_os_str().to_owned();
    name.push(format!(".cut-{good_end}"));
    let cut_path = PathBuf::from(name);
    let mut kept = private_options()
        .write(true)
        .create_new(true)
        .open(&cut_path)
        .map_err(|_| Error::Io)?;
    kept.write_all(&tail).map_err(|_| Error::Io)?;
    kept.sync_all().map_err(|_| Error::Io)?;
    file.set_len(good_end).map_err(|_| Error::Io)?;
    file.sync_all().map_err(|_| Error::Io)?;
    Ok((len - good_end, cut_path))
}

/// Open options that create a file owner-only on Unix (`0o600`). Elsewhere
/// a new file inherits its directory's access control.
pub(crate) fn private_options() -> OpenOptions {
    #[cfg_attr(not(unix), allow(unused_mut))]
    let mut options = OpenOptions::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        let _same = options.mode(0o600);
    }
    options
}
