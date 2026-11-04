//! Opening a chain file: verify every record, then resume at the tail.

use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader, BufWriter, Read, Seek, SeekFrom, Write};
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
/// # let _ = std::fs::remove_file(path.with_extension("log.lock"));
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
    /// The offset just after the last complete, verified record (0 when
    /// even the header is incomplete).
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
    /// A missing or empty file is created with the format header, which is
    /// synced to disk together with its directory entry (on Unix). The
    /// hasher must be the one the chain was written with.
    ///
    /// The file must be private to its owner:
    ///
    /// * `path` must name a regular file, not a symbolic link. The link is
    ///   refused as the file is opened, not checked beforehand, so it
    ///   cannot be swapped in between.
    /// * On Unix a created file has mode `0o600`. An existing file that its
    ///   group or others can read is made owner-only; one they can *write*
    ///   is refused, because the chain cannot vouch for a file others could
    ///   have rewritten. Elsewhere the file inherits its directory's access
    ///   control.
    ///
    /// Only one chain may append to a file. When the crate is built with
    /// Rust 1.89 or later, the chain holds an exclusive lock on
    /// `<path>.lock` (created owner-only, never removed) until it is
    /// dropped, and a second `open_file` of the same path, in this process
    /// or another, fails with [`Error::Io`] while the first is open. Built
    /// with an older compiler, or on a file system without locks, the
    /// caller must keep to one writer. Either way a file that grows while
    /// it is being verified is refused.
    ///
    /// A clock that can step back (a wall clock under NTP) should be a
    /// [`MonotonicClock`](crate::MonotonicClock), advanced past
    /// [`Chain::last_timestamp`] after opening.
    ///
    /// Verification proves every record up to the end of the file. It
    /// cannot tell that records were removed *from the end*, or that the
    /// whole file was rewritten by someone able to recompute the hashes:
    /// compare [`Chain::next_id`] and [`Chain::last_hash`] with a copy kept
    /// elsewhere (see the crate documentation, "What a chain proves").
    ///
    /// # Errors
    ///
    /// * [`Error::Truncated`] - the file ends inside a record or inside the
    ///   header, or ends in zero bytes where a record should start: a crash
    ///   while writing, or a cut file. Nothing is changed;
    ///   [`Chain::open_file_repairing_tail`] can cut the incomplete record.
    /// * [`Error::HashMismatch`], [`Error::LinkMismatch`],
    ///   [`Error::IdMismatch`], [`Error::NonMonotonicClock`] - a record was
    ///   changed, removed, or reordered: the chain does not verify.
    /// * [`Error::InvalidFormat`] - the header or a record does not decode,
    ///   or a record's field contains the hash's separator byte.
    /// * [`Error::Io`] - the file cannot be opened, read, written or
    ///   synced; `path` is a symbolic link or not a regular file; others
    ///   can write the file; another chain holds the file's lock; or the
    ///   file grew while it was being verified.
    pub fn open_file(path: impl AsRef<Path>, hasher: H, clock: C) -> Result<(Self, OpenReport)> {
        open(path.as_ref(), hasher, clock, false)
    }

    /// As [`Chain::open_file`], but an incomplete last record is cut off
    /// instead of refused: the bytes after the last complete record are
    /// first copied to `<path>.cut-<offset>` (or `<path>.cut-<offset>.<n>`
    /// when that name is taken; owner-only on Unix, synced), then removed
    /// from the chain file. Records that verify are never touched, and
    /// nothing is cut when verification fails. A file cut inside its
    /// header is cut to nothing and given a fresh header.
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
    let lock = lock(path)?;
    let mut file = open_private(path)?;
    owner_only(&file)?;
    let len = file.metadata().map_err(|_| Error::Io)?.len();
    if len == 0 {
        write_header(&mut file)?;
        sync_parent(path).map_err(|_| Error::Io)?;
        let sink = FileSink::with_lock(BufWriter::new(file), lock);
        let report = OpenReport {
            records: 0,
            created: true,
            cut: None,
        };
        return Ok((Chain::new(hasher, sink, clock), report));
    }

    let scan = scan(&file, len, hasher)?;
    let mut cut = None;
    let mut end = len;
    if scan.good_end < len {
        if !repair {
            return Err(Error::Truncated);
        }
        cut = Some(cut_tail(&mut file, path, scan.good_end, len)?);
        end = scan.good_end;
        if end == 0 {
            write_header(&mut file)?;
            end = codec::FILE_HEADER_LEN as u64;
        }
    }
    // Bytes past what was verified were written by someone else while the
    // file was being read; appending after them would fork the chain.
    if file.seek(SeekFrom::End(0)).map_err(|_| Error::Io)? != end {
        return Err(Error::Io);
    }

    let next_id = scan.verifier.next_id();
    let last_hash = scan.verifier.last_hash();
    let last_timestamp = scan.verifier.last_timestamp();
    let hasher = scan.verifier.into_hasher();
    let sink = FileSink::with_lock(BufWriter::new(file), lock);
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

/// Writes the format header at the start of the file and syncs it.
fn write_header(file: &mut File) -> Result<()> {
    let mut header = Vec::with_capacity(codec::FILE_HEADER_LEN);
    codec::write_file_header(&mut header);
    let _start = file.seek(SeekFrom::Start(0)).map_err(|_| Error::Io)?;
    file.write_all(&header).map_err(|_| Error::Io)?;
    file.sync_data().map_err(|_| Error::Io)
}

/// Reads and verifies every complete record. Stops at the end of the file
/// or at an incomplete last record; fails on anything that does not verify.
///
/// Records are decoded in place from one reused buffer, so the scan does
/// not allocate per record. The buffer is as large as the largest record,
/// whose length is checked against the file's size before it is allocated.
fn scan<H: Hasher>(file: &File, len: u64, hasher: H) -> Result<Scan<H>> {
    let mut reader = BufReader::with_capacity(64 * 1024, file);
    let _start = reader.seek(SeekFrom::Start(0)).map_err(|_| Error::Io)?;
    let mut verifier = Verifier::new(hasher);
    let header_len = codec::FILE_HEADER_LEN as u64;
    let mut header = [0u8; codec::FILE_HEADER_LEN];
    if len < header_len {
        // A crash while the header was written can leave its start, or
        // zeros. Anything else is not a chain file.
        let part = header
            .get_mut(..usize::try_from(len).map_err(|_| Error::Capacity)?)
            .ok_or(Error::InvalidFormat)?;
        reader.read_exact(part).map_err(|_| Error::Io)?;
        if !is_partial_header(part) {
            return Err(Error::InvalidFormat);
        }
        return Ok(Scan {
            verifier,
            records: 0,
            good_end: 0,
        });
    }
    reader.read_exact(&mut header).map_err(|_| Error::Io)?;
    if header == [0u8; codec::FILE_HEADER_LEN] && rest_is_zero(&mut reader, len - header_len)? {
        // The file's size reached the disk but its bytes did not.
        return Ok(Scan {
            verifier,
            records: 0,
            good_end: 0,
        });
    }
    codec::verify_file_header(&header)?;

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
        if len_buf == [0u8; 4] {
            // No record has length zero. Zeros to the end of the file are
            // a last write whose size reached the disk but whose bytes did
            // not (a crash on a file system that allocates lazily): an
            // incomplete last record. Anything else after them is not.
            if rest_is_zero(&mut reader, remaining - 4)? {
                break;
            }
            return Err(Error::InvalidFormat);
        }
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
        let (record, consumed) = codec::decode_frame(&scratch)?;
        if consumed != frame {
            return Err(Error::InvalidFormat);
        }
        verifier.verify(&record)?;
        records += 1;
        offset += frame_len;
    }
    Ok(Scan {
        verifier,
        records,
        good_end: offset,
    })
}

/// Whether `bytes` (shorter than a header) is the start of a valid header,
/// or zeros: what a crash while creating the file can leave.
fn is_partial_header(bytes: &[u8]) -> bool {
    let mut expected = Vec::with_capacity(codec::FILE_HEADER_LEN);
    codec::write_file_header(&mut expected);
    expected.starts_with(bytes) || bytes.iter().all(|&b| b == 0)
}

/// Whether the next `count` bytes of `reader` are all zero.
fn rest_is_zero<R: Read>(reader: &mut R, count: u64) -> Result<bool> {
    let mut buf = [0u8; 4096];
    let mut left = count;
    while left > 0 {
        let want = usize::try_from(left.min(buf.len() as u64)).map_err(|_| Error::Capacity)?;
        let chunk = &mut buf[..want];
        reader.read_exact(chunk).map_err(|_| Error::Io)?;
        if chunk.iter().any(|&b| b != 0) {
            return Ok(false);
        }
        left -= want as u64;
    }
    Ok(true)
}

/// Copies `[good_end, len)` to a new owner-only `<path>.cut-<good_end>`,
/// syncs it and its directory entry, then cuts the chain file at
/// `good_end`. The copy streams: the tail is never held in memory.
fn cut_tail(file: &mut File, path: &Path, good_end: u64, len: u64) -> Result<(u64, PathBuf)> {
    let (mut kept, cut_path) = create_cut_file(path, good_end)?;
    let _pos = file
        .seek(SeekFrom::Start(good_end))
        .map_err(|_| Error::Io)?;
    let tail = len - good_end;
    let copied = io::copy(&mut Read::by_ref(file).take(tail), &mut kept).map_err(|_| Error::Io)?;
    if copied != tail {
        return Err(Error::Io);
    }
    kept.sync_all().map_err(|_| Error::Io)?;
    sync_parent(&cut_path).map_err(|_| Error::Io)?;
    file.set_len(good_end).map_err(|_| Error::Io)?;
    file.sync_all().map_err(|_| Error::Io)?;
    Ok((tail, cut_path))
}

/// Creates the file that keeps cut bytes. A name already taken (an earlier
/// cut at the same offset) gets a numbered suffix; an existing file is
/// never opened, so nothing kept before is overwritten.
fn create_cut_file(path: &Path, good_end: u64) -> Result<(File, PathBuf)> {
    for attempt in 0..1000_u32 {
        let mut name = path.as_os_str().to_owned();
        if attempt == 0 {
            name.push(format!(".cut-{good_end}"));
        } else {
            name.push(format!(".cut-{good_end}.{attempt}"));
        }
        let candidate = PathBuf::from(name);
        match private_options()
            .write(true)
            .create_new(true)
            .open(&candidate)
        {
            Ok(file) => return Ok((file, candidate)),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(_) => return Err(Error::Io),
        }
    }
    Err(Error::Io)
}

/// Takes the exclusive lock on `<path>.lock` that keeps a second chain from
/// appending to the same file. `None` when the file system has no locks.
///
/// The lock is on a separate file because on Windows a locked range cannot
/// be read through another handle, which would stop a `FileReader` from
/// reading the chain while it is open.
#[cfg(audit_trail_file_lock)]
// Above the MSRV, but compiled only when the build script found a compiler
// that has `File::try_lock` (1.89).
#[allow(clippy::incompatible_msrv)]
fn lock(path: &Path) -> Result<Option<File>> {
    let mut name = path.as_os_str().to_owned();
    name.push(".lock");
    let file = open_private(Path::new(&name))?;
    match file.try_lock() {
        Ok(()) => Ok(Some(file)),
        Err(fs::TryLockError::Error(e)) if e.kind() == io::ErrorKind::Unsupported => Ok(None),
        Err(_) => Err(Error::Io),
    }
}

/// Without `File::try_lock` (Rust before 1.89) there is no lock to take.
#[cfg(not(audit_trail_file_lock))]
#[allow(clippy::unnecessary_wraps)] // Same signature as the locking variant.
fn lock(_path: &Path) -> Result<Option<File>> {
    Ok(None)
}

/// Opens (creating if absent) a file for reading and writing with
/// [`private_options`], and refuses one that is not a regular file.
fn open_private(path: &Path) -> Result<File> {
    let file = private_options()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
        .map_err(|_| Error::Io)?;
    check_opened(&file, path).map_err(|_| Error::Io)?;
    Ok(file)
}

/// On Unix: refuses a file its group or others can write, and makes one
/// they can only read owner-only. The mode is read and changed on the open
/// handle (`fstat`, `fchmod`), so the file cannot be swapped in between.
#[cfg(unix)]
fn owner_only(file: &File) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;

    let mode = file.metadata().map_err(|_| Error::Io)?.permissions().mode();
    if mode & 0o022 != 0 {
        return Err(Error::Io);
    }
    if mode & 0o044 != 0 {
        file.set_permissions(fs::Permissions::from_mode(mode & 0o700))
            .map_err(|_| Error::Io)?;
    }
    Ok(())
}

/// Elsewhere the file keeps the access control it inherited.
#[cfg(not(unix))]
#[allow(clippy::unnecessary_wraps)] // Same signature as the Unix variant.
fn owner_only(_file: &File) -> Result<()> {
    Ok(())
}

/// Refuses an opened file that is not a regular file (a directory, a
/// FIFO, a device) or, outside Unix, a path that is a symbolic link. On
/// Unix `O_NOFOLLOW` already refused the link when the file was opened;
/// elsewhere the link is checked just after, which leaves a short window
/// (creating a link on Windows needs a privilege by default).
pub(crate) fn check_opened(file: &File, path: &Path) -> io::Result<()> {
    if !file.metadata()?.file_type().is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "not a regular file",
        ));
    }
    #[cfg(not(unix))]
    if fs::symlink_metadata(path)?.file_type().is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "a symbolic link",
        ));
    }
    #[cfg(unix)]
    let _unused = path;
    Ok(())
}

/// Syncs the directory holding `path`, so a file created in it survives a
/// power loss. Unix only: elsewhere a directory cannot be synced through
/// the standard library, and NTFS journals its metadata.
pub(crate) fn sync_parent(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        let parent = match path.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => parent,
            _ => Path::new("."),
        };
        File::open(parent)?.sync_all()?;
    }
    #[cfg(not(unix))]
    let _unused = path;
    Ok(())
}

/// Open options for the crate's private files. A created file is
/// owner-only on Unix (`0o600`), and a symbolic link at the path makes the
/// open fail (`O_NOFOLLOW`). Elsewhere a new file inherits its directory's
/// access control, and [`check_opened`] refuses a link after the open.
pub(crate) fn private_options() -> OpenOptions {
    #[cfg_attr(not(unix), allow(unused_mut))]
    let mut options = OpenOptions::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        let _same = options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    options
}
