//! Append-only file-backed [`Sink`]. Requires the `std` feature.

use alloc::vec::Vec;
use std::fs::{File, OpenOptions};
use std::io::{self, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::Path;

use crate::codec;
use crate::error::SinkError;
use crate::record::Record;
use crate::sink::Sink;

/// Append-only file-backed [`Sink`].
///
/// Wraps any `W: io::Write` and serialises records through the stable
/// [`crate::codec`]. The format header is written exactly once, by
/// [`FileSink::open_or_create`] when the target file is empty.
///
/// Writes are not auto-flushed. Call [`FileSink::flush`] (or wrap the
/// inner writer in a `BufWriter` and rely on `Drop`) at appropriate
/// checkpoints; a typical pattern is flushing after every append or
/// after every batch. [`FileSink::sync`] also puts the records on disk.
///
/// # After a write error
///
/// A failed write or flush may have left part of a record in the file,
/// and a record appended after it would sit behind bytes that do not
/// decode, where no repair can reach. So after the first I/O error the
/// sink refuses every later write, flush and sync: writes fail with
/// [`SinkError::Closed`] and the `io::Result` methods with an error of
/// kind [`io::ErrorKind::Other`]. Drop the chain and open the file again
/// (`Chain::open_file_repairing_tail` cuts a torn last record and keeps
/// its bytes).
pub struct FileSink<W: Write> {
    writer: W,
    scratch: Vec<u8>,
    failed: bool,
    /// The chain file's lock, held as long as the sink (see
    /// `Chain::open_file`). Declared last so it is released after the
    /// writer's final flush on drop.
    _lock: Option<File>,
}

impl FileSink<BufWriter<File>> {
    /// Open `path` for append-only audit writes, creating it if absent.
    ///
    /// On a freshly-created file this writes the format header and syncs
    /// it (with the directory entry, on Unix). On an existing file this
    /// validates the header and positions the writer at end-of-file. The
    /// underlying [`File`] is wrapped in a [`BufWriter`].
    ///
    /// The records already in the file are not verified, and nothing stops
    /// a second writer; `Chain::open_file` does both.
    ///
    /// # Errors
    ///
    /// Surface I/O errors from opening, validating, or seeking the file.
    /// A bad existing header is reported as
    /// [`io::ErrorKind::InvalidData`].
    pub fn open_or_create(path: impl AsRef<Path>) -> io::Result<Self> {
        Self::open_with(path.as_ref(), OpenOptions::new(), false)
    }

    /// As [`FileSink::open_or_create`], but a file it creates is
    /// owner-only on Unix (mode `0o600`); elsewhere a new file inherits
    /// its directory's access control. An existing file keeps its mode.
    /// `path` must be a regular file: a symbolic link is not followed.
    ///
    /// # Errors
    ///
    /// As for [`FileSink::open_or_create`]; also
    /// [`io::ErrorKind::InvalidInput`] when `path` is not a regular file
    /// and, on Unix, the operating system's error when it is a symbolic
    /// link.
    pub fn open_or_create_private(path: impl AsRef<Path>) -> io::Result<Self> {
        Self::open_with(path.as_ref(), crate::open::private_options(), true)
    }

    /// Flush buffered records and sync the file's data to disk
    /// (`File::sync_data`): when this returns, every record appended so far
    /// survives a power loss.
    ///
    /// # Errors
    ///
    /// Surfaces the flush or sync I/O error verbatim, and refuses (see
    /// "After a write error") once a write, flush or sync has failed.
    pub fn sync(&mut self) -> io::Result<()> {
        self.usable()?;
        let synced = self
            .writer
            .flush()
            .and_then(|()| self.writer.get_ref().sync_data());
        self.note(synced)
    }

    fn open_with(path: &Path, mut options: OpenOptions, private: bool) -> io::Result<Self> {
        let mut file = options
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)?;
        if private {
            crate::open::check_opened(&file, path)?;
        }

        let len = file.seek(SeekFrom::End(0))?;
        if len == 0 {
            // Brand-new file: write the format header and make it, and the
            // file's name, durable before any record depends on them.
            let _ = file.seek(SeekFrom::Start(0))?;
            let mut header = Vec::with_capacity(codec::FILE_HEADER_LEN);
            codec::write_file_header(&mut header);
            file.write_all(&header)?;
            file.sync_data()?;
            crate::open::sync_parent(path)?;
            let _ = file.seek(SeekFrom::End(0))?;
        } else {
            // Existing file: validate the header.
            let _ = file.seek(SeekFrom::Start(0))?;
            let mut header = [0u8; codec::FILE_HEADER_LEN];
            file.read_exact(&mut header)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "missing audit header"))?;
            codec::verify_file_header(&header)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid audit header"))?;
            let _ = file.seek(SeekFrom::End(0))?;
        }

        Ok(Self::new(BufWriter::new(file)))
    }
}

impl<W: Write> FileSink<W> {
    /// Wrap an existing writer that is already positioned correctly
    /// (header already written, ready to append records).
    ///
    /// Most callers want [`FileSink::open_or_create`] instead.
    #[inline]
    pub fn new(writer: W) -> Self {
        Self::with_lock(writer, None)
    }

    /// As [`FileSink::new`], holding `lock` (the chain file's lock) for as
    /// long as the sink lives.
    pub(crate) fn with_lock(writer: W, lock: Option<File>) -> Self {
        Self {
            writer,
            scratch: Vec::with_capacity(256),
            failed: false,
            _lock: lock,
        }
    }

    /// Flush the underlying writer.
    ///
    /// # Errors
    ///
    /// Surfaces the writer's I/O error verbatim, and refuses (see "After a
    /// write error") once a write, flush or sync has failed.
    #[inline]
    pub fn flush(&mut self) -> io::Result<()> {
        self.usable()?;
        let flushed = self.writer.flush();
        self.note(flushed)
    }

    /// Consume the sink and return the underlying writer.
    #[inline]
    pub fn into_writer(self) -> W {
        self.writer
    }

    fn usable(&self) -> io::Result<()> {
        if self.failed {
            Err(io::Error::other(
                "an earlier audit write failed; open the chain again",
            ))
        } else {
            Ok(())
        }
    }

    /// Remembers a failure, so nothing is written after a torn record.
    fn note(&mut self, result: io::Result<()>) -> io::Result<()> {
        if result.is_err() {
            self.failed = true;
        }
        result
    }
}

impl<W: Write> Sink for FileSink<W> {
    fn write(&mut self, record: &Record<'_>) -> core::result::Result<(), SinkError> {
        if self.failed {
            return Err(SinkError::Closed);
        }
        self.scratch.clear();
        codec::encode_record(record, &mut self.scratch).map_err(|_| SinkError::Other)?;
        let written = self.writer.write_all(&self.scratch);
        self.note(written).map_err(|_| SinkError::Io)
    }

    fn flush(&mut self) -> core::result::Result<(), SinkError> {
        if self.failed {
            return Err(SinkError::Closed);
        }
        let flushed = self.writer.flush();
        self.note(flushed).map_err(|_| SinkError::Io)
    }
}
