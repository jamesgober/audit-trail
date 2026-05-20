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
/// checkpoints — a typical pattern is flushing after every append or
/// after every batch.
pub struct FileSink<W: Write> {
    writer: W,
    scratch: Vec<u8>,
}

impl FileSink<BufWriter<File>> {
    /// Open `path` for append-only audit writes, creating it if absent.
    ///
    /// On a freshly-created file this writes the format header. On an
    /// existing file this validates the header and positions the writer
    /// at end-of-file. The underlying [`File`] is wrapped in a
    /// [`BufWriter`].
    ///
    /// # Errors
    ///
    /// Surface I/O errors from opening, validating, or seeking the file.
    /// A bad existing header is reported as
    /// [`io::ErrorKind::InvalidData`].
    pub fn open_or_create(path: impl AsRef<Path>) -> io::Result<Self> {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)?;

        let len = file.seek(SeekFrom::End(0))?;
        if len == 0 {
            // Brand-new file — write the format header.
            let _ = file.seek(SeekFrom::Start(0))?;
            let mut header = Vec::with_capacity(codec::FILE_HEADER_LEN);
            codec::write_file_header(&mut header);
            file.write_all(&header)?;
            let _ = file.seek(SeekFrom::End(0))?;
        } else {
            // Existing file — validate the header.
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
        Self {
            writer,
            scratch: Vec::with_capacity(256),
        }
    }

    /// Flush the underlying writer.
    ///
    /// # Errors
    ///
    /// Surfaces the writer's I/O error verbatim.
    #[inline]
    pub fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }

    /// Consume the sink and return the underlying writer.
    #[inline]
    pub fn into_writer(self) -> W {
        self.writer
    }
}

impl<W: Write> Sink for FileSink<W> {
    fn write(&mut self, record: &Record<'_>) -> core::result::Result<(), SinkError> {
        self.scratch.clear();
        codec::encode_record(record, &mut self.scratch).map_err(|_| SinkError::Other)?;
        self.writer
            .write_all(&self.scratch)
            .map_err(|_| SinkError::Io)?;
        Ok(())
    }
}
