//! Streaming reader for audit log files. Requires the `std` feature.

use std::fs::File;
use std::io::{self, BufReader, Read};
use std::path::Path;

use crate::codec;
use crate::error::{Error, Result};
use crate::owned::OwnedRecord;

/// Iterator that yields [`OwnedRecord`] values decoded from an audit log
/// produced by [`crate::FileSink`].
///
/// The format header is validated lazily on the first `next()` call. On
/// header failure the iterator yields `Some(Err(...))` once and then
/// `None` on every subsequent call.
pub struct FileReader<R: Read> {
    reader: R,
    state: State,
    /// Reusable frame buffer. Resized as needed; never shrunk.
    scratch: Vec<u8>,
}

enum State {
    /// Header not yet validated.
    Fresh,
    /// Header validated successfully — reading records.
    Reading,
    /// Iteration is terminated (either by EOF or a previous error).
    Done,
}

impl FileReader<BufReader<File>> {
    /// Open `path` for reading. The header is not validated until the
    /// first record is requested via `next()`.
    ///
    /// # Errors
    ///
    /// Surfaces I/O errors from opening the file.
    pub fn open(path: impl AsRef<Path>) -> io::Result<Self> {
        let file = File::open(path)?;
        Ok(Self::new(BufReader::new(file)))
    }
}

impl<R: Read> FileReader<R> {
    /// Wrap an existing reader positioned at the start of an audit log
    /// (i.e. at the format header).
    #[inline]
    pub fn new(reader: R) -> Self {
        Self {
            reader,
            state: State::Fresh,
            scratch: Vec::with_capacity(256),
        }
    }

    /// Consume the iterator and return the underlying reader.
    #[inline]
    pub fn into_reader(self) -> R {
        self.reader
    }

    fn read_header(&mut self) -> Result<()> {
        let mut header = [0u8; codec::FILE_HEADER_LEN];
        match self.reader.read_exact(&mut header) {
            Ok(()) => codec::verify_file_header(&header),
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => Err(Error::Truncated),
            Err(_) => Err(Error::Io),
        }
    }

    fn read_record(&mut self) -> Option<Result<OwnedRecord>> {
        let mut len_buf = [0u8; 4];
        match self.reader.read_exact(&mut len_buf) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return None,
            Err(_) => return Some(Err(Error::Io)),
        }
        let body_len = u32::from_be_bytes(len_buf) as usize;
        let frame_len = 4 + body_len;
        self.scratch.clear();
        self.scratch.resize(frame_len, 0);
        self.scratch[0..4].copy_from_slice(&len_buf);
        if let Err(e) = self.reader.read_exact(&mut self.scratch[4..]) {
            return Some(Err(match e.kind() {
                io::ErrorKind::UnexpectedEof => Error::Truncated,
                _ => Error::Io,
            }));
        }
        match codec::decode_record(&self.scratch) {
            Ok((record, consumed)) if consumed == frame_len => Some(Ok(record)),
            Ok(_) => Some(Err(Error::InvalidFormat)),
            Err(e) => Some(Err(e)),
        }
    }
}

impl<R: Read> Iterator for FileReader<R> {
    type Item = Result<OwnedRecord>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            match self.state {
                State::Fresh => match self.read_header() {
                    Ok(()) => self.state = State::Reading,
                    Err(e) => {
                        self.state = State::Done;
                        return Some(Err(e));
                    }
                },
                State::Reading => match self.read_record() {
                    None => {
                        self.state = State::Done;
                        return None;
                    }
                    Some(Err(e)) => {
                        self.state = State::Done;
                        return Some(Err(e));
                    }
                    Some(Ok(record)) => return Some(Ok(record)),
                },
                State::Done => return None,
            }
        }
    }
}
