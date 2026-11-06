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
///
/// A file that ends inside a record, including inside its 4-byte length
/// prefix, yields [`Error::Truncated`] as its last item. Memory use is
/// bounded by the largest record actually present, not by what a length
/// prefix claims.
///
/// The reader decodes; it does not verify. Replay the records through a
/// [`crate::Verifier`], or open the file with `Chain::open_file`, to prove
/// the chain.
pub struct FileReader<R: Read> {
    reader: R,
    state: State,
    /// Reusable frame buffer. Resized as needed; never shrunk.
    scratch: Vec<u8>,
}

enum State {
    /// Header not yet validated.
    Fresh,
    /// Header validated successfully - reading records.
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
        match read_up_to(&mut self.reader, &mut len_buf) {
            Ok(0) => return None,
            Ok(4) => {}
            // The file ends inside a length prefix: a cut last record.
            Ok(_) => return Some(Err(Error::Truncated)),
            Err(_) => return Some(Err(Error::Io)),
        }
        let body_len = u64::from(u32::from_be_bytes(len_buf));
        self.scratch.clear();
        self.scratch.extend_from_slice(&len_buf);
        // The buffer grows with the bytes actually read, never to the
        // claimed length up front: a corrupt or hostile prefix claiming
        // 4 GiB costs what the file really holds.
        match Read::by_ref(&mut self.reader)
            .take(body_len)
            .read_to_end(&mut self.scratch)
        {
            Ok(read) if read as u64 == body_len => {}
            Ok(_) => return Some(Err(Error::Truncated)),
            Err(_) => return Some(Err(Error::Io)),
        }
        match codec::decode_record(&self.scratch) {
            Ok((record, consumed)) if consumed == self.scratch.len() => Some(Ok(record)),
            Ok(_) => Some(Err(Error::InvalidFormat)),
            Err(e) => Some(Err(e)),
        }
    }
}

/// Reads until `buf` is full or the reader ends; returns how many bytes
/// were read (0 at a clean end).
fn read_up_to<R: Read>(reader: &mut R, buf: &mut [u8]) -> io::Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match reader.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(filled)
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
