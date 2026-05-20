//! Reference [`Sink`] implementations.
//!
//! - [`MemorySink`] — in-memory, requires `alloc`.
//! - [`FileSink`] — append-only file writer, requires `std`.
//!
//! [`Sink`]: crate::Sink

mod memory;

#[cfg(feature = "std")]
mod file;

pub use memory::MemorySink;

#[cfg(feature = "std")]
pub use file::FileSink;
