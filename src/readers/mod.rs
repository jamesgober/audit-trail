//! Streaming readers for persisted audit logs.
//!
//! - [`FileReader`] — iterator over records read from a file, requires
//!   `std`.

#[cfg(feature = "std")]
mod file;

#[cfg(feature = "std")]
pub use file::FileReader;
