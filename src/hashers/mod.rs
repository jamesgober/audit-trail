//! Reference [`Hasher`] implementations behind feature flags.
//!
//! Each implementation is gated on the matching crate-level feature:
//!
//! | Type                  | Feature flag | Backing crate |
//! |-----------------------|--------------|---------------|
//! | [`Sha256Hasher`]      | `sha2`       | [`sha2`]      |
//!
//! [`Hasher`]: crate::Hasher

#[cfg(feature = "sha2")]
mod sha256;

#[cfg(feature = "sha2")]
pub use sha256::Sha256Hasher;
