//! BLAKE3 [`Hasher`] backed by the [`blake3`] crate. Requires the `blake3`
//! feature.

use crate::hash::{Digest, HASH_LEN, Hasher};

/// BLAKE3 [`Hasher`].
///
/// Faster than SHA-256 on most modern hardware and produces a 32-byte
/// output that drops in wherever [`crate::Sha256Hasher`] would. Useful
/// when throughput matters more than the FIPS pedigree of SHA-256.
///
/// # Example
///
/// ```
/// use audit_trail::{Blake3Hasher, Digest, Hasher};
///
/// let mut hasher = Blake3Hasher::new();
/// hasher.update(b"audit-trail");
/// let mut out = Digest::ZERO;
/// hasher.finalize(&mut out);
/// assert_ne!(out, Digest::ZERO);
/// ```
#[derive(Clone, Default)]
pub struct Blake3Hasher(blake3::Hasher);

impl Blake3Hasher {
    /// Construct a fresh [`Blake3Hasher`].
    #[inline]
    pub fn new() -> Self {
        Self(blake3::Hasher::new())
    }
}

impl core::fmt::Debug for Blake3Hasher {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Blake3Hasher").finish_non_exhaustive()
    }
}

impl Hasher for Blake3Hasher {
    #[inline]
    fn reset(&mut self) {
        let _ = self.0.reset();
    }

    #[inline]
    fn update(&mut self, bytes: &[u8]) {
        let _ = self.0.update(bytes);
    }

    #[inline]
    fn finalize(&mut self, out: &mut Digest) {
        let hash = self.0.finalize();
        let bytes: [u8; HASH_LEN] = *hash.as_bytes();
        *out = Digest::from_bytes(bytes);
    }
}
