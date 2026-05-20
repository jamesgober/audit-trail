//! SHA-256 [`Hasher`] backed by the [`sha2`] crate. Requires the `sha2`
//! feature.

use sha2::Digest as _;

use crate::hash::{Digest, HASH_LEN, Hasher};

/// SHA-256 [`Hasher`].
///
/// The most common production hasher for audit-trail. SHA-256 is a FIPS
/// 180-4 standard primitive, 32-byte output, widely accepted by HIPAA,
/// SOC 2, PCI-DSS, and other compliance frameworks.
///
/// # Example
///
/// ```
/// use audit_trail::{Digest, Hasher, Sha256Hasher};
///
/// let mut hasher = Sha256Hasher::new();
/// hasher.update(b"audit-trail");
/// let mut out = Digest::ZERO;
/// hasher.finalize(&mut out);
/// // SHA-256("audit-trail") = 4e9b…
/// assert_ne!(out, Digest::ZERO);
/// ```
#[derive(Clone, Default)]
pub struct Sha256Hasher(sha2::Sha256);

impl Sha256Hasher {
    /// Construct a fresh [`Sha256Hasher`].
    #[inline]
    pub fn new() -> Self {
        Self(sha2::Sha256::new())
    }
}

impl core::fmt::Debug for Sha256Hasher {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Sha256Hasher").finish_non_exhaustive()
    }
}

impl Hasher for Sha256Hasher {
    #[inline]
    fn reset(&mut self) {
        self.0 = sha2::Sha256::new();
    }

    #[inline]
    fn update(&mut self, bytes: &[u8]) {
        sha2::Digest::update(&mut self.0, bytes);
    }

    #[inline]
    fn finalize(&mut self, out: &mut Digest) {
        let result = self.0.finalize_reset();
        let mut bytes = [0u8; HASH_LEN];
        bytes.copy_from_slice(&result);
        *out = Digest::from_bytes(bytes);
    }
}
