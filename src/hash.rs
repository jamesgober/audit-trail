//! Hash digest and pluggable [`Hasher`] trait.
//!
//! `audit-trail` does not bundle a concrete hash function. Callers wire in an
//! implementation of [`Hasher`] backed by SHA-256, BLAKE3, SHA3-256, or any
//! other collision-resistant 32-byte hash. The trait is hot-path friendly:
//! no allocations, no boxed trait objects, no `dyn`.

use core::fmt;

/// Size, in bytes, of a hash output produced by a [`Hasher`].
///
/// Fixed at 32 bytes to cover the common cryptographic primitives
/// (SHA-256, BLAKE3, SHA3-256, KangarooTwelve-256).
pub const HASH_LEN: usize = 32;

/// Fixed-size hash output.
///
/// Used as the `prev_hash` and `hash` fields on every [`crate::Record`].
///
/// # Example
///
/// ```
/// use audit_trail::Digest;
///
/// let zero = Digest::ZERO;
/// assert_eq!(zero.as_bytes(), &[0u8; 32]);
/// ```
#[derive(Copy, Clone, PartialEq, Eq, Hash)]
pub struct Digest([u8; HASH_LEN]);

impl Digest {
    /// All-zero digest. Used as the `prev_hash` of the genesis record.
    pub const ZERO: Self = Self([0u8; HASH_LEN]);

    /// Construct a digest from raw bytes.
    ///
    /// # Example
    ///
    /// ```
    /// use audit_trail::Digest;
    /// let d = Digest::from_bytes([1u8; 32]);
    /// assert_eq!(d.as_bytes()[0], 1);
    /// ```
    #[inline]
    pub const fn from_bytes(bytes: [u8; HASH_LEN]) -> Self {
        Self(bytes)
    }

    /// Borrow the underlying bytes.
    #[inline]
    pub const fn as_bytes(&self) -> &[u8; HASH_LEN] {
        &self.0
    }

    /// Consume the digest and return the underlying bytes.
    #[inline]
    pub const fn into_bytes(self) -> [u8; HASH_LEN] {
        self.0
    }
}

impl Default for Digest {
    #[inline]
    fn default() -> Self {
        Self::ZERO
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Digest(")?;
        for byte in &self.0 {
            write!(f, "{byte:02x}")?;
        }
        f.write_str(")")
    }
}

impl fmt::LowerHex for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl AsRef<[u8]> for Digest {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Pluggable hash function used to chain audit records.
///
/// Implementations must be deterministic and collision-resistant. A typical
/// adapter wraps a `Sha256`, `Blake3`, or `Sha3_256` from an external crate.
///
/// The trait is stateful: callers invoke [`reset`](Hasher::reset) at the
/// start of each record, [`update`](Hasher::update) with field bytes, then
/// [`finalize`](Hasher::finalize) to write the output digest. Implementations
/// may reuse internal buffers across calls to avoid heap allocation.
///
/// # Example
///
/// ```
/// use audit_trail::{Digest, Hasher, HASH_LEN};
///
/// /// A trivially-insecure XOR "hasher" for demonstration only.
/// struct XorHasher([u8; HASH_LEN]);
///
/// impl Hasher for XorHasher {
///     fn reset(&mut self) { self.0 = [0u8; HASH_LEN]; }
///     fn update(&mut self, bytes: &[u8]) {
///         for (i, b) in bytes.iter().enumerate() {
///             self.0[i % HASH_LEN] ^= *b;
///         }
///     }
///     fn finalize(&mut self, out: &mut Digest) {
///         *out = Digest::from_bytes(self.0);
///     }
/// }
/// ```
pub trait Hasher {
    /// Reset the hasher to its initial state.
    fn reset(&mut self);

    /// Absorb a byte slice into the hash state.
    fn update(&mut self, bytes: &[u8]);

    /// Finalize the hash and write the result into `out`.
    ///
    /// After finalization the hasher is left in an unspecified state and
    /// must be [`reset`](Hasher::reset) before being used again.
    fn finalize(&mut self, out: &mut Digest);
}
