//! Time source and [`Timestamp`] type.

/// A timestamp expressed as nanoseconds since the Unix epoch.
///
/// Stored as a `u64`, so the representable range extends well beyond the
/// 22nd century. Operations are saturating to avoid panics on overflow.
///
/// # Example
///
/// ```
/// use audit_trail::Timestamp;
///
/// let t = Timestamp::from_nanos(1_700_000_000_000_000_000);
/// assert_eq!(t.as_nanos(), 1_700_000_000_000_000_000);
/// ```
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Timestamp(u64);

impl Timestamp {
    /// The Unix epoch (1970-01-01T00:00:00Z), expressed as nanoseconds.
    pub const EPOCH: Self = Self(0);

    /// Construct a timestamp from nanoseconds since the Unix epoch.
    #[inline]
    pub const fn from_nanos(nanos: u64) -> Self {
        Self(nanos)
    }

    /// Nanoseconds since the Unix epoch.
    #[inline]
    pub const fn as_nanos(self) -> u64 {
        self.0
    }
}

/// Pluggable time source for the audit chain.
///
/// Implementations are expected to be monotonic with respect to successive
/// calls. The chain enforces monotonicity at append time and returns
/// [`crate::Error::NonMonotonicClock`] if a regression is observed.
///
/// # Example
///
/// ```
/// use audit_trail::{Clock, Timestamp};
///
/// /// A fixed clock useful for testing.
/// struct FixedClock(Timestamp);
///
/// impl Clock for FixedClock {
///     fn now(&self) -> Timestamp { self.0 }
/// }
///
/// let clock = FixedClock(Timestamp::from_nanos(42));
/// assert_eq!(clock.now().as_nanos(), 42);
/// ```
pub trait Clock {
    /// Return the current timestamp.
    fn now(&self) -> Timestamp;
}
