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

/// Wall-clock time source backed by [`std::time::SystemTime`]. Requires
/// the `std` feature.
///
/// Most production deployments want this; it returns nanoseconds since
/// the Unix epoch using the host's system clock. The host clock is **not**
/// strictly monotonic — if the operator adjusts time backwards, the next
/// [`crate::Chain::append`] will return [`crate::Error::NonMonotonicClock`].
/// Deployments that need a strictly-monotonic source should wrap a
/// monotonic instant in a custom [`Clock`] instead.
///
/// On the unusual case that `SystemTime::now()` is before the Unix epoch,
/// this returns [`Timestamp::EPOCH`] (0). On the equally-unusual case
/// that the system clock exceeds `u64::MAX` nanoseconds past the epoch
/// (year ~2554 and later), the value saturates at `u64::MAX`.
///
/// # Example
///
/// ```
/// use audit_trail::{Clock, SystemClock};
///
/// let clock = SystemClock::new();
/// let t = clock.now();
/// assert!(t.as_nanos() > 0);
/// ```
#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
#[derive(Copy, Clone, Debug, Default)]
pub struct SystemClock;

#[cfg(feature = "std")]
impl SystemClock {
    /// Construct a fresh `SystemClock`.
    #[inline]
    pub const fn new() -> Self {
        Self
    }
}

#[cfg(feature = "std")]
impl Clock for SystemClock {
    fn now(&self) -> Timestamp {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX))
            .unwrap_or(0);
        Timestamp::from_nanos(nanos)
    }
}
