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

/// A [`Clock`] whose timestamps never go back: each call returns the inner
/// clock's time, or one nanosecond after the previous timestamp when the
/// inner clock stepped back (an NTP correction, a manual change).
///
/// [`Chain::append`](crate::Chain::append) refuses a timestamp that is not
/// strictly greater than the last one, so a wall clock that steps back
/// would stop the chain until the clock caught up. With this adapter the
/// chain keeps appending; timestamps stay strictly increasing and run one
/// nanosecond apart until the wall clock passes the last one again.
///
/// After resuming a chain, call [`MonotonicClock::advance_past`] with the
/// chain's last timestamp, so the first new record is after it even if
/// the wall clock is now behind.
///
/// `Sync`: the last timestamp is one atomic word.
///
/// # Example
///
/// ```
/// use core::cell::Cell;
/// use audit_trail::{Clock, MonotonicClock, Timestamp};
///
/// struct Steps(Cell<u64>);
/// impl Clock for Steps {
///     fn now(&self) -> Timestamp {
///         let t = self.0.get();
///         self.0.set(t.saturating_sub(10)); // runs backwards
///         Timestamp::from_nanos(t)
///     }
/// }
///
/// let clock = MonotonicClock::new(Steps(Cell::new(100)));
/// let a = clock.now();
/// let b = clock.now();
/// assert!(b > a);
/// assert_eq!(b.as_nanos(), 101);
/// ```
#[cfg(target_has_atomic = "64")]
#[derive(Debug, Default)]
pub struct MonotonicClock<C> {
    inner: C,
    last: core::sync::atomic::AtomicU64,
}

#[cfg(target_has_atomic = "64")]
impl<C> MonotonicClock<C> {
    /// Wrap `inner`.
    #[inline]
    pub const fn new(inner: C) -> Self {
        Self {
            inner,
            last: core::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Make every later timestamp greater than `timestamp` (for example a
    /// resumed chain's [`last_timestamp`](crate::Chain::last_timestamp)).
    #[inline]
    pub fn advance_past(&self, timestamp: Timestamp) {
        let _previous = self
            .last
            .fetch_max(timestamp.as_nanos(), core::sync::atomic::Ordering::AcqRel);
    }

    /// The wrapped clock.
    #[inline]
    pub const fn inner(&self) -> &C {
        &self.inner
    }
}

#[cfg(target_has_atomic = "64")]
impl<C: Clock> Clock for MonotonicClock<C> {
    fn now(&self) -> Timestamp {
        use core::sync::atomic::Ordering;

        let now = self.inner.now().as_nanos();
        let mut last = self.last.load(Ordering::Acquire);
        loop {
            let next = if now > last {
                now
            } else {
                last.saturating_add(1)
            };
            match self
                .last
                .compare_exchange_weak(last, next, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => return Timestamp::from_nanos(next),
                Err(actual) => last = actual,
            }
        }
    }
}
