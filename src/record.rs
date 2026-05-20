//! The audit [`Record`] and its component types.
//!
//! A record captures the canonical "who / what / when / where / result" tuple
//! plus the chain linkage (`prev_hash`, `hash`). Records are borrowed: their
//! string fields hold `&str` references rather than owning allocations, so the
//! hot append path costs nothing on the heap.

use crate::clock::Timestamp;
use crate::hash::Digest;

/// Monotonically-increasing identifier for an audit record.
///
/// Ids start at `0` for the genesis record and increment by one for every
/// successful append.
///
/// # Example
///
/// ```
/// use audit_trail::RecordId;
///
/// let id = RecordId::from_u64(7);
/// assert_eq!(id.as_u64(), 7);
/// ```
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct RecordId(u64);

impl RecordId {
    /// The first identifier produced by a fresh chain.
    pub const GENESIS: Self = Self(0);

    /// Wrap a raw `u64` as a [`RecordId`].
    #[inline]
    pub const fn from_u64(value: u64) -> Self {
        Self(value)
    }

    /// Return the underlying `u64`.
    #[inline]
    pub const fn as_u64(self) -> u64 {
        self.0
    }
}

/// The subject performing an audited action (the "who").
///
/// Typically a user id, service principal, or session identifier.
///
/// # Example
///
/// ```
/// use audit_trail::Actor;
///
/// let actor = Actor::new("user-42");
/// assert_eq!(actor.as_str(), "user-42");
/// ```
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct Actor<'a>(&'a str);

impl<'a> Actor<'a> {
    /// Wrap a string slice as an [`Actor`].
    #[inline]
    pub const fn new(value: &'a str) -> Self {
        Self(value)
    }

    /// Borrow the underlying string slice.
    #[inline]
    pub const fn as_str(&self) -> &'a str {
        self.0
    }
}

/// The verb of an audited event (the "what").
///
/// Conventionally a dotted action name such as `"user.login"` or
/// `"record.delete"`.
///
/// # Example
///
/// ```
/// use audit_trail::Action;
///
/// let action = Action::new("user.login");
/// assert_eq!(action.as_str(), "user.login");
/// ```
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct Action<'a>(&'a str);

impl<'a> Action<'a> {
    /// Wrap a string slice as an [`Action`].
    #[inline]
    pub const fn new(value: &'a str) -> Self {
        Self(value)
    }

    /// Borrow the underlying string slice.
    #[inline]
    pub const fn as_str(&self) -> &'a str {
        self.0
    }
}

/// The resource an audited action was performed on (the "where").
///
/// Typically a resource identifier such as `"file:///etc/passwd"`,
/// `"record:42"`, or `"tenant:acme/user:42"`.
///
/// # Example
///
/// ```
/// use audit_trail::Target;
///
/// let target = Target::new("record:42");
/// assert_eq!(target.as_str(), "record:42");
/// ```
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct Target<'a>(&'a str);

impl<'a> Target<'a> {
    /// Wrap a string slice as a [`Target`].
    #[inline]
    pub const fn new(value: &'a str) -> Self {
        Self(value)
    }

    /// Borrow the underlying string slice.
    #[inline]
    pub const fn as_str(&self) -> &'a str {
        self.0
    }
}

/// Outcome of an audited action (the "result").
///
/// `#[non_exhaustive]` so additional outcomes may be added without a major
/// version bump.
///
/// # Example
///
/// ```
/// use audit_trail::Outcome;
///
/// assert_eq!(Outcome::Success.as_u8(), 0);
/// ```
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
#[repr(u8)]
pub enum Outcome {
    /// The action completed successfully.
    Success = 0,
    /// The action was attempted and failed for an operational reason.
    Failure = 1,
    /// The action was denied by policy or authorization.
    Denied = 2,
    /// The action errored due to an unexpected condition.
    Error = 3,
}

impl Outcome {
    /// Stable numeric encoding suitable for hashing.
    #[inline]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

/// A single audited event in the chain.
///
/// A record is intentionally borrowed: its string fields point at caller
/// memory. This keeps the append hot path allocation-free. Sinks that need
/// to persist a record across the lifetime of the borrow must encode it
/// before returning.
///
/// # Example
///
/// ```
/// use audit_trail::{Action, Actor, Digest, Outcome, Record, RecordId, Target, Timestamp};
///
/// let record = Record::new(
///     RecordId::GENESIS,
///     Timestamp::from_nanos(0),
///     Actor::new("system"),
///     Action::new("chain.init"),
///     Target::new("chain:0"),
///     Outcome::Success,
///     Digest::ZERO,
///     Digest::ZERO,
/// );
/// assert_eq!(record.actor().as_str(), "system");
/// ```
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Record<'a> {
    id: RecordId,
    timestamp: Timestamp,
    actor: Actor<'a>,
    action: Action<'a>,
    target: Target<'a>,
    outcome: Outcome,
    prev_hash: Digest,
    hash: Digest,
}

impl<'a> Record<'a> {
    /// Construct a record from its constituent parts.
    ///
    /// The crate's [`crate::Chain`] is normally responsible for producing
    /// records. This constructor is exposed so that custom storage layers
    /// and verifiers can reconstruct records when reading them back.
    #[allow(clippy::too_many_arguments)]
    #[inline]
    pub const fn new(
        id: RecordId,
        timestamp: Timestamp,
        actor: Actor<'a>,
        action: Action<'a>,
        target: Target<'a>,
        outcome: Outcome,
        prev_hash: Digest,
        hash: Digest,
    ) -> Self {
        Self {
            id,
            timestamp,
            actor,
            action,
            target,
            outcome,
            prev_hash,
            hash,
        }
    }

    /// Record identifier.
    #[inline]
    pub const fn id(&self) -> RecordId {
        self.id
    }

    /// Record timestamp.
    #[inline]
    pub const fn timestamp(&self) -> Timestamp {
        self.timestamp
    }

    /// The actor (who).
    #[inline]
    pub const fn actor(&self) -> Actor<'a> {
        self.actor
    }

    /// The action (what).
    #[inline]
    pub const fn action(&self) -> Action<'a> {
        self.action
    }

    /// The target (where).
    #[inline]
    pub const fn target(&self) -> Target<'a> {
        self.target
    }

    /// The outcome (result).
    #[inline]
    pub const fn outcome(&self) -> Outcome {
        self.outcome
    }

    /// Hash of the immediately preceding record in the chain.
    ///
    /// For the genesis record this is [`Digest::ZERO`].
    #[inline]
    pub const fn prev_hash(&self) -> Digest {
        self.prev_hash
    }

    /// Hash of this record, computed over all other fields.
    #[inline]
    pub const fn hash(&self) -> Digest {
        self.hash
    }
}
