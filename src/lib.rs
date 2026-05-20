//! # audit-trail
//!
//! Tamper-evident audit logging via cryptographically chained records.
//!
//! Every audited event becomes a [`Record`] capturing the canonical
//! who / what / when / where / result tuple, together with the hash of the
//! preceding record. Any modification to a past record breaks the chain at
//! that point and is trivially detectable on re-verification.
//!
//! ## Public surface
//!
//! - [`Record`] — the audited event (5W + chain links).
//! - [`Chain`] — the append-only chain that wires a [`Hasher`], a [`Sink`],
//!   and a [`Clock`].
//! - [`Hasher`] — pluggable hash function (SHA-256, BLAKE3, …).
//! - [`Sink`] — pluggable backend that persists each record.
//! - [`Clock`] — pluggable time source.
//! - [`Verifier`] — replays a chain and proves it is untampered.
//!
//! `audit-trail` does not bundle a concrete hasher, sink, or clock in the
//! foundation milestone. Callers wire concrete implementations in.
//!
//! ## Design principles
//!
//! - **Zero-allocation hot path.** Records borrow their string fields; the
//!   append path never touches the heap.
//! - **No async runtime dependency.** The append API is synchronous.
//! - **`no_std` capable.** Enable with `default-features = false`.
//!
//! See `.dev/ROADMAP.md` for the path to 1.0.
//!
//! ## License
//!
//! Dual-licensed under Apache-2.0 OR MIT.

#![doc(html_root_url = "https://docs.rs/audit-trail")]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(not(feature = "std"), no_std)]
#![deny(missing_docs)]
#![deny(unsafe_op_in_unsafe_fn)]
#![deny(unused_must_use)]
#![deny(unused_results)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::todo)]
#![deny(clippy::unimplemented)]
#![deny(clippy::print_stdout)]
#![deny(clippy::print_stderr)]
#![deny(clippy::dbg_macro)]
#![deny(clippy::undocumented_unsafe_blocks)]
#![deny(clippy::missing_safety_doc)]

/// Crate version string, populated by Cargo at build time.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

mod canonical;
mod chain;
mod clock;
mod error;
mod hash;
mod record;
mod sink;
mod verify;

pub use chain::Chain;
pub use clock::{Clock, Timestamp};
pub use error::{Error, Result, SinkError};
pub use hash::{Digest, HASH_LEN, Hasher};
pub use record::{Action, Actor, Outcome, Record, RecordId, Target};
pub use sink::Sink;
pub use verify::Verifier;
