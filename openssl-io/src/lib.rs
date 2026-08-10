//! Experimental async OpenSSL streams built on a runtime-neutral TLS engine.
//!
//! # Status
//!
//! **This crate is an experiment.** It is not published, its API is unstable,
//! and it is Linux-only. Kernel TLS offload is explicitly out of scope — see the
//! sibling `openssl-ktls` crate for that.
//!
//! Concurrent split halves, interoperability testing against an independent TLS
//! implementation, renegotiation, post-handshake key update, and
//! sanitizer-instrumented runs are **not yet implemented**. See
//! `docs/CompioStream.md` for what that leaves and why.
//!
//! # Why it exists
//!
//! The readiness-based async model hands a library a borrowed buffer and asks
//! the operating system whether a connection is ready before transferring. That
//! fits `epoll`, but not completion-based interfaces such as `io_uring`, where
//! the caller submits a buffer the kernel takes ownership of and returns only
//! once the transfer has finished.
//!
//! This crate provides a TLS stream that speaks that ownership-passing
//! vocabulary directly, so an application already committed to such a runtime
//! does not need a second, readiness-based runtime purely for its TLS layer.
//!
//! # Selecting a runtime
//!
//! The TLS state machine is synchronous and runtime-neutral; only the transport
//! pump differs. Each pump lives behind its own Cargo feature, and both are
//! enabled by default:
//!
//! | Feature | Module | Binding |
//! |---|---|---|
//! | `compio` | [`compio`](compio) | completion-based, for [compio] |
//! | `tokio` | [`tokio`](tokio) | readiness-based, for [tokio] |
//!
//! Turning default features off and selecting one keeps the other runtime's
//! packages out of the dependency graph entirely. Usage examples, caller
//! constraints, and design notes are runtime-specific and live in each module's
//! own documentation.
//!
//! [compio]: https://docs.rs/compio
//! [tokio]: https://docs.rs/tokio

#![deny(unsafe_op_in_unsafe_fn)]

mod engine;
mod error;
mod ffi;

#[cfg(feature = "compio")]
pub mod compio;
#[cfg(feature = "tokio")]
pub mod tokio;

pub use error::Error;
