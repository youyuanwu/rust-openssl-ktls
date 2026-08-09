//! Experimental completion-based async OpenSSL stream for the [compio] runtime.
//!
//! # Status
//!
//! **This crate is an experiment.** It is not published, its API is unstable,
//! and it is Linux-only. Kernel TLS offload is explicitly out of scope — see the
//! sibling `openssl-ktls` crate for that.
//!
//! # Why it exists
//!
//! The readiness-based async model hands a library a borrowed buffer and asks
//! the operating system whether a connection is ready before transferring. That
//! fits `epoll`, but not completion-based interfaces such as `io_uring`, where
//! the caller submits a buffer the kernel takes ownership of and returns only
//! once the transfer has finished.
//!
//! This crate provides a TLS stream that speaks the completion-based
//! ownership-passing vocabulary directly, so an application already committed to
//! such a runtime does not need a second, readiness-based runtime purely for its
//! TLS layer.
//!
//! # Design
//!
//! The stream is deliberately transport-agnostic: the TLS engine never touches a
//! socket. OpenSSL is attached to a BIO pair, and ciphertext is pumped between
//! that pair and a caller-supplied transport.
//!
//! One invariant is structural and holds everywhere: **caller buffers are never
//! submitted to the transport.** OpenSSL borrows a caller's buffer only during a
//! synchronous call; everything crossing the runtime boundary is a crate-owned
//! ciphertext buffer. This is what makes an abandoned operation safe.
//!
//! [compio]: https://docs.rs/compio

#![deny(unsafe_op_in_unsafe_fn)]

mod engine;
mod error;
mod ffi;
mod stream;

pub use error::Error;
pub use stream::SslStream;
