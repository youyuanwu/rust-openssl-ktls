//! Experimental async OpenSSL streams built on a runtime-neutral TLS engine.
//!
//! # Status
//!
//! **This crate is an experiment.** It is not published, its API is unstable,
//! and it is Linux-only. Kernel TLS offload is explicitly out of scope — see the
//! sibling `openssl-ktls` crate for that.
//!
//! Both bindings support the handshake in either role, plaintext transfer,
//! flush, TLS shutdown, session inspection, guarded transport recovery, and
//! classified errors. Not implemented in either: peer-initiated renegotiation,
//! post-handshake key update, interoperability with a TLS library other than
//! OpenSSL, and sanitizer-instrumented runs. The compio binding additionally
//! has no concurrent split halves; the tokio binding gets those from
//! `tokio::io::split`. See [`docs/CompioStream.md`] and [`docs/TokioStream.md`]
//! for what that leaves and why.
//!
//! [`docs/CompioStream.md`]: https://github.com/youyuanwu/rust-openssl-ktls/blob/main/docs/CompioStream.md
//! [`docs/TokioStream.md`]: https://github.com/youyuanwu/rust-openssl-ktls/blob/main/docs/TokioStream.md
//!
//! # Why it exists
//!
//! The readiness-based async model hands a library a borrowed buffer and asks
//! the operating system whether a connection is ready before transferring. That
//! fits `epoll`, but not completion-based interfaces such as `io_uring`, where
//! the caller submits a buffer the kernel takes ownership of and returns only
//! once the transfer has finished.
//!
//! This crate began as a TLS stream speaking that ownership-passing vocabulary
//! directly, so an application already committed to such a runtime does not
//! need a second, readiness-based runtime purely for its TLS layer. It now also
//! provides a readiness-based binding, driven by the *same* synchronous TLS
//! state machine — which is the point: the hard part of TLS correctness is
//! written and tested once, regardless of which async model an application
//! picks.
//!
//! # Selecting a runtime
//!
//! The TLS state machine is synchronous and runtime-neutral; only the transport
//! pump differs. Each pump lives behind its own Cargo feature, and both are
//! enabled by default:
//!
//! | Feature | Module | Binding |
//! |---|---|---|
//! | `compio` | [`compio`] | completion-based, for [compio] |
//! | `tokio` | [`tokio`] | readiness-based, for [tokio] |
//!
//! Turning default features off and selecting one keeps the other runtime's
//! packages out of the dependency graph entirely. Usage examples, caller
//! constraints, and design notes are runtime-specific and live in each module's
//! own documentation.
//!
//! # How the two bindings differ
//!
//! The async models are not interchangeable, and these differences are forced
//! by them rather than chosen. A caller moving between the bindings should read
//! this list.
//!
//! - **What a write's count means.** The compio binding reports plaintext only
//!   once its ciphertext has reached the transport. The tokio binding reports
//!   plaintext accepted by TLS; delivery is attempted immediately but only
//!   *guaranteed* after `flush` or `shutdown`. Tokio documents a single-call
//!   write as cancel-safe, which is incompatible with the stronger promise.
//!   Residual ciphertext is drained by the next operation in either direction,
//!   so writing and then reading cannot strand it.
//! - **Backpressure.** The tokio binding admits new plaintext only when nothing
//!   is queued, bounding caller-funded ciphertext to a single TLS record; once
//!   the transport stalls, a write parks rather than buffering further.
//! - **The handshake is explicit on tokio.** A read or write before `connect`
//!   or `accept` fails with [`Error::HandshakeRequired`], touching neither the
//!   caller's buffer nor the transport. The role cannot be inferred.
//! - **Abandoning an operation.** On tokio it is ordinary: a cancelled pending
//!   write delivers nothing and a cancelled read loses nothing, because no
//!   caller buffer is held across a poll. On compio an abandoned write is
//!   indeterminate and forfeits its buffer.
//! - **Half-shutdown.** Whether shutting the write side down leaves reads
//!   usable is determined by the transport. `tokio::net::TcpStream` and the
//!   in-memory duplex both preserve reads; a transport that closes both
//!   directions gets that behaviour instead.
//! - **Concurrency.** `tokio::io::split` gives the tokio binding independent
//!   halves. The compio binding takes `&mut self`, so operations cannot overlap.
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
