//! Experimental completion-based async OpenSSL stream for the [compio] runtime.
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
//! # Usage
//!
//! The stream is generic over the transport, which is supplied as a reading and
//! a writing half. compio's `TcpStream` and `UnixStream` split into halves
//! directly; anything else can be split with `compio_io::split`.
//!
//! Connecting as a client:
//!
//! ```no_run
//! use compio_io::AsyncWriteExt;
//! use openssl::ssl::{SslConnector, SslMethod};
//! use openssl_io::SslStream;
//!
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! let tcp = compio::net::TcpStream::connect("example.com:4433").await?;
//! let (read_half, write_half) = tcp.into_split();
//!
//! // `configure().into_ssl(domain)` is what sets SNI and hostname
//! // verification. Building an `Ssl` straight from the context skips both, so
//! // a certificate trusted for some *other* host would be accepted.
//! let connector = SslConnector::builder(SslMethod::tls())?.build();
//! let ssl = connector.configure()?.into_ssl("example.com")?;
//!
//! let mut stream = SslStream::new(ssl, read_half, write_half)?;
//! stream.connect().await?;
//!
//! stream.write_all(b"GET / HTTP/1.0\r\n\r\n".to_vec()).await.0?;
//! stream.close().await?;
//! # Ok(())
//! # }
//! ```
//!
//! Accepting as a server:
//!
//! ```no_run
//! use compio_io::AsyncRead;
//! use openssl::ssl::Ssl;
//! use openssl_io::SslStream;
//!
//! # async fn run(acceptor: openssl::ssl::SslAcceptor) -> Result<(), Box<dyn std::error::Error>> {
//! let listener = compio::net::TcpListener::bind("127.0.0.1:0").await?;
//! let (tcp, _peer) = listener.accept().await?;
//! let (read_half, write_half) = tcp.into_split();
//!
//! let ssl = Ssl::new(acceptor.context())?;
//! let mut stream = SslStream::new(ssl, read_half, write_half)?;
//! stream.accept().await?;
//!
//! let buf = Vec::with_capacity(4096);
//! let compio_buf::BufResult(n, _buf) = stream.read(buf).await;
//! println!("{} plaintext bytes", n?);
//! # Ok(())
//! # }
//! ```
//!
//! # Constraints callers must observe
//!
//! - **One operation at a time.** The stream takes `&mut self`, so a read and a
//!   write cannot overlap. Full-duplex use needs split halves, which are not yet
//!   implemented.
//! - **Writes may be partial.** A single `SSL_write_ex` accepts at most one TLS
//!   record (16 KiB), so a larger write returns a partial count and the caller
//!   resubmits the remainder. A reported count always means that much ciphertext
//!   has reached the transport.
//! - **Abandoning a write is indeterminate.** Dropping a write future — on a
//!   timeout, say — leaves the session correct and usable, but an unknown
//!   prefix of the payload may already have been committed, and the count is
//!   lost with the future. The caller's buffer is forfeited; only ciphertext
//!   OpenSSL has already produced, or plaintext it is still owed a retry for, is
//!   retained and completed by the next operation. Anything not yet accepted is
//!   gone with the future, so a caller that must know what was sent has to
//!   resynchronize at the application layer. Abandoning a *read* has no such
//!   caveat.
//! - **Close explicitly.** Dropping the stream does not send `close_notify`, so
//!   the peer will see a truncated connection. Call [`SslStream::close`], or
//!   `shutdown` from compio's `AsyncWrite` trait, which does the same thing.
//!
//! # Design
//!
//! The stream is transport-agnostic because the TLS engine never touches a
//! socket: OpenSSL is attached to a BIO pair, and ciphertext is pumped between
//! that pair and the caller's transport.
//!
//! One invariant is structural and holds everywhere: **caller buffers are never
//! submitted to the transport.** OpenSSL borrows a caller's buffer only during a
//! synchronous call; everything crossing the runtime boundary is a crate-owned
//! ciphertext buffer. That, plus keeping in-flight transport operations in the
//! stream rather than in the returned future, is what makes an abandoned
//! operation safe.
//!
//! `docs/CompioStream.md` covers the rest: why a BIO pair rather than a memory
//! BIO or a custom `BIO_METHOD`, the BIO ownership split, the staged-write
//! rules, and the buffer inventory.
//!
//! [compio]: https://docs.rs/compio

#![deny(unsafe_op_in_unsafe_fn)]

mod engine;
mod error;
mod ffi;
mod stream;

pub use error::Error;
pub use stream::SslStream;
