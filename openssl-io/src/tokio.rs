//! The public readiness-based TLS stream for the [tokio] runtime.
//!
//! # Status
//!
//! **Experimental.** Construction, session inspection, the explicit client and
//! server handshakes, tokio's [`AsyncRead`] and [`AsyncWrite`], TLS shutdown,
//! and guarded transport recovery are in place. Peer-initiated renegotiation
//! and TLS 1.3 key update are not handled: either one terminates the write
//! direction with [`Error::Tls`] while reads continue.
//!
//! # Design
//!
//! The stream drives the same synchronous TLS engine the [`crate::compio`]
//! binding drives; only the pump differs. Where the completion-based binding
//! hands owned buffers to the runtime and therefore has to retain in-flight
//! transport futures, this binding borrows: every transport poll begins and
//! ends inside one `poll_*` call, so the stream holds no caller buffer and no
//! transport future across a return. That is what makes a cancelled operation
//! ordinary rather than indeterminate here.
//!
//! Four rules govern the pump and are worth stating up front, because the
//! rest of the module is their consequence:
//!
//! - **The handshake is explicit.** A read before [`SslStream::connect`] or
//!   [`SslStream::accept`] fails with [`Error::HandshakeRequired`] before any
//!   transport poll happens at all. The role cannot be inferred from a read, so
//!   guessing one would be worse than refusing.
//! - **A write decides to park before OpenSSL is called.** `SSL_write_ex`
//!   demands that a retry present the byte-identical buffer, and tokio's
//!   `AsyncWrite` contract lets the next poll bring a different one; a
//!   violation is a permanent, session-killing "bad write retry" rather than a
//!   stall. So plaintext is offered only when nothing is queued in the engine
//!   or in this stream, and a pending write has consumed nothing.
//! - **The transport always sees one stable waker on its write side.** A
//!   transport retains one waker per direction, and both directions of this
//!   stream can need write readiness — a write drains its own ciphertext, and
//!   a read drains the backlog left behind by an earlier write. If each poll
//!   registered its own caller's waker there, whichever polled last would
//!   displace the other, and cancelling it would leave the transport holding a
//!   dead waker. So every transport write-direction poll passes a waker owned
//!   by the *stream*, and waking it wakes whichever of the two directions is
//!   parked. Nothing can be stolen because nothing is ever registered twice.
//! - **A read still drains queued ciphertext.** A write's delivery is
//!   best-effort until flush, so the read path must push any residual backlog
//!   out; otherwise "write a request, then read the reply" could deadlock with
//!   the request stranded. A failure of that write-side drain is never reported
//!   as the read's own result — a read reports read-side outcomes only — and
//!   the drain is skipped entirely once the write direction is closing or has
//!   failed, so a half-shutdown read cannot resurface a write-side error.
//!
//! Note that `mod tokio` shadows the `tokio` crate at this crate's root, so
//! every path to the external crate is written absolutely as `::tokio::...`,
//! here and in shared code.
//!
//! # Usage
//!
//! The stream wraps one transport implementing tokio's [`AsyncRead`] and
//! [`AsyncWrite`], and implements those traits itself. Use
//! [`tokio::io::split`](https://docs.rs/tokio/latest/tokio/io/fn.split.html)
//! for a reading and a writing half.
//!
//! Connecting as a client:
//!
//! ```no_run
//! use openssl::ssl::{SslConnector, SslMethod};
//! use openssl_io::tokio::SslStream;
//! use tokio::io::{AsyncReadExt, AsyncWriteExt};
//!
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! let tcp = tokio::net::TcpStream::connect("example.com:4433").await?;
//!
//! // `configure().into_ssl(domain)` is what sets SNI and hostname
//! // verification. Building an `Ssl` straight from the context skips both, so
//! // a certificate trusted for some *other* host would be accepted.
//! let connector = SslConnector::builder(SslMethod::tls())?.build();
//! let ssl = connector.configure()?.into_ssl("example.com")?;
//!
//! let mut stream = SslStream::new(ssl, tcp)?;
//! stream.connect().await?;
//!
//! stream.write_all(b"GET / HTTP/1.0\r\n\r\n").await?;
//! // A write is accepted by TLS immediately, but only guaranteed delivered
//! // once flushed. Reading would push it out too; flushing says so plainly.
//! stream.flush().await?;
//!
//! let mut body = Vec::new();
//! stream.read_to_end(&mut body).await?;
//! stream.shutdown().await?;
//! # Ok(())
//! # }
//! ```
//!
//! Accepting as a server:
//!
//! ```no_run
//! use openssl::ssl::Ssl;
//! use openssl_io::tokio::SslStream;
//! use tokio::io::AsyncReadExt;
//!
//! # async fn run(acceptor: openssl::ssl::SslAcceptor) -> Result<(), Box<dyn std::error::Error>> {
//! let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
//! let (tcp, _peer) = listener.accept().await?;
//!
//! let ssl = Ssl::new(acceptor.context())?;
//! let mut stream = SslStream::new(ssl, tcp)?;
//! stream.accept().await?;
//!
//! let mut buf = vec![0u8; 4096];
//! let n = stream.read(&mut buf).await?;
//! println!("{n} plaintext bytes");
//! # Ok(())
//! # }
//! ```
//!
//! [tokio]: https://docs.rs/tokio

use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll, Wake, Waker};

use openssl::ssl::{Ssl, SslRef};

use ::tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::engine::{CIPHER_CHUNK, MAX_RECORD, PAIR_BUF, Progress, Role, TlsEngine};
use crate::error::Error;

/// Structural ceiling on ciphertext buffered on the caller's behalf.
///
/// It matches the BIO pair's per-direction size, so a completely full pair can
/// always be collected in one go and the engine is never left holding records
/// the stream refuses to take. It is a ceiling, not an expected occupancy: one
/// `SSL_write_ex` emits at most one record.
const OUTBOUND_LIMIT: usize = 4 * MAX_RECORD;

// The ceiling has to absorb a completely full pair, or `collect_outbound`
// could refuse ciphertext OpenSSL has already committed to.
const _: () = assert!(
    OUTBOUND_LIMIT >= PAIR_BUF,
    "the ciphertext backlog must be able to absorb a full BIO pair"
);

/// How far the closure sequence has got.
///
/// Shutdown is several steps over a transport that can park at any of them, so
/// the phase is latched rather than recomputed: `close_notify` is emitted
/// exactly once no matter how often the trait method is polled or retried.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum ShutdownState {
    /// No closure has been started.
    Open,
    /// `close_notify` has been produced by the engine.
    TlsClosed,
    /// Every byte of it has reached the transport, which has been flushed.
    TransportFlushed,
    /// The transport's own shutdown has completed.
    Done,
}

/// A terminal condition on the write direction.
///
/// Reads stay usable in both cases — this latches only what the *write* half
/// may still do — and the distinction matters: one of them still permits a
/// closure notification and the other does not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WriteFailure {
    /// The session is closed for application data. The peer sent
    /// `close_notify`, or this side already did, so no further plaintext can be
    /// accepted. `SSL_shutdown` remains legal and flush still reports success:
    /// nothing failed, the direction is simply finished.
    Closed,
    /// A fatal post-handshake TLS condition. OpenSSL must not be re-entered, so
    /// no new `close_notify` can be synthesized; ciphertext already produced is
    /// still delivered, and every write-side result reports this classification.
    Tls,
}

impl WriteFailure {
    /// The classification a latched failure reports, rebuilt on each use
    /// because `Error` is not `Copy`.
    fn to_error(self) -> Error {
        match self {
            WriteFailure::Closed => Error::Closed,
            WriteFailure::Tls => Error::tls(),
        }
    }
}

/// Outcome of a write-side drain performed on behalf of a *read*.
///
/// A read reports only read-side outcomes, so a transport write failure is not
/// an error value here — it is latched for the write direction and reported as
/// [`Drain::Failed`] purely so the read path knows not to keep retrying it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Drain {
    /// Nothing is queued: everything produced so far has reached the transport.
    Complete,
    /// The transport is not ready. This poll's waker is registered for the read
    /// direction, and the transport holds the stream's stable write waker, so
    /// write readiness reaches this task and the write direction alike.
    Pending,
    /// The transport failed. The error was latched for the write direction.
    Failed,
    /// The drain was suppressed because the write direction is shutting down or
    /// has failed terminally. Nothing was polled and nothing was latched.
    Skipped,
}

/// What one inbound pump step achieved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Inbound {
    /// Ciphertext was obtained and offered to OpenSSL.
    Fed,
    /// The transport reported end of file; the engine has been told.
    Eof,
}

/// Which of the stream's two directions a poll belongs to.
///
/// Both of them can end up waiting on the transport's *write* side — a write
/// drains its own ciphertext, and a read drains the backlog an earlier write
/// left behind — so a wakeup has to be able to reach either.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Side {
    Read,
    Write,
}

/// The waker of the task parked on each direction, at most one apiece.
#[derive(Debug, Default)]
struct Slots {
    read: Option<Waker>,
    write: Option<Waker>,
}

/// The one place a parked task's waker lives, and the stable waker the
/// transport's write direction is given.
///
/// A transport retains a single waker per direction. Handing it a caller's
/// waker directly would make the two directions compete for that one slot:
/// whichever polled last would displace the other's registration, and if that
/// last poller were then cancelled the transport would wake a dead task while
/// the survivor slept on — the caller's ciphertext stranded and neither
/// direction able to move it.
///
/// So this value *is* the waker the transport sees on its write side, for every
/// write-direction poll the stream makes. It never changes, so no poll can
/// displace another's registration, and delivering a wakeup means waking
/// whichever of the two directions is currently parked — both, when both are.
///
/// Waking the read side on write readiness is deliberate rather than
/// incidental: a read that has parked with backlog queued genuinely needs that
/// readiness to push the backlog out. A spurious poll is the cost, and it is
/// bounded by the fact that only the transport ever wakes this — a poll of this
/// stream that achieves nothing still wakes nothing.
///
/// Locking rule: the mutex guard is never held across a `Waker::wake` call or a
/// transport poll, so a transport that wakes inline cannot deadlock against it.
/// Poisoning is recovered rather than unwrapped, so a panicking task reports its
/// own failure instead of a cascade of secondary ones.
#[derive(Debug, Default)]
struct Waiters {
    slots: Mutex<Slots>,
}

impl Waiters {
    fn lock(&self) -> MutexGuard<'_, Slots> {
        self.slots
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Store `cx`'s waker for `side`, reusing the existing one when it is
    /// equivalent.
    ///
    /// The clone happens before the lock and the displaced waker is dropped
    /// after it. Both operations run arbitrary caller code — a legitimate
    /// custom waker may wake something from its own `clone` or `drop` — and if
    /// that something is this stable waker, doing it under the guard would
    /// re-enter `wake_by_ref` and deadlock on a non-reentrant mutex.
    fn register(&self, side: Side, cx: &Context<'_>) {
        let fresh = cx.waker().clone();
        let displaced = {
            let mut slots = self.lock();
            let slot = match side {
                Side::Read => &mut slots.read,
                Side::Write => &mut slots.write,
            };
            match slot {
                Some(existing) if existing.will_wake(cx.waker()) => None,
                _ => slot.replace(fresh),
            }
        };
        drop(displaced);
    }

    /// Wake both retained directions after observable progress.
    ///
    /// "Observable progress" means bytes actually moved, end of file was seen,
    /// or the session changed lifecycle state — never merely that a poll
    /// happened. The current task's own registration is left exactly where it
    /// is: waking it would only schedule a redundant poll, and removing it
    /// would drop a registration this poll may still be relying on.
    fn wake_progress(&self, cx: &Context<'_>) {
        let (read, write) = {
            let mut slots = self.lock();
            (
                take_other(&mut slots.read, cx),
                take_other(&mut slots.write, cx),
            )
        };
        if let Some(waker) = read {
            waker.wake();
        }
        if let Some(waker) = write {
            waker.wake();
        }
    }
}

impl Wake for Waiters {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        let (read, write) = {
            let mut slots = self.lock();
            (slots.read.take(), slots.write.take())
        };
        if let Some(waker) = read {
            waker.wake();
        }
        if let Some(waker) = write {
            waker.wake();
        }
    }
}

/// Take a retained waker unless it belongs to the task doing the waking.
fn take_other(slot: &mut Option<Waker>, cx: &Context<'_>) -> Option<Waker> {
    match slot {
        Some(existing) if existing.will_wake(cx.waker()) => None,
        _ => slot.take(),
    }
}

/// A TLS stream over any readiness-based transport.
///
/// The transport is one value implementing tokio's [`AsyncRead`] and
/// [`AsyncWrite`]; it does not have to be backed by an operating-system handle.
/// Use `tokio::io::split` for concurrent read and write halves — the stream
/// keeps a waker slot per direction, and hands the transport one stable waker
/// of its own, precisely so that works.
///
/// # Cancellation
///
/// Dropping a read future is safe and loses no plaintext: a read that returns
/// `Poll::Pending` has written nothing into the caller's buffer, and all
/// received ciphertext stays in the stream or in the engine. The next read
/// resumes where the abandoned one left off.
pub struct SslStream<S> {
    engine: TlsEngine,
    transport: S,

    /// Ciphertext received from the transport but not yet accepted by the
    /// bounded BIO pair. `put_inbound` can take less than it is offered, and
    /// dropping the remainder would corrupt the record stream.
    inbound: Vec<u8>,
    /// How much of `inbound` OpenSSL has already taken. An offset rather than a
    /// front-drain, because a short accept is the common case and repeatedly
    /// shifting the whole buffer would be pure waste.
    inbound_offset: usize,

    /// Ciphertext produced by OpenSSL but not yet accepted by the transport.
    outbound: Vec<u8>,
    /// How much of `outbound` the transport has already taken.
    outbound_offset: usize,

    /// Fixed staging buffer for transport reads. Owned by the stream so no
    /// caller buffer is ever handed to the transport.
    read_scratch: Vec<u8>,

    /// Most recent task parked on each direction.
    ///
    /// Shared with the transport: it is also the waker every write-direction
    /// transport poll registers, so write readiness reaches whichever
    /// direction is waiting on it.
    waiters: Arc<Waiters>,
    /// The `Waker` view of [`Self::waiters`], built once and handed to the
    /// transport's write side on every poll.
    write_ready: Waker,

    /// A transport *write* failure observed on a path whose own result must not
    /// carry it.
    ///
    /// A read that drains queued ciphertext can hit one, and reporting it as
    /// the read's outcome would collide with the truncation-versus-clean-EOF
    /// distinction. It is latched here for the write direction to surface
    /// instead, so the failure is neither dropped nor misattributed. A write's
    /// own best-effort drain uses it too: once TLS has accepted plaintext,
    /// returning the transport's error instead of the accepted count would lose
    /// the caller's bytes.
    ///
    /// `poll_write`, `poll_flush`, and `poll_shutdown` each take it before
    /// doing anything else, so it is reported exactly once and only on the
    /// write side.
    pending_write_error: Option<Error>,

    /// How far closure has progressed, so each step happens at most once.
    shutdown_state: ShutdownState,

    /// A latched terminal condition on the write direction, if any.
    write_failure: Option<WriteFailure>,
}

impl<S> SslStream<S> {
    /// Wrap an already-connected transport.
    ///
    /// No handshake is performed: call [`SslStream::connect`] or
    /// [`SslStream::accept`] next, because the role cannot be inferred later.
    pub fn new(ssl: Ssl, transport: S) -> Result<Self, Error> {
        let waiters = Arc::new(Waiters::default());
        let write_ready = Waker::from(waiters.clone());
        Ok(Self {
            engine: TlsEngine::new(ssl)?,
            transport,
            inbound: Vec::new(),
            inbound_offset: 0,
            outbound: Vec::new(),
            outbound_offset: 0,
            read_scratch: vec![0u8; CIPHER_CHUNK],
            waiters,
            write_ready,
            pending_write_error: None,
            shutdown_state: ShutdownState::Open,
            write_failure: None,
        })
    }

    /// Inspect the underlying TLS session.
    ///
    /// Scoped rather than returning a reference: the session lives behind the
    /// stream's own bookkeeping, so lending it for the duration of a closure is
    /// what can be offered safely.
    pub fn with_ssl<T>(&self, f: impl FnOnce(&SslRef) -> T) -> T {
        f(self.engine.ssl())
    }

    /// Negotiated protocol version, once the handshake has completed.
    pub fn version(&self) -> &'static str {
        self.engine.ssl().version_str()
    }

    /// Negotiated cipher suite name, once the handshake has completed.
    pub fn cipher(&self) -> Option<String> {
        self.engine
            .ssl()
            .current_cipher()
            .map(|c| c.name().to_owned())
    }

    /// True once the peer's `close_notify` has been observed.
    pub fn is_peer_closed(&self) -> bool {
        self.engine.is_peer_closed()
    }

    /// Recover the transport, consuming the stream.
    ///
    /// Refused whenever handing the transport back would silently discard
    /// state: ciphertext queued in either direction, a transport failure the
    /// write direction has been promised, a session that has been terminally
    /// failed on the write side, or a closure sequence stopped halfway
    /// through. A refusal returns the stream itself alongside the reason, so
    /// nothing is destroyed by asking.
    ///
    /// A peer-closed session is *not* a refusal. Nothing failed there and
    /// nothing is buffered; the write direction is simply finished.
    // The error carries the whole stream back, which is the point.
    #[allow(clippy::result_large_err)]
    pub fn into_inner(self) -> Result<S, (Self, Error)> {
        let refusal = if self.inbound_len() > 0 {
            Some("ciphertext received from the transport has not been consumed")
        } else if self.outbound_len() > 0 || self.engine.outbound_pending() > 0 {
            Some("ciphertext produced by TLS has not reached the transport")
        } else if self.pending_write_error.is_some() {
            // Latched with the promise that the next write-side call reports
            // it. A read can empty both buffers while it is still latched, so
            // without this the transport would come back and the failure would
            // vanish with the stream.
            Some("a deferred transport failure has not been reported")
        } else if self.write_failure == Some(WriteFailure::Tls) {
            Some("the write direction failed terminally")
        } else if self.shutdown_state != ShutdownState::Open
            && self.shutdown_state != ShutdownState::Done
        {
            Some("a shutdown is only partly complete")
        } else {
            None
        };

        if let Some(reason) = refusal {
            let err = Error::Transport(io::Error::other(reason));
            return Err((self, err));
        }

        // A retry obligation is only ever created by a `write_plaintext` call
        // that did not return `Done(n > 0)`, and every such call latches a
        // write failure in the same poll. So an unlatched session with empty
        // buffers cannot owe one, and recovery cannot strand accepted plaintext.
        #[cfg(debug_assertions)]
        {
            assert!(
                self.write_failure.is_some() || !self.engine.retry_owed(),
                "recovering a transport while OpenSSL was owed a write retry"
            );
        }

        Ok(self.transport)
    }

    /// The single pre-handshake guard, shared by every application-data entry
    /// point.
    ///
    /// It is checked before an empty-buffer short circuit, before OpenSSL, and
    /// before any transport poll, so a caller that forgot to handshake observes
    /// no I/O at all — not even a readiness registration.
    fn check_handshake_done(&self) -> Result<(), Error> {
        if self.engine.is_handshaking() {
            return Err(Error::HandshakeRequired);
        }
        Ok(())
    }

    // --- waker discipline ---------------------------------------------------

    /// Register `cx`'s waker for the read direction, leaving the write
    /// direction's alone.
    fn register_read_waiter(&self, cx: &Context<'_>) {
        self.waiters.register(Side::Read, cx);
    }

    /// Register `cx`'s waker for the write direction, leaving the read
    /// direction's alone.
    fn register_write_waiter(&self, cx: &Context<'_>) {
        self.waiters.register(Side::Write, cx);
    }

    /// Wake both retained directions after observable progress.
    ///
    /// See [`Waiters::wake_progress`] for what counts as progress and why the
    /// current task's own registration is left in place.
    fn wake_progress(&self, cx: &Context<'_>) {
        self.waiters.wake_progress(cx);
    }

    // --- ciphertext buffers -------------------------------------------------

    /// Ciphertext queued for the transport but not yet accepted by it.
    fn outbound_len(&self) -> usize {
        self.outbound.len() - self.outbound_offset
    }

    /// Ciphertext received from the transport but not yet accepted by OpenSSL.
    fn inbound_len(&self) -> usize {
        self.inbound.len() - self.inbound_offset
    }

    /// Move ciphertext out of the engine and into the crate's backlog.
    ///
    /// Growth stops at [`OUTBOUND_LIMIT`]. Refusing is a terminal internal
    /// condition rather than an allocation, because the ceiling is sized to
    /// absorb a completely full BIO pair: reaching it means the engine produced
    /// more than the pair can hold, which it cannot.
    fn collect_outbound(&mut self) -> Result<(), Error> {
        while self.engine.outbound_pending() > 0 {
            self.compact_outbound();
            if self.outbound.len() >= OUTBOUND_LIMIT {
                return Err(Error::tls());
            }
            let room = (OUTBOUND_LIMIT - self.outbound.len()).min(CIPHER_CHUNK);
            let start = self.outbound.len();
            self.outbound.resize(start + room, 0);
            let n = self.engine.take_outbound(&mut self.outbound[start..]);
            self.outbound.truncate(start + n);
            if n == 0 {
                break;
            }
        }
        Ok(())
    }

    /// Drop the delivered prefix, so the offset never keeps memory alive that
    /// no longer has a reader.
    fn compact_outbound(&mut self) {
        if self.outbound_offset == 0 {
            return;
        }
        self.outbound.drain(..self.outbound_offset);
        self.outbound_offset = 0;
    }

    /// Offer retained ciphertext to OpenSSL, returning how much it took.
    fn feed_inbound(&mut self) -> usize {
        if self.inbound_len() == 0 {
            self.inbound.clear();
            self.inbound_offset = 0;
            return 0;
        }
        let accepted = self
            .engine
            .put_inbound(&self.inbound[self.inbound_offset..]);
        self.inbound_offset += accepted;
        if self.inbound_len() == 0 {
            self.inbound.clear();
            self.inbound_offset = 0;
        }
        accepted
    }
}

impl<S> SslStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    /// Perform the handshake as the initiating side.
    ///
    /// Cancelling this future retains the engine, both ciphertext buffers, and
    /// the transport, so calling it again resumes the same handshake.
    pub async fn connect(&mut self) -> Result<(), Error> {
        std::future::poll_fn(|cx| self.poll_handshake(cx, Role::Client)).await
    }

    /// Perform the handshake as the accepting side.
    ///
    /// Cancellation behaves as it does for [`SslStream::connect`].
    pub async fn accept(&mut self) -> Result<(), Error> {
        std::future::poll_fn(|cx| self.poll_handshake(cx, Role::Server)).await
    }

    // --- handshake ----------------------------------------------------------

    /// Drive one handshake step per loop iteration until it completes, parks,
    /// or fails.
    ///
    /// The ordering rule the engine enforces — flush outranks inbound — is what
    /// keeps this from deadlocking: records already produced reach the
    /// transport before the peer is waited on. Unlike a read, a handshake owns
    /// both directions, so a transport write failure here is genuinely the
    /// handshake's own failure and is reported as such.
    fn poll_handshake(&mut self, cx: &mut Context<'_>, role: Role) -> Poll<Result<(), Error>> {
        let mut eof_seen = false;

        loop {
            let progress = match self.engine.step_handshake(role) {
                Ok(progress) => progress,
                Err(e) => return Poll::Ready(Err(e)),
            };

            if !self.engine.is_handshaking() {
                // Whatever the final step produced still has to reach the peer
                // before the session can be called established.
                if let Err(e) = self.collect_outbound() {
                    return Poll::Ready(Err(e));
                }
                return match self.poll_drain_outbound(cx, Side::Write) {
                    Poll::Ready(Ok(())) => {
                        self.wake_progress(cx);
                        Poll::Ready(Ok(()))
                    }
                    Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                    Poll::Pending => {
                        self.register_write_waiter(cx);
                        Poll::Pending
                    }
                };
            }

            if progress == Progress::NeedsFlush {
                if let Err(e) = self.collect_outbound() {
                    return Poll::Ready(Err(e));
                }
                match self.poll_drain_outbound(cx, Side::Write) {
                    Poll::Ready(Ok(())) => continue,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => {
                        self.register_write_waiter(cx);
                        return Poll::Pending;
                    }
                }
            }

            // Inbound is needed. Anything already produced goes out first
            // (FR-010), but a transport that cannot take it right now must not
            // stop us reading: the peer may itself be blocked writing to us,
            // and waiting for the write would deadlock both sides. Polling the
            // read side too leaves the transport holding this task's waker in
            // both slots, so either direction becoming ready wakes us.
            if let Err(e) = self.collect_outbound() {
                return Poll::Ready(Err(e));
            }
            if let Poll::Ready(Err(e)) = self.poll_drain_outbound(cx, Side::Write) {
                return Poll::Ready(Err(e));
            }

            if eof_seen {
                // The transport is finished and the engine still wants more.
                return Poll::Ready(Err(Error::UnexpectedEof));
            }
            match self.poll_pump_inbound(cx) {
                Poll::Pending => {
                    self.register_read_waiter(cx);
                    return Poll::Pending;
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(Inbound::Eof)) => eof_seen = true,
                Poll::Ready(Ok(Inbound::Fed)) => {}
            }
        }
    }

    // --- transport pumps ----------------------------------------------------

    /// Push the backlog at the transport until it is empty or the transport
    /// stops taking bytes.
    ///
    /// `side` is the direction whose task is doing the pushing. Its waker is
    /// registered *before* the transport is polled, not after a `Pending`
    /// return: the transport is given the stream's stable write waker rather
    /// than this task's, so a readiness wake arriving between the poll and the
    /// return would otherwise find no slot to deliver into and be lost.
    ///
    /// Byte movement is observable progress, so retained waiters are woken even
    /// when the drain ultimately parks or fails.
    fn poll_drain_outbound(&mut self, cx: &mut Context<'_>, side: Side) -> Poll<Result<(), Error>> {
        let mut moved = false;

        let outcome = loop {
            if self.outbound_len() == 0 {
                self.outbound.clear();
                self.outbound_offset = 0;
                break Poll::Ready(Ok(()));
            }
            self.waiters.register(side, cx);
            let mut ready = Context::from_waker(&self.write_ready);
            match Pin::new(&mut self.transport)
                .poll_write(&mut ready, &self.outbound[self.outbound_offset..])
            {
                Poll::Pending => break Poll::Pending,
                Poll::Ready(Ok(0)) => {
                    // A transport that reports success while taking nothing
                    // would spin here forever, so it is a failure.
                    break Poll::Ready(Err(Error::Transport(io::Error::from(
                        io::ErrorKind::WriteZero,
                    ))));
                }
                Poll::Ready(Ok(n)) => {
                    self.outbound_offset += n;
                    moved = true;
                }
                Poll::Ready(Err(e)) => break Poll::Ready(Err(Error::Transport(e))),
            }
        };

        if moved {
            self.wake_progress(cx);
        }
        outcome
    }

    /// Flush the transport itself, on the write direction's behalf.
    ///
    /// Same registration rule as [`Self::poll_drain_outbound`]: the transport
    /// sees the stream's stable waker, so this task's own must already be in
    /// its slot when the poll happens.
    fn poll_transport_flush(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        self.register_write_waiter(cx);
        let mut ready = Context::from_waker(&self.write_ready);
        Pin::new(&mut self.transport)
            .poll_flush(&mut ready)
            .map_err(Error::Transport)
    }

    /// Shut the transport's write direction down. Registration as above.
    fn poll_transport_shutdown(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        self.register_write_waiter(cx);
        let mut ready = Context::from_waker(&self.write_ready);
        Pin::new(&mut self.transport)
            .poll_shutdown(&mut ready)
            .map_err(Error::Transport)
    }

    /// Drain the backlog on behalf of a *read*.
    ///
    /// Two rules distinguish this from [`Self::poll_drain_outbound`], and both
    /// exist so a read reports only read-side outcomes. A transport failure is
    /// latched for the write direction rather than returned, and the drain
    /// never parks the read on write readiness alone.
    ///
    /// A third rule is the skip guard. Once the write direction is closing or
    /// has failed terminally, a read must not touch the transport's write side
    /// at all: a half-shutdown read that resurfaced a write-side error would
    /// contradict the whole point of leaving the read half usable.
    // Every read-path drain goes through here, so both the guard and the
    // latching rule are stated exactly once.
    fn drain_for_read(&mut self, cx: &mut Context<'_>) -> Drain {
        if self.shutdown_state != ShutdownState::Open
            || self.write_failure == Some(WriteFailure::Tls)
        {
            return Drain::Skipped;
        }
        if self.outbound_len() == 0 {
            return Drain::Complete;
        }
        match self.poll_drain_outbound(cx, Side::Read) {
            Poll::Ready(Ok(())) => Drain::Complete,
            Poll::Ready(Err(e)) => {
                if self.pending_write_error.is_none() {
                    self.pending_write_error = Some(e);
                }
                Drain::Failed
            }
            Poll::Pending => Drain::Pending,
        }
    }

    /// Obtain ciphertext and offer it to OpenSSL.
    ///
    /// Retained bytes come first: the pair is bounded, so a short accept is
    /// routine and reading more before the remainder is placed would reorder
    /// the record stream.
    fn poll_pump_inbound(&mut self, cx: &mut Context<'_>) -> Poll<Result<Inbound, Error>> {
        if self.inbound_len() > 0 && self.feed_inbound() > 0 {
            self.wake_progress(cx);
            return Poll::Ready(Ok(Inbound::Fed));
        }

        let filled = {
            let mut buf = ReadBuf::new(&mut self.read_scratch);
            match Pin::new(&mut self.transport).poll_read(cx, &mut buf) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(Error::Transport(e))),
                Poll::Ready(Ok(())) => buf.filled().len(),
            }
        };

        if filled == 0 {
            self.engine.note_transport_eof();
            self.wake_progress(cx);
            return Poll::Ready(Ok(Inbound::Eof));
        }

        self.compact_inbound();
        self.inbound.extend_from_slice(&self.read_scratch[..filled]);
        self.feed_inbound();
        self.wake_progress(cx);
        Poll::Ready(Ok(Inbound::Fed))
    }

    fn compact_inbound(&mut self) {
        if self.inbound_offset == 0 {
            return;
        }
        self.inbound.drain(..self.inbound_offset);
        self.inbound_offset = 0;
    }

    // --- application data ---------------------------------------------------

    /// The read pump.
    ///
    /// Errors are returned as this crate's classification and converted to
    /// `io::Error` exactly once, at the trait boundary.
    fn poll_read_impl(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<(), Error>> {
        // Before the empty-buffer short circuit, before OpenSSL, and before any
        // transport poll.
        if let Err(e) = self.check_handshake_done() {
            return Poll::Ready(Err(e));
        }
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }

        // Both are per-poll latches that keep the loop from retrying something
        // that has already failed, been suppressed, or ended.
        let mut drain_stopped = false;
        let mut eof_seen = false;

        loop {
            // A write's delivery is best-effort until flush, so residual
            // ciphertext must not be left stranded while this side waits on the
            // peer. The read never parks on this drain.
            if !drain_stopped && matches!(self.drain_for_read(cx), Drain::Failed | Drain::Skipped) {
                drain_stopped = true;
            }

            // OpenSSL fills the caller's buffer during this synchronous call;
            // nothing borrowed from the caller ever reaches the transport.
            // SAFETY: `unfilled_mut` is unsafe because its contents must stay
            // at least as initialized as they were. OpenSSL only writes into
            // the slice and never de-initializes any byte of it.
            let unfilled = unsafe { buf.unfilled_mut() };
            let progress = match self.engine.read_plaintext_uninit(unfilled) {
                Ok(progress) => progress,
                Err(e) => return Poll::Ready(Err(e)),
            };

            match progress {
                // Zero plaintext into a non-empty buffer is the peer's
                // `close_notify`: a clean end of stream, and a sticky one.
                Progress::Done(0) => return Poll::Ready(Ok(())),
                Progress::Done(n) => {
                    // SAFETY: `read_plaintext_uninit` reported that OpenSSL
                    // initialized exactly `n` bytes at the front of the
                    // unfilled region.
                    unsafe { buf.assume_init(n) };
                    buf.advance(n);
                    return Poll::Ready(Ok(()));
                }
                Progress::NeedsFlush => {
                    // The engine genuinely owes a send — under TLS 1.3 this is
                    // typically a `KeyUpdate` response. This is the one case
                    // where a read may park purely on write readiness.
                    if let Err(e) = self.collect_outbound() {
                        return Poll::Ready(Err(e));
                    }
                    if !drain_stopped && self.outbound_len() > 0 {
                        match self.drain_for_read(cx) {
                            Drain::Complete => continue,
                            Drain::Pending => {
                                self.register_read_waiter(cx);
                                return Poll::Pending;
                            }
                            Drain::Failed | Drain::Skipped => drain_stopped = true,
                        }
                    }
                    // Either there was nothing to send after all, or the write
                    // side is broken or closing and its ciphertext is no longer
                    // this read's business. Fall through: only the peer can
                    // move this session now, and polling the read side is what
                    // gives this task a wake source it can trust.
                }
                Progress::NeedsInbound => {
                    // `classify` guarantees the engine owes no flush here, so
                    // this never waits on the peer with our own records queued.
                    debug_assert_eq!(self.engine.outbound_pending(), 0);
                }
            }

            if eof_seen {
                // The transport ended and the engine still cannot progress.
                // Reported as truncation, which is a read-side outcome.
                return Poll::Ready(Err(Error::UnexpectedEof));
            }
            match self.poll_pump_inbound(cx) {
                Poll::Pending => {
                    self.register_read_waiter(cx);
                    return Poll::Pending;
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(Inbound::Eof)) => eof_seen = true,
                Poll::Ready(Ok(Inbound::Fed)) => {}
            }
        }
    }

    /// Take a transport write error latched by an earlier operation.
    ///
    /// Every write-side entry point calls this first, which is what makes a
    /// deferred failure surface exactly once, on the direction it belongs to.
    fn take_pending_write_error(&mut self) -> Option<Error> {
        self.pending_write_error.take()
    }

    /// Debug-only guard on the rule that makes a readiness write path safe.
    ///
    /// Parking with a retry owed would let the next poll present a different
    /// buffer, which OpenSSL rejects permanently as a "bad write retry" and
    /// which kills the session rather than stalling it.
    ///
    /// Written as a gated block rather than a `debug_assert!` on purpose: the
    /// predicate exists only where assertions run, and `debug_assert!` would
    /// still type-check its argument in a build with assertions off.
    fn debug_assert_no_retry_owed(&self) {
        #[cfg(debug_assertions)]
        {
            assert!(
                !self.engine.retry_owed(),
                "poll_write parked while OpenSSL was owed a byte-identical retry"
            );
        }
    }

    /// Latch a terminal write-direction condition and report it once.
    fn fail_write(&mut self, failure: WriteFailure, error: Error) -> Poll<Result<usize, Error>> {
        self.write_failure = Some(failure);
        Poll::Ready(Err(error))
    }

    /// The write pump.
    ///
    /// The admission rule is the whole design: the decision to park is taken
    /// *before* OpenSSL is entered. A measured `SSL_write_ex` retried with a
    /// different buffer fails permanently, and tokio's `AsyncWrite` contract
    /// explicitly allows the next poll to bring one, so "call, then park" is
    /// not available here. Plaintext is offered only when nothing is queued
    /// anywhere, which simultaneously bounds buffering and guarantees that a
    /// pending write consumed nothing.
    fn poll_write_impl(&mut self, cx: &mut Context<'_>, data: &[u8]) -> Poll<Result<usize, Error>> {
        // Before the empty-slice short circuit, before OpenSSL, and before any
        // transport poll.
        if let Err(e) = self.check_handshake_done() {
            return Poll::Ready(Err(e));
        }
        // A transport failure deferred by an earlier best-effort drain belongs
        // to this direction and is reported before anything else happens.
        if let Some(e) = self.take_pending_write_error() {
            return Poll::Ready(Err(e));
        }
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if let Some(failure) = self.write_failure {
            // Terminal in both cases: OpenSSL is never re-entered on this path.
            return Poll::Ready(Err(failure.to_error()));
        }

        // Everything already produced goes out first. Only an empty engine and
        // an empty backlog make room for a full record, which is what lets the
        // ceiling be a structural one rather than a running total.
        if let Err(e) = self.collect_outbound() {
            return self.fail_write(WriteFailure::Tls, e);
        }
        match self.poll_drain_outbound(cx, Side::Write) {
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => {
                // Prior ciphertext is still queued, so OpenSSL is not entered
                // at all and the caller's buffer is untouched.
                self.register_write_waiter(cx);
                self.debug_assert_no_retry_owed();
                return Poll::Pending;
            }
            Poll::Ready(Ok(())) => {}
        }
        debug_assert_eq!(self.outbound_len(), 0);
        debug_assert_eq!(self.engine.outbound_pending(), 0);

        // One record is all `SSL_write_ex` will take, so offering more only
        // enlarges the slice OpenSSL would owe a retry for.
        let offered = &data[..data.len().min(MAX_RECORD)];
        let mut flush_retried = false;

        loop {
            let progress = match self.engine.write_plaintext(offered) {
                Ok(progress) => progress,
                Err(Error::Closed) => return self.fail_write(WriteFailure::Closed, Error::Closed),
                Err(e) => return self.fail_write(WriteFailure::Tls, e),
            };

            match progress {
                // A non-empty slice that TLS accepted nothing from is the
                // peer's `close_notify` seen through the write path. OpenSSL is
                // owed a retry whose length cannot be reconstructed from a
                // later caller buffer, so the direction ends here rather than
                // reporting a zero-length success it is not allowed to report.
                Progress::Done(0) => return self.fail_write(WriteFailure::Closed, Error::Closed),
                Progress::Done(n) => {
                    if let Err(e) = self.collect_outbound() {
                        return self.fail_write(WriteFailure::Tls, e);
                    }
                    // Best effort, and deliberately not part of the result: TLS
                    // has already taken these bytes, so anything but
                    // `Ready(Ok(n))` would lose them. A transport failure is
                    // latched for the next write-side call instead of dropped.
                    match self.poll_drain_outbound(cx, Side::Write) {
                        Poll::Ready(Ok(())) | Poll::Pending => {}
                        Poll::Ready(Err(e)) => {
                            if self.pending_write_error.is_none() {
                                self.pending_write_error = Some(e);
                            }
                        }
                    }
                    return Poll::Ready(Ok(n));
                }
                Progress::NeedsFlush => {
                    // Unreachable by construction — the pair was empty and has
                    // room for four records, while one write emits at most one
                    // — so this is defensive only. The identical slice is
                    // retried at most once, and never spins.
                    if flush_retried {
                        return self.fail_write(WriteFailure::Tls, Error::tls());
                    }
                    flush_retried = true;
                    if let Err(e) = self.collect_outbound() {
                        return self.fail_write(WriteFailure::Tls, e);
                    }
                }
                Progress::NeedsInbound => {
                    // A write that needs to *read* means a peer-initiated
                    // post-handshake condition — renegotiation or a TLS 1.3
                    // key update — which M1 does not handle. Parking here would
                    // park with a retry owed, and staging the caller's
                    // plaintext would break the cancellation guarantee, so the
                    // write direction ends instead. Reads keep working, and
                    // flush and shutdown still deliver what was produced.
                    return self.fail_write(WriteFailure::Tls, Error::tls());
                }
            }
        }
    }

    /// The flush pump: the point at which delivery stops being best effort.
    ///
    /// Every byte of ciphertext produced so far reaches the transport, and the
    /// transport itself is flushed, before this reports success.
    fn poll_flush_impl(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        if let Some(e) = self.take_pending_write_error() {
            return Poll::Ready(Err(e));
        }

        // Collecting reads the BIO; it does not re-enter OpenSSL, so it is
        // still correct — and still required — under a terminal failure.
        if let Err(e) = self.collect_outbound() {
            self.write_failure = Some(WriteFailure::Tls);
            return Poll::Ready(Err(e));
        }
        match self.poll_drain_outbound(cx, Side::Write) {
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => {
                self.register_write_waiter(cx);
                return Poll::Pending;
            }
            Poll::Ready(Ok(())) => {}
        }
        match self.poll_transport_flush(cx) {
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Ok(())) => {}
        }

        // A clean drain under a peer-closed session is a real success: nothing
        // failed and nothing is outstanding. A fatal TLS condition is not, even
        // though the ciphertext that existed has been delivered.
        if self.write_failure == Some(WriteFailure::Tls) {
            return Poll::Ready(Err(Error::tls()));
        }
        Poll::Ready(Ok(()))
    }

    /// The closure pump.
    ///
    /// Generic tokio utilities reach for `shutdown`, so this must not be a way
    /// to bypass `close_notify` and leave the peer seeing a truncated stream.
    /// It does not wait for the peer's own notification: a silent peer would
    /// otherwise hang the caller, and TLS does not require the wait.
    fn poll_shutdown_impl(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        if let Some(e) = self.take_pending_write_error() {
            return Poll::Ready(Err(e));
        }

        loop {
            match self.shutdown_state {
                ShutdownState::Open => {
                    // Application ciphertext goes out before the notification,
                    // so the peer never sees closure overtake data.
                    if let Err(e) = self.collect_outbound() {
                        self.write_failure = Some(WriteFailure::Tls);
                        return Poll::Ready(Err(e));
                    }
                    match self.poll_drain_outbound(cx, Side::Write) {
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Pending => {
                            self.register_write_waiter(cx);
                            return Poll::Pending;
                        }
                        Poll::Ready(Ok(())) => {}
                    }

                    // A peer-closed session is still allowed to close: the
                    // engine has not sent its own notification, and withholding
                    // it would truncate the peer. Only a fatal TLS condition
                    // forbids re-entering OpenSSL, and it leaves M1 unable to
                    // synthesize a notification at all.
                    if self.write_failure != Some(WriteFailure::Tls) {
                        match self.engine.shutdown() {
                            Ok(Progress::Done(_)) => {}
                            // Defensive: the pair was just drained, so a
                            // `close_notify` cannot fail to fit and the peer is
                            // never waited on.
                            Ok(_) => self.write_failure = Some(WriteFailure::Tls),
                            Err(_) => self.write_failure = Some(WriteFailure::Tls),
                        }
                        if let Err(e) = self.collect_outbound() {
                            self.write_failure = Some(WriteFailure::Tls);
                            return Poll::Ready(Err(e));
                        }
                    }
                    self.shutdown_state = ShutdownState::TlsClosed;
                    self.wake_progress(cx);
                }
                ShutdownState::TlsClosed => {
                    match self.poll_drain_outbound(cx, Side::Write) {
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Pending => {
                            self.register_write_waiter(cx);
                            return Poll::Pending;
                        }
                        Poll::Ready(Ok(())) => {}
                    }
                    match self.poll_transport_flush(cx) {
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Ok(())) => {}
                    }
                    self.shutdown_state = ShutdownState::TransportFlushed;
                }
                ShutdownState::TransportFlushed => {
                    // Whether this leaves the read half usable is the
                    // transport's contract, not this crate's.
                    match self.poll_transport_shutdown(cx) {
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Ok(())) => {}
                    }
                    self.shutdown_state = ShutdownState::Done;
                }
                // Closing an already-closed session succeeds without emitting
                // a second notification, however often it is repeated.
                ShutdownState::Done => {
                    return Poll::Ready(if self.write_failure == Some(WriteFailure::Tls) {
                        Err(Error::tls())
                    } else {
                        Ok(())
                    });
                }
            }
        }
    }
}

impl<S> AsyncRead for SslStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    /// Reads plaintext, driving the transport as far as the session requires.
    ///
    /// A `Poll::Pending` return leaves `buf` untouched and discards no
    /// plaintext, so dropping the read is safe. A peer that closed cleanly
    /// yields zero filled bytes — end of stream — for every subsequent read.
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // Converted exactly once: re-wrapping the result would bury the
        // classification beyond `Error::downcast_io`'s reach.
        self.get_mut()
            .poll_read_impl(cx, buf)
            .map(|result| result.map_err(io::Error::from))
    }
}

impl<S> AsyncWrite for SslStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    /// Writes plaintext, reporting what the TLS layer accepted.
    ///
    /// A successful return means the bytes are committed to the session and
    /// their ciphertext is queued; one best-effort attempt is made to hand that
    /// ciphertext to the transport before returning, so the common
    /// write-then-read sequence makes progress with no explicit flush. Delivery
    /// is *guaranteed* only once [`poll_flush`](AsyncWrite::poll_flush) or
    /// [`poll_shutdown`](AsyncWrite::poll_shutdown) completes. This differs
    /// from the compio binding, which reports only bytes whose ciphertext has
    /// reached the transport.
    ///
    /// At most one TLS record is accepted per call, so a larger buffer returns
    /// a partial count. A `Poll::Pending` return has consumed nothing at all,
    /// which is what makes dropping a write future deliver nothing to the peer.
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // Converted exactly once: re-wrapping the result would bury the
        // classification beyond `Error::downcast_io`'s reach.
        self.get_mut()
            .poll_write_impl(cx, buf)
            .map(|result| result.map_err(io::Error::from))
    }

    /// Delivers every byte of ciphertext produced so far, then flushes the
    /// transport.
    ///
    /// This is the delivery boundary a write does not provide.
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut()
            .poll_flush_impl(cx)
            .map(|result| result.map_err(io::Error::from))
    }

    /// Shuts the TLS session down, not merely the transport.
    ///
    /// Queued ciphertext is flushed, one `close_notify` is sent, and the
    /// transport is flushed and shut down. The peer's own notification is not
    /// waited for. Repeating this after it has completed succeeds without
    /// emitting a second notification.
    ///
    /// Whether the read half survives is the transport's contract: a transport
    /// whose shutdown closes only its write direction leaves reads usable until
    /// the peer closes, and one that closes both does not.
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut()
            .poll_shutdown_impl(cx)
            .map(|result| result.map_err(io::Error::from))
    }
}
