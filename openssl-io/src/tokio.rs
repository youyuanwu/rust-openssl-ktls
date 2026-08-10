//! The public readiness-based TLS stream for the [tokio] runtime.
//!
//! # Status
//!
//! **Partially implemented.** Construction, session inspection, the explicit
//! client and server handshakes, and tokio's [`AsyncRead`] are in place. The
//! write half — `AsyncWrite`, flush, TLS shutdown, and transport recovery — is
//! not yet exposed, so the stream is currently usable for handshaking and for
//! reading plaintext a peer sends.
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
//! Three rules govern the pump and are worth stating up front, because the
//! rest of the module is their consequence:
//!
//! - **The handshake is explicit.** A read before [`SslStream::connect`] or
//!   [`SslStream::accept`] fails with [`Error::HandshakeRequired`] before any
//!   transport poll happens at all. The role cannot be inferred from a read, so
//!   guessing one would be worse than refusing.
//! - **Read and write waiters are stored separately.** A transport retains one
//!   waker per direction, so when a read poll uses the transport's *write* side
//!   and finds it not ready, it hands that single slot back by waking the
//!   stored writer. Without that, a reader that is dropped on a timeout would
//!   strand a writer on a dead waker.
//! - **A read still drains queued ciphertext.** A write's delivery is
//!   best-effort until flush, so the read path must push any residual backlog
//!   out; otherwise "write a request, then read the reply" could deadlock with
//!   the request stranded. A failure of that write-side drain is never reported
//!   as the read's own result — a read reports read-side outcomes only.
//!
//! Note that `mod tokio` shadows the `tokio` crate at this crate's root, so
//! every path to the external crate is written absolutely as `::tokio::...`,
//! here and in shared code.
//!
//! [tokio]: https://docs.rs/tokio

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, Waker};

use openssl::ssl::{Ssl, SslRef};

use ::tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::engine::{CIPHER_CHUNK, MAX_RECORD, Progress, Role, TlsEngine};
use crate::error::Error;

/// Structural ceiling on ciphertext buffered on the caller's behalf.
///
/// It matches the BIO pair's per-direction size, so a completely full pair can
/// always be collected in one go and the engine is never left holding records
/// the stream refuses to take. It is a ceiling, not an expected occupancy: one
/// `SSL_write_ex` emits at most one record.
const OUTBOUND_LIMIT: usize = 4 * MAX_RECORD;

/// Outcome of a write-side drain performed on behalf of a *read*.
///
/// A read reports only read-side outcomes, so a transport write failure is not
/// an error value here — it is latched for the write direction and reported as
/// [`Drain::Failed`] purely so the read path knows not to keep retrying it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Drain {
    /// Nothing is queued: everything produced so far has reached the transport.
    Complete,
    /// The transport is not ready. The stored writer has been woken so it can
    /// reclaim the transport's single write-waker slot.
    Pending,
    /// The transport failed. The error was latched for the write direction.
    Failed,
}

/// What one inbound pump step achieved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Inbound {
    /// Ciphertext was obtained and offered to OpenSSL.
    Fed,
    /// The transport reported end of file; the engine has been told.
    Eof,
}

/// A TLS stream over any readiness-based transport.
///
/// The transport is one value implementing tokio's [`AsyncRead`] and
/// [`AsyncWrite`]; it does not have to be backed by an operating-system handle.
/// Use `tokio::io::split` for concurrent read and write halves — the stream
/// keeps separate read and write waiters precisely so that works.
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

    /// Most recent task parked on the read direction.
    read_waiter: Option<Waker>,
    /// Most recent task parked on the handshake or write direction.
    write_waiter: Option<Waker>,

    /// A transport *write* failure observed on a path whose own result must not
    /// carry it.
    ///
    /// A read that drains queued ciphertext can hit one, and reporting it as
    /// the read's outcome would collide with the truncation-versus-clean-EOF
    /// distinction. It is latched here for the write direction to surface
    /// instead, so the failure is neither dropped nor misattributed.
    // The consumers — `poll_write`, `poll_flush`, and `poll_shutdown` — arrive
    // with the write half in the next phase; the producer already exists here.
    pending_write_error: Option<Error>,
}

impl<S> SslStream<S> {
    /// Wrap an already-connected transport.
    ///
    /// No handshake is performed: call [`SslStream::connect`] or
    /// [`SslStream::accept`] next, because the role cannot be inferred later.
    pub fn new(ssl: Ssl, transport: S) -> Result<Self, Error> {
        Ok(Self {
            engine: TlsEngine::new(ssl)?,
            transport,
            inbound: Vec::new(),
            inbound_offset: 0,
            outbound: Vec::new(),
            outbound_offset: 0,
            read_scratch: vec![0u8; CIPHER_CHUNK],
            read_waiter: None,
            write_waiter: None,
            pending_write_error: None,
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
    fn register_read_waiter(&mut self, cx: &Context<'_>) {
        register(&mut self.read_waiter, cx);
    }

    /// Register `cx`'s waker for the write direction, leaving the read
    /// direction's alone.
    fn register_write_waiter(&mut self, cx: &Context<'_>) {
        register(&mut self.write_waiter, cx);
    }

    /// Hand the transport's single write-waker slot back to the writer.
    ///
    /// A read poll that touches the transport's write side overwrites whatever
    /// waker a parked writer had registered there. Waking that writer makes it
    /// re-poll and re-register, so a reader that is subsequently dropped cannot
    /// leave the writer waiting on a waker nobody will ever fire.
    ///
    /// This is deliberately *not* a progress wake: it targets only the writer,
    /// never the reader, so it cannot form a no-progress wake loop.
    fn wake_writer(&mut self) {
        if let Some(waker) = self.write_waiter.take() {
            waker.wake();
        }
    }

    /// Wake both retained directions after observable progress.
    ///
    /// "Observable progress" means bytes actually moved, end of file was seen,
    /// or the session changed lifecycle state — never merely that a poll
    /// happened. The current task's own waker is skipped: this poll will either
    /// return `Ready` or register again before returning `Pending`, so waking
    /// it would only schedule a redundant poll.
    fn wake_progress(&mut self, cx: &Context<'_>) {
        wake_other(&mut self.read_waiter, cx);
        wake_other(&mut self.write_waiter, cx);
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
                return match self.poll_drain_outbound(cx) {
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
                match self.poll_drain_outbound(cx) {
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
            if let Poll::Ready(Err(e)) = self.poll_drain_outbound(cx) {
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
    /// Byte movement is observable progress, so retained waiters are woken even
    /// when the drain ultimately parks or fails.
    fn poll_drain_outbound(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        let mut moved = false;

        let outcome = loop {
            if self.outbound_len() == 0 {
                self.outbound.clear();
                self.outbound_offset = 0;
                break Poll::Ready(Ok(()));
            }
            match Pin::new(&mut self.transport)
                .poll_write(cx, &self.outbound[self.outbound_offset..])
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

    /// Drain the backlog on behalf of a *read*.
    ///
    /// Two rules distinguish this from [`Self::poll_drain_outbound`], and both
    /// exist so a read reports only read-side outcomes. A transport failure is
    /// latched for the write direction rather than returned, and a transport
    /// that is not ready costs the writer its registration, so the writer is
    /// woken to reclaim it.
    // Every read-path drain goes through here, so the shutdown and
    // terminal-write-failure skip guard the write half needs lands in one place.
    fn drain_for_read(&mut self, cx: &mut Context<'_>) -> Drain {
        if self.outbound_len() == 0 {
            return Drain::Complete;
        }
        match self.poll_drain_outbound(cx) {
            Poll::Ready(Ok(())) => Drain::Complete,
            Poll::Ready(Err(e)) => {
                if self.pending_write_error.is_none() {
                    self.pending_write_error = Some(e);
                }
                self.wake_writer();
                Drain::Failed
            }
            Poll::Pending => {
                self.wake_writer();
                Drain::Pending
            }
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
        // that has already failed or ended.
        let mut drain_failed = false;
        let mut eof_seen = false;

        loop {
            // A write's delivery is best-effort until flush, so residual
            // ciphertext must not be left stranded while this side waits on the
            // peer. The read never parks on this drain.
            if !drain_failed && self.drain_for_read(cx) == Drain::Failed {
                drain_failed = true;
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
                    if !drain_failed && self.outbound_len() > 0 {
                        match self.drain_for_read(cx) {
                            Drain::Complete => continue,
                            Drain::Pending => {
                                self.register_read_waiter(cx);
                                return Poll::Pending;
                            }
                            Drain::Failed => drain_failed = true,
                        }
                    }
                    // Either there was nothing to send after all, or the write
                    // side is broken and its error belongs to the writer. Fall
                    // through: only the peer can move this session now, and
                    // polling the read side is what gives this task a wake
                    // source it can trust.
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

/// Store `cx`'s waker, reusing the existing one when it is equivalent.
fn register(slot: &mut Option<Waker>, cx: &Context<'_>) {
    match slot {
        Some(existing) if existing.will_wake(cx.waker()) => {}
        _ => *slot = Some(cx.waker().clone()),
    }
}

/// Wake a retained waker unless it belongs to the task doing the waking.
fn wake_other(slot: &mut Option<Waker>, cx: &Context<'_>) {
    let Some(waker) = slot.take() else {
        return;
    };
    if !waker.will_wake(cx.waker()) {
        waker.wake();
    }
}
