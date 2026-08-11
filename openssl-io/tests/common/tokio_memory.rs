//! An in-memory duplex transport implementing tokio's I/O traits, with hooks
//! for injecting the failures a real socket makes hard to reproduce and with
//! the instrumentation the tokio stream's tests assert against.
//!
//! It exists for the same two reasons `common/memory.rs` does — a transport
//! with no operating-system handle proves the stream is genuinely
//! transport-agnostic, and conditions such as "the peer accepts nothing", "the
//! peer accepts one byte at a time" and "the connection dies without
//! `close_notify`" are timing-dependent over loopback TCP but deterministic
//! here.
//!
//! `tokio::io::duplex` is deliberately not used. It offers no per-call read or
//! write cap, no injectable errors, no reopenable write gate, and no
//! instrumentation, so the poll-count, byte-count, event-order and
//! drop-observation assertions the specification asks for cannot be expressed
//! against it.
//!
//! Three differences from the compio transport are structural rather than
//! incidental:
//!
//! * State is held in `Arc<Mutex<..>>` rather than `Rc<RefCell<..>>`, so an
//!   endpoint — and therefore each half of a `tokio::io::split` — is `Send` and
//!   can be moved into a spawned task.
//! * Each direction stores exactly one waker. That is precisely the constraint
//!   a real readiness transport imposes, and the constraint the stream's
//!   read/write waker discipline has to cope with, so it is not papered over by
//!   storing more.
//! * `AsyncWrite::poll_shutdown` closes only the write direction, mirroring
//!   `tokio::io::DuplexStream` (`tokio/src/io/util/mem.rs:166-172`). The peer
//!   drains what is queued and then observes a clean end of stream, while this
//!   endpoint keeps reading. Full-duplex teardown happens only on `Drop`.
//!
//! Locking rules, since these mutexes are shared with control handles that
//! other tasks hold: at most one lock is held at a time, no guard is alive
//! across a `Waker::wake` call, and no guard is ever handed back to caller
//! code — accessors return owned snapshots. Poisoned locks are recovered
//! explicitly rather than unwrapped, so a panicking test reports its own
//! failure instead of a cascade of secondary panics from every other task.

#![allow(dead_code)]

use std::collections::VecDeque;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll, Waker};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Recover the guard of a poisoned test mutex.
///
/// Poisoning here only ever means some other test task panicked while holding
/// the lock. That panic is the interesting failure; turning it into a second
/// panic in every task that touches the transport would hide it.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Store `cx`'s waker, reusing the existing one when it is equivalent.
fn register(slot: &mut Option<Waker>, cx: &Context<'_>) {
    match slot {
        Some(existing) if existing.will_wake(cx.waker()) => {}
        _ => *slot = Some(cx.waker().clone()),
    }
}

/// How an endpoint should misbehave.
///
/// Every knob is per-endpoint and applies to that endpoint's own operations:
/// `max_read` fragments what *this* endpoint reads, `max_write` truncates what
/// *this* endpoint writes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Faults {
    /// Deliver at most this many bytes per read, simulating fragmentation.
    pub max_read: Option<usize>,
    /// Accept at most this many bytes per write, simulating a short write.
    pub max_write: Option<usize>,
    /// Accept nothing; writes park until the gate is reopened.
    ///
    /// Unlike a closed write half this is reversible, which is what a test
    /// needs in order to force the stream into a pending write, cancel it, and
    /// then let delivery resume.
    pub write_gate_closed: bool,
    /// Accept at most this many further bytes in total, then park.
    ///
    /// Distinct from `max_write`, which caps a single call but lets the next
    /// one through. A budget is consumed across calls and, once exhausted,
    /// behaves exactly like a closed gate. It is what lets a test drive a
    /// transport that accepts *part* of a record and only then goes pending —
    /// the case where ciphertext is left stranded mid-write.
    pub write_budget: Option<usize>,
    /// Fail the next read with this error kind instead of returning data.
    pub read_error: Option<io::ErrorKind>,
    /// Fail the next write with this error kind.
    pub write_error: Option<io::ErrorKind>,
}

/// One observable transport operation, recorded in call order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    /// A read poll delivered `n` bytes. `n` is zero only for an empty buffer.
    Read(usize),
    /// A read poll observed a drained, closed channel: clean end of stream.
    ReadEof,
    /// A read poll parked because no bytes were available.
    ReadPending,
    /// A read poll returned an injected error.
    ReadError,
    /// A write poll accepted `n` bytes.
    Write(usize),
    /// A write poll parked because the write gate was closed.
    WritePending,
    /// A write poll failed, either injected or because the half is closed.
    WriteError,
    /// `poll_flush` was called.
    Flush,
    /// `poll_shutdown` closed the write direction.
    Shutdown,
}

impl Event {
    /// Whether this event came from the inbound direction.
    pub fn is_read(self) -> bool {
        matches!(
            self,
            Event::Read(_) | Event::ReadEof | Event::ReadPending | Event::ReadError
        )
    }

    /// Whether this event came from the outbound direction.
    pub fn is_write(self) -> bool {
        matches!(
            self,
            Event::Write(_) | Event::WritePending | Event::WriteError
        )
    }

    /// Whether this event actually handed bytes to the peer.
    pub fn delivered_bytes(self) -> bool {
        matches!(self, Event::Write(n) if n > 0)
    }
}

/// Instrumentation for one endpoint.
#[derive(Debug, Default)]
struct Stats {
    read_polls: usize,
    write_polls: usize,
    bytes_read: usize,
    bytes_written: usize,
    events: Vec<Event>,
}

/// One direction of the pair: a byte queue plus one waker per side.
#[derive(Default)]
struct Channel {
    buf: VecDeque<u8>,
    /// The writing side has gone away; readers see end of stream once drained.
    closed: bool,
    /// Waker of the task reading *out of* this channel.
    read_waker: Option<Waker>,
    /// Waker of the task writing *into* this channel.
    write_waker: Option<Waker>,
}

/// One end of an in-memory duplex pair.
///
/// Implements tokio's `AsyncRead` and `AsyncWrite` and is `Unpin` and `Send`,
/// so `tokio::io::split` works on it and either half can be moved into a
/// spawned task.
pub struct MemoryStream {
    /// Bytes this endpoint reads from; the peer writes into it.
    rx: Arc<Mutex<Channel>>,
    /// Bytes this endpoint writes into; the peer reads from it.
    tx: Arc<Mutex<Channel>>,
    faults: Arc<Mutex<Faults>>,
    stats: Arc<Mutex<Stats>>,
    drops: Arc<AtomicUsize>,
}

/// Create a connected pair of endpoints.
pub fn duplex() -> (MemoryStream, MemoryStream) {
    let a = Arc::new(Mutex::new(Channel::default()));
    let b = Arc::new(Mutex::new(Channel::default()));
    (
        MemoryStream {
            rx: a.clone(),
            tx: b.clone(),
            faults: Arc::new(Mutex::new(Faults::default())),
            stats: Arc::new(Mutex::new(Stats::default())),
            drops: Arc::new(AtomicUsize::new(0)),
        },
        MemoryStream {
            rx: b,
            tx: a,
            faults: Arc::new(Mutex::new(Faults::default())),
            stats: Arc::new(Mutex::new(Stats::default())),
            drops: Arc::new(AtomicUsize::new(0)),
        },
    )
}

impl MemoryStream {
    /// A cloneable handle for driving this endpoint's faults, gate, and
    /// half-close from anywhere, including while an operation is parked.
    pub fn controls(&self) -> Controls {
        Controls {
            rx: self.rx.clone(),
            tx: self.tx.clone(),
            faults: self.faults.clone(),
        }
    }

    /// A cloneable read-only handle to this endpoint's instrumentation.
    ///
    /// It outlives the stream, so counters and the event log remain readable
    /// after a test drops the transport.
    pub fn stats(&self) -> StatsHandle {
        StatsHandle {
            stats: self.stats.clone(),
        }
    }

    /// A handle that observes this endpoint being dropped.
    pub fn drop_watch(&self) -> DropWatch {
        DropWatch {
            drops: self.drops.clone(),
        }
    }

    pub fn set_faults(&self, faults: Faults) {
        *lock(&self.faults) = faults;
    }

    pub fn faults(&self) -> Faults {
        *lock(&self.faults)
    }

    /// Close the write direction abruptly, as a reset would.
    ///
    /// The peer reads whatever was already buffered and then end of stream,
    /// with no TLS `close_notify` — exactly the truncation case. This
    /// endpoint's read direction is untouched.
    pub fn close_write(&self) {
        self.controls().close_write();
    }

    fn record(&self, event: Event) {
        let mut stats = lock(&self.stats);
        match event {
            Event::Read(n) => stats.bytes_read += n,
            Event::Write(n) => stats.bytes_written += n,
            _ => {}
        }
        stats.events.push(event);
    }

    fn count_read_poll(&self) {
        lock(&self.stats).read_polls += 1;
    }

    fn count_write_poll(&self) {
        lock(&self.stats).write_polls += 1;
    }
}

impl Drop for MemoryStream {
    /// Full-duplex teardown, mirroring `tokio::io::DuplexStream::drop`
    /// (`tokio/src/io/util/mem.rs:175-181`): the peer's reads see end of stream
    /// and the peer's writes see a broken pipe.
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::SeqCst);

        let peer_reader = {
            let mut tx = lock(&self.tx);
            tx.closed = true;
            tx.read_waker.take()
        };
        if let Some(waker) = peer_reader {
            waker.wake();
        }

        let peer_writer = {
            let mut rx = lock(&self.rx);
            rx.closed = true;
            rx.write_waker.take()
        };
        if let Some(waker) = peer_writer {
            waker.wake();
        }
    }
}

/// Deterministic control surface for one endpoint.
///
/// Cheap to clone and `Send`, so a test can hold it while the endpoint itself
/// has been split or moved into another task.
#[derive(Clone)]
pub struct Controls {
    rx: Arc<Mutex<Channel>>,
    tx: Arc<Mutex<Channel>>,
    faults: Arc<Mutex<Faults>>,
}

impl Controls {
    pub fn faults(&self) -> Faults {
        *lock(&self.faults)
    }

    pub fn set_faults(&self, faults: Faults) {
        *lock(&self.faults) = faults;
    }

    /// Mutate the fault set in place.
    pub fn update<F: FnOnce(&mut Faults)>(&self, f: F) {
        f(&mut lock(&self.faults));
    }

    pub fn set_max_read(&self, cap: Option<usize>) {
        self.update(|f| f.max_read = cap);
    }

    pub fn set_max_write(&self, cap: Option<usize>) {
        self.update(|f| f.max_write = cap);
    }

    /// Arm a one-shot read failure.
    pub fn inject_read_error(&self, kind: io::ErrorKind) {
        self.update(|f| f.read_error = Some(kind));
    }

    /// Arm a one-shot write failure.
    pub fn inject_write_error(&self, kind: io::ErrorKind) {
        self.update(|f| f.write_error = Some(kind));
    }

    /// Stop accepting writes. Writes park instead of failing, so the endpoint
    /// stays usable and the gate can be reopened later.
    pub fn close_write_gate(&self) {
        self.update(|f| f.write_gate_closed = true);
    }

    /// Accept writes again and wake the retained writer, if any.
    ///
    /// The wake is the point of the gate: a writer parked behind it must make
    /// progress without anything else poking the transport.
    pub fn open_write_gate(&self) {
        self.update(|f| {
            f.write_gate_closed = false;
            f.write_budget = None;
        });
        let writer = lock(&self.tx).write_waker.take();
        if let Some(waker) = writer {
            waker.wake();
        }
    }

    /// Accept at most `bytes` further bytes in total, then park as if gated.
    ///
    /// Use this to strand ciphertext *mid-record*: the transport takes a
    /// prefix and only then goes pending, which is the case a closed gate
    /// cannot produce because it accepts nothing at all.
    pub fn set_write_budget(&self, bytes: Option<usize>) {
        self.update(|f| f.write_budget = bytes);
    }

    /// Close only the write direction: the peer drains, then sees clean end of
    /// stream. This endpoint's read direction stays usable.
    pub fn close_write(&self) {
        let reader = {
            let mut tx = lock(&self.tx);
            tx.closed = true;
            tx.read_waker.take()
        };
        if let Some(waker) = reader {
            waker.wake();
        }
    }

    /// Push bytes straight into this endpoint's inbound queue and wake its
    /// reader, without going through the peer.
    ///
    /// This is how a test injects peer data at an exact point in a waker
    /// schedule.
    pub fn inject_inbound(&self, data: &[u8]) {
        let reader = {
            let mut rx = lock(&self.rx);
            rx.buf.extend(data);
            rx.read_waker.take()
        };
        if let Some(waker) = reader {
            waker.wake();
        }
    }

    /// Whether this endpoint currently has a reader parked on inbound data.
    pub fn has_read_waker(&self) -> bool {
        lock(&self.rx).read_waker.is_some()
    }

    /// Whether this endpoint currently has a writer parked on the gate.
    pub fn has_write_waker(&self) -> bool {
        lock(&self.tx).write_waker.is_some()
    }

    /// Whether this endpoint's write direction has been closed.
    pub fn write_closed(&self) -> bool {
        lock(&self.tx).closed
    }

    /// Bytes queued for the peer but not yet read by it.
    pub fn queued_for_peer(&self) -> usize {
        lock(&self.tx).buf.len()
    }

    /// A copy of everything queued for the peer, leaving it in place.
    ///
    /// Lets a test assert on what did — and did not — reach the wire without
    /// consuming it.
    pub fn peek_queued_for_peer(&self) -> Vec<u8> {
        lock(&self.tx).buf.iter().copied().collect()
    }

    /// Bytes queued for this endpoint but not yet read by it.
    pub fn queued_inbound(&self) -> usize {
        lock(&self.rx).buf.len()
    }
}

/// Read-only view of one endpoint's instrumentation.
#[derive(Clone)]
pub struct StatsHandle {
    stats: Arc<Mutex<Stats>>,
}

impl StatsHandle {
    pub fn read_polls(&self) -> usize {
        lock(&self.stats).read_polls
    }

    pub fn write_polls(&self) -> usize {
        lock(&self.stats).write_polls
    }

    pub fn bytes_read(&self) -> usize {
        lock(&self.stats).bytes_read
    }

    pub fn bytes_written(&self) -> usize {
        lock(&self.stats).bytes_written
    }

    /// The ordered operation log.
    pub fn events(&self) -> Vec<Event> {
        lock(&self.stats).events.clone()
    }

    /// Position of the first inbound event, if any.
    pub fn first_read_position(&self) -> Option<usize> {
        lock(&self.stats).events.iter().position(|e| e.is_read())
    }

    /// Position of the first outbound event, if any.
    pub fn first_write_position(&self) -> Option<usize> {
        lock(&self.stats).events.iter().position(|e| e.is_write())
    }

    /// Position of the first write that actually handed bytes to the peer.
    pub fn first_delivering_write_position(&self) -> Option<usize> {
        lock(&self.stats)
            .events
            .iter()
            .position(|e| e.delivered_bytes())
    }

    /// Clear counters and the log, so a phase of a test can be measured in
    /// isolation from the handshake that preceded it.
    pub fn reset(&self) {
        *lock(&self.stats) = Stats::default();
    }
}

/// Observes endpoint drops. Outlives the endpoint it watches.
#[derive(Clone)]
pub struct DropWatch {
    drops: Arc<AtomicUsize>,
}

impl DropWatch {
    pub fn is_dropped(&self) -> bool {
        self.count() > 0
    }

    pub fn count(&self) -> usize {
        self.drops.load(Ordering::SeqCst)
    }
}

impl AsyncRead for MemoryStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.count_read_poll();

        if let Some(kind) = lock(&this.faults).read_error.take() {
            this.record(Event::ReadError);
            return Poll::Ready(Err(io::Error::from(kind)));
        }

        let capacity = buf.remaining();
        if capacity == 0 {
            this.record(Event::Read(0));
            return Poll::Ready(Ok(()));
        }

        let limit = lock(&this.faults).max_read.unwrap_or(usize::MAX);

        enum Outcome {
            Data(Vec<u8>),
            Eof,
            Park,
        }

        let outcome = {
            let mut rx = lock(&this.rx);
            if rx.buf.is_empty() {
                if rx.closed {
                    Outcome::Eof
                } else {
                    register(&mut rx.read_waker, cx);
                    Outcome::Park
                }
            } else {
                let n = rx.buf.len().min(capacity).min(limit);
                Outcome::Data(rx.buf.drain(..n).collect())
            }
        };

        match outcome {
            Outcome::Data(bytes) => {
                buf.put_slice(&bytes);
                this.record(Event::Read(bytes.len()));
                Poll::Ready(Ok(()))
            }
            // A closed, drained channel is a clean end of stream, and stays
            // one for every later poll.
            Outcome::Eof => {
                this.record(Event::ReadEof);
                Poll::Ready(Ok(()))
            }
            Outcome::Park => {
                this.record(Event::ReadPending);
                Poll::Pending
            }
        }
    }
}

impl AsyncWrite for MemoryStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.count_write_poll();

        let (injected, gated, limit) = {
            let mut faults = lock(&this.faults);
            let budget_spent = faults.write_budget == Some(0);
            (
                faults.write_error.take(),
                faults.write_gate_closed || budget_spent,
                faults
                    .max_write
                    .unwrap_or(usize::MAX)
                    .min(faults.write_budget.unwrap_or(usize::MAX)),
            )
        };

        if let Some(kind) = injected {
            this.record(Event::WriteError);
            return Poll::Ready(Err(io::Error::from(kind)));
        }

        // Checked before the empty-buffer short circuit, matching the compio
        // transport's `stall_writes` ordering: a gated endpoint accepts
        // nothing at all.
        if gated {
            register(&mut lock(&this.tx).write_waker, cx);
            this.record(Event::WritePending);
            return Poll::Pending;
        }

        if data.is_empty() {
            this.record(Event::Write(0));
            return Poll::Ready(Ok(0));
        }

        let (accepted, peer_reader) = {
            let mut tx = lock(&this.tx);
            if tx.closed {
                (None, None)
            } else {
                let n = data.len().min(limit);
                tx.buf.extend(&data[..n]);
                (Some(n), tx.read_waker.take())
            }
        };

        let Some(n) = accepted else {
            this.record(Event::WriteError);
            return Poll::Ready(Err(io::Error::from(io::ErrorKind::BrokenPipe)));
        };

        if let Some(waker) = peer_reader {
            waker.wake();
        }
        if let Some(budget) = lock(&this.faults).write_budget.as_mut() {
            *budget -= n;
        }
        this.record(Event::Write(n));
        Poll::Ready(Ok(n))
    }

    /// Nothing is buffered on this side of the queue, so a flush has only to be
    /// observable.
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().record(Event::Flush);
        Poll::Ready(Ok(()))
    }

    /// Half-close, mirroring `tokio::io::DuplexStream::poll_shutdown`
    /// (`tokio/src/io/util/mem.rs:166-172`).
    ///
    /// Only the write direction closes. The peer drains what is queued and
    /// then reads a clean end of stream, while this endpoint's read direction
    /// remains usable — which is what makes a stream half-shutdown observable
    /// without a socket.
    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.record(Event::Shutdown);
        this.controls().close_write();
        Poll::Ready(Ok(()))
    }
}
