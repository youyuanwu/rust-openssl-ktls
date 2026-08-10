//! Directional waker discipline for the tokio stream.
//!
//! Everything here is about D-E: the stream keeps a read waiter and a write
//! waiter, and one poll never discards the other direction's registration.
//!
//! The transport stores exactly one waker per direction, which is what a real
//! readiness transport does, so these schedules are not artificial: they are the
//! only orderings in which the single-slot constraint bites. The stream never
//! puts a caller's waker in that slot. It registers one stable waker of its own
//! for the transport's write side and keeps the two callers' wakers itself, so
//! no poll can displace another's registration and a delivered readiness wakes
//! whichever directions are parked. Cancelling either direction is therefore
//! harmless, which is what the stranding tests below check from both sides.
//!
//! Determinism comes from explicit `poll` calls against separately instrumented
//! wakers — A for the reader, B for the writer — never from waiting. Every wake
//! is provoked by a named action and asserted immediately afterwards, so an
//! assertion cannot pass because something else happened to run.
//! `tokio::time::timeout` appears only as a failure detector: a lost wakeup
//! fails the suite instead of hanging it.

mod common;

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, RawWaker, RawWakerVTable, Wake, Waker};
use std::time::Duration;

use common::certs;
use common::tokio_memory::{Controls, Event, MemoryStream, StatsHandle, duplex};
use openssl_io::tokio::SslStream;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::Notify;
use tokio::time::timeout;

/// Long enough that a working implementation never reaches it, short enough
/// that a broken one fails quickly.
const LIMIT: Duration = Duration::from_secs(5);

/// The budget for waiting on one specific wakeup, deliberately shorter than
/// [`LIMIT`] so a lost wake is reported by the assertion that names it rather
/// than by the enclosing timeout.
const WAKE_LIMIT: Duration = Duration::from_secs(2);

type Stream = SslStream<MemoryStream>;

/// A handshaken pair, with the client's control surface and instrumentation
/// retained after its transport was moved into the stream.
struct Pair {
    client: Stream,
    server: Stream,
    client_controls: Controls,
    client_stats: StatsHandle,
}

/// Build a connected, handshaken pair over memory, settled so that no
/// post-handshake housekeeping is left in flight.
async fn connected() -> Pair {
    let (c_ssl, s_ssl) = certs::engine_ssl_pair();
    let (c_tp, s_tp) = duplex();
    let client_controls = c_tp.controls();
    let client_stats = c_tp.stats();

    let mut client = SslStream::new(c_ssl, c_tp).unwrap();
    let mut server = SslStream::new(s_ssl, s_tp).unwrap();

    let (c, s) = timeout(LIMIT, async {
        tokio::join!(client.connect(), server.accept())
    })
    .await
    .expect("handshake timed out");
    c.expect("client handshake");
    s.expect("server handshake");

    settle(&mut client, &client_controls);

    Pair {
        client,
        server,
        client_controls,
        client_stats,
    }
}

/// Consume whatever the peer sent after the handshake.
///
/// OpenSSL emits session tickets there, and feeding them is *observable
/// progress*, which legitimately wakes both stored waiters. A schedule that
/// left them queued could mistake that housekeeping wake for the directional
/// wake under test, so every schedule starts from a transport with nothing
/// inbound pending.
fn settle(client: &mut Stream, controls: &Controls) {
    let (_idle, waker) = counting_waker();
    let mut cx = Context::from_waker(&waker);
    let mut storage = [0u8; 512];
    let mut buf = ReadBuf::new(&mut storage);
    assert!(
        Pin::new(client).poll_read(&mut cx, &mut buf).is_pending(),
        "the peer sent application data before the schedule began"
    );
    assert_eq!(
        controls.queued_inbound(),
        0,
        "inbound ciphertext was still queued after settling"
    );
}

/// A waker that records how often it was woken.
struct CountingWaker(AtomicUsize);

impl CountingWaker {
    fn count(&self) -> usize {
        self.0.load(Ordering::SeqCst)
    }
}

impl Wake for CountingWaker {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

fn counting_waker() -> (Arc<CountingWaker>, Waker) {
    let inner = Arc::new(CountingWaker(AtomicUsize::new(0)));
    let waker = Waker::from(inner.clone());
    (inner, waker)
}

/// A counting waker a test can *wait* on.
///
/// Asserting a counter immediately after an action proves a wake was delivered
/// synchronously, which is all the schedules above need. A schedule that must
/// prove a wake is delivered *at all* needs to block until it arrives, or a
/// lost wakeup would read as "not yet". `Notify::notify_one` stores a permit
/// when nobody is waiting, so the wait cannot miss a wake that already
/// happened.
struct SignalWaker {
    count: AtomicUsize,
    notify: Notify,
}

impl SignalWaker {
    fn count(&self) -> usize {
        self.count.load(Ordering::SeqCst)
    }

    /// Wait for the next wake, or fail the test if none arrives in time.
    async fn woken(&self, what: &str) {
        timeout(WAKE_LIMIT, self.notify.notified())
            .await
            .unwrap_or_else(|_| panic!("{what}"));
    }
}

impl Wake for SignalWaker {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.count.fetch_add(1, Ordering::SeqCst);
        self.notify.notify_one();
    }
}

fn signal_waker() -> (Arc<SignalWaker>, Waker) {
    let inner = Arc::new(SignalWaker {
        count: AtomicUsize::new(0),
        notify: Notify::new(),
    });
    let waker = Waker::from(inner.clone());
    (inner, waker)
}

/// Park a write behind a closed gate, so the stream holds this waker as its
/// write waiter and the transport holds the stream's stable waker.
///
/// The gate must already be closed and a first write already accepted, so that
/// admission finds ciphertext queued and refuses to enter OpenSSL at all.
fn park_write(client: &mut Stream, cx: &mut Context<'_>, data: &[u8]) {
    assert!(
        Pin::new(client).poll_write(cx, data).is_pending(),
        "a stalled transport must park the write rather than admit it"
    );
}

/// Poll a read once and assert it parked without touching the caller's buffer.
fn park_read(client: &mut Stream, cx: &mut Context<'_>) {
    let mut storage = [0xC7u8; 128];
    let mut buf = ReadBuf::new(&mut storage);
    assert!(
        Pin::new(client).poll_read(cx, &mut buf).is_pending(),
        "nothing has arrived, so the read must park"
    );
    assert_eq!(buf.filled().len(), 0, "a pending read filled the buffer");
    assert_eq!(
        storage, [0xC7u8; 128],
        "a pending read wrote into the buffer"
    );
}

/// Assert that the events recorded since the last reset contain no observable
/// inbound progress.
///
/// D-E wakes both waiters whenever bytes actually move, which is correct and
/// which would also satisfy a naive "the writer was woken" assertion. Requiring
/// the measured poll to have moved nothing is what leaves transport readiness
/// reaching the stable waker as the only possible explanation for the wake.
fn assert_made_no_progress(stats: &StatsHandle) {
    let events = stats.events();
    assert!(
        !events
            .iter()
            .any(|e| matches!(e, Event::Read(n) | Event::Write(n) if *n > 0)),
        "the measured poll moved bytes, so a wake proves nothing: {events:?}"
    );
}

/// SC-009, schedule 1. A read parks registering waker A; a write is polled
/// afterwards and parks registering waker B; the peer's data then arrives.
///
/// A is the waker that must fire. B must not: inbound readiness is no business
/// of the writer's, and a stream that wakes both on any transport event would
/// pass a weaker test while still churning the wrong task.
#[tokio::test]
async fn schedule_one_inbound_data_wakes_the_reader_and_not_the_writer() {
    timeout(LIMIT, async {
        let mut pair = connected().await;

        // Ciphertext the gate will not let out, so the *next* write has
        // something to park behind.
        pair.client_controls.close_write_gate();
        let first = b"queued behind the closed gate";
        let n = pair.client.write(first).await.expect("the first write");
        assert_eq!(n, first.len(), "TLS accepted the whole payload");

        let (a, waker_a) = counting_waker();
        let (b, waker_b) = counting_waker();
        let mut cx_a = Context::from_waker(&waker_a);
        let mut cx_b = Context::from_waker(&waker_b);

        park_read(&mut pair.client, &mut cx_a);
        assert_eq!(a.count(), 0, "parking must not wake immediately");

        // The write now parks too. Both directions are registered with the
        // stream; the transport's single slot holds the stream's stable waker.
        park_write(&mut pair.client, &mut cx_b, b"the second write");
        assert_eq!(b.count(), 0, "parking must not wake immediately");
        assert_eq!(
            a.count(),
            0,
            "polling the write direction disturbed the parked reader"
        );

        // Peer data arrives. Only the reader is waiting on it.
        pair.server.write_all(b"a reply").await.unwrap();
        pair.server.flush().await.unwrap();

        assert!(
            a.count() >= 1,
            "the transport was not holding the parked reader's own waker"
        );
        assert_eq!(
            b.count(),
            0,
            "inbound readiness woke the writer, which is waiting on the write side"
        );

        // And the read completes with exactly what the peer sent.
        let mut buf = [0u8; 64];
        let n = pair.client.read(&mut buf).await.expect("the resumed read");
        assert_eq!(&buf[..n], b"a reply");
    })
    .await
    .expect("schedule 1 timed out");
}

/// SC-009, schedule 2. A write parks registering waker B; a read is polled
/// afterwards and also touches the transport's write side; the gate then
/// reopens.
///
/// B is the waker that must fire, and it must fire *without the writer being
/// re-polled first*. That is the whole point of the stable transport-write
/// waker: the intervening read registers nothing of its own on the transport's
/// write side, so B's registration is still live when readiness arrives. A poll
/// that moves no bytes is required to wake nobody, so the read poll itself must
/// leave both counters alone.
#[tokio::test]
async fn schedule_two_the_parked_writer_is_woken_and_the_write_completes() {
    timeout(LIMIT, async {
        let mut pair = connected().await;
        pair.client_controls.close_write_gate();

        let first = b"the first payload";
        let n = pair.client.write(first).await.expect("the first write");
        assert_eq!(n, first.len());

        let (a, waker_a) = counting_waker();
        let (b, waker_b) = counting_waker();
        let mut cx_a = Context::from_waker(&waker_a);
        let mut cx_b = Context::from_waker(&waker_b);

        let second = b"the second payload";
        park_write(&mut pair.client, &mut cx_b, second);
        assert_eq!(b.count(), 0, "parking must not wake immediately");

        // The read's mandatory backlog drain polls the transport's write side
        // and finds it not ready. Nothing moves in either direction during that
        // poll, so nothing may be woken by it either.
        pair.client_stats.reset();
        park_read(&mut pair.client, &mut cx_a);
        assert_made_no_progress(&pair.client_stats);
        assert_eq!(a.count(), 0, "the reader woke itself");
        assert_eq!(
            b.count(),
            0,
            "a poll that moved no bytes woke the parked writer"
        );

        // Readiness arrives with the writer still parked exactly where it was:
        // it was never re-polled, so only a registration the read could not
        // displace can deliver this wake. Counted as a delta, so an earlier
        // stray wake could not stand in for this one.
        let before = b.count();
        pair.client_controls.open_write_gate();
        assert!(
            b.count() > before,
            "the read displaced the parked writer's claim on transport write \
             readiness"
        );

        // The write completes, and both payloads arrive in order.
        let n = pair
            .client
            .write(second)
            .await
            .expect("the write must complete once the transport reopens");
        assert_eq!(n, second.len());
        pair.client.flush().await.unwrap();

        let mut got = vec![0u8; first.len() + second.len()];
        pair.server.read_exact(&mut got).await.unwrap();
        let mut expected = first.to_vec();
        expected.extend_from_slice(second);
        assert_eq!(got, expected);
    })
    .await
    .expect("schedule 2 timed out");
}

/// The waker-theft regression, reader-cancelled direction. A reader touches the
/// transport's write side after a writer parked on it, and is then cancelled.
///
/// If the reader's own waker could reach the transport's single write slot, the
/// transport would be left holding a dead task's waker and reopening it would
/// wake nobody: the writer would hang with its ciphertext queued. The writer is
/// deliberately *not* re-polled between the cancellation and the reopening, so
/// only a registration the reader could never displace can carry the wake.
#[tokio::test]
async fn dropping_a_reader_cannot_strand_a_parked_writer() {
    timeout(LIMIT, async {
        let mut pair = connected().await;
        pair.client_controls.close_write_gate();

        let first = b"stranded ciphertext";
        assert_eq!(
            pair.client.write(first).await.expect("the first write"),
            first.len()
        );

        let (b, waker_b) = counting_waker();
        let mut cx_b = Context::from_waker(&waker_b);
        let second = b"the write that must survive the reader";
        park_write(&mut pair.client, &mut cx_b, second);
        assert_eq!(b.count(), 0);

        // A reader polls the same transport write side and is then cancelled
        // outright.
        let (a, waker_a) = counting_waker();
        pair.client_stats.reset();
        {
            let mut buf = [0u8; 64];
            let mut read = Box::pin(pair.client.read(&mut buf));
            let polled = read.as_mut().poll(&mut Context::from_waker(&waker_a));
            assert!(polled.is_pending(), "the read must park");
            // Dropped here, unpolled again: the waker it left behind is dead.
        }
        assert_made_no_progress(&pair.client_stats);
        assert_eq!(
            b.count(),
            0,
            "a poll that moved no bytes woke the parked writer"
        );
        assert_eq!(a.count(), 0);

        // Reopening reaches the writer even though it never re-registered.
        // Counted as a delta, so an earlier stray wake cannot stand in for it.
        let before = b.count();
        pair.client_controls.open_write_gate();
        assert!(
            b.count() > before,
            "the reopened transport woke the dropped reader instead of the writer"
        );

        assert_eq!(
            pair.client.write(second).await.expect("the parked write"),
            second.len()
        );
        pair.client.flush().await.unwrap();

        let mut got = vec![0u8; first.len() + second.len()];
        pair.server.read_exact(&mut got).await.unwrap();
        let mut expected = first.to_vec();
        expected.extend_from_slice(second);
        assert_eq!(got, expected);
    })
    .await
    .expect("the cancellation regression timed out");
}

/// Read-readiness isolation. With writes gated and a backlog queued, a parked
/// read must still be woken by inbound data.
///
/// The read path polls the transport's write side first, which is where a
/// plausible implementation stops: parking on write readiness alone would leave
/// the reader deaf to the peer for as long as the transport refuses writes.
/// Only a genuine engine flush obligation may do that, and there is none here.
#[tokio::test]
async fn a_reader_wakes_from_inbound_data_while_writes_stay_gated() {
    timeout(LIMIT, async {
        let mut pair = connected().await;
        pair.client_controls.close_write_gate();

        let queued = b"a backlog that cannot move";
        assert_eq!(
            pair.client.write(queued).await.expect("the write"),
            queued.len()
        );

        let (a, waker_a) = counting_waker();
        let mut buf = [0u8; 64];
        let mut read = Box::pin(pair.client.read(&mut buf));
        let polled = read.as_mut().poll(&mut Context::from_waker(&waker_a));
        assert!(
            polled.is_pending(),
            "nothing has arrived, so the read parks"
        );
        assert!(
            pair.client_controls.has_read_waker(),
            "the read parked without registering for inbound readiness"
        );

        // Writes are still gated; only the inbound direction moves.
        pair.server
            .write_all(b"inbound while writes are gated")
            .await
            .unwrap();
        pair.server.flush().await.unwrap();
        assert!(
            a.count() >= 1,
            "the parked reader was not woken by inbound data"
        );
        assert!(
            pair.client_controls.faults().write_gate_closed,
            "the gate reopened, so this proved nothing"
        );

        let n = read.await.expect("the resumed read");
        assert_eq!(&buf[..n], b"inbound while writes are gated");
    })
    .await
    .expect("the read-readiness regression timed out");
}

/// SC-009's third clause: a bidirectional, multi-record exchange through
/// `tokio::io::split`, with every half moved into its own spawned task.
///
/// Each direction sends far more than one TLS record, so the halves interleave
/// under a real scheduler rather than completing in one poll, and each side
/// verifies the other's payload byte for byte.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn split_halves_exchange_multiple_records_from_separate_tasks() {
    let pair = connected().await;
    let Pair { client, server, .. } = pair;

    let from_client: Vec<u8> = (0..120_000u32).map(|i| (i % 251) as u8).collect();
    let from_server: Vec<u8> = (0..97_000u32).map(|i| (i % 241) as u8).collect();

    let (mut client_read, mut client_write) = tokio::io::split(client);
    let (mut server_read, mut server_write) = tokio::io::split(server);

    let client_out = from_client.clone();
    let server_out = from_server.clone();

    let client_writer = tokio::spawn(async move {
        client_write.write_all(&client_out).await.unwrap();
        client_write.flush().await.unwrap();
        client_write.shutdown().await.unwrap();
    });
    let server_writer = tokio::spawn(async move {
        server_write.write_all(&server_out).await.unwrap();
        server_write.flush().await.unwrap();
        server_write.shutdown().await.unwrap();
    });
    let client_reader = tokio::spawn(async move {
        let mut got = Vec::new();
        client_read.read_to_end(&mut got).await.unwrap();
        got
    });
    let server_reader = tokio::spawn(async move {
        let mut got = Vec::new();
        server_read.read_to_end(&mut got).await.unwrap();
        got
    });

    let (cw, sw, cr, sr) = timeout(LIMIT, async {
        tokio::join!(client_writer, server_writer, client_reader, server_reader)
    })
    .await
    .expect("the split exchange timed out");

    cw.expect("the client's writer task");
    sw.expect("the server's writer task");
    assert_eq!(
        cr.expect("the client's reader task"),
        from_server,
        "the client received corrupted plaintext"
    );
    assert_eq!(
        sr.expect("the server's reader task"),
        from_client,
        "the server received corrupted plaintext"
    );
}

/// The anti-livelock invariant. A poll that moves no bytes wakes nobody.
///
/// D-E's wake-both rule is deliberately conditional on *observable progress*.
/// A binding that woke both waiters on entry or exit from every poll would
/// still pass the schedules above while spinning two tasks against each other
/// forever, so this asserts the negative directly: with the transport refusing
/// writes, nothing inbound, and no writer parked, repeated read polls leave
/// every counter at zero.
#[tokio::test]
async fn a_poll_that_makes_no_progress_wakes_nothing() {
    timeout(LIMIT, async {
        let mut pair = connected().await;
        pair.client_controls.close_write_gate();

        let queued = b"a backlog with nowhere to go";
        assert_eq!(
            pair.client.write(queued).await.expect("the write"),
            queued.len()
        );

        let (a, waker_a) = counting_waker();
        let (b, waker_b) = counting_waker();
        let mut cx_a = Context::from_waker(&waker_a);
        let mut cx_b = Context::from_waker(&waker_b);

        pair.client_stats.reset();
        for round in 0..3 {
            park_read(&mut pair.client, &mut cx_a);
            assert_eq!(a.count(), 0, "round {round}: the reader woke itself");
            assert_eq!(
                b.count(),
                0,
                "round {round}: a wake was delivered to a writer that was never parked"
            );
        }

        // The same for the write direction: a write that parks behind the gate
        // must not wake the reader that is parked on inbound readiness.
        park_write(&mut pair.client, &mut cx_b, b"another write");
        assert_eq!(a.count(), 0, "a parked write woke the reader");
        assert_eq!(b.count(), 0, "a parked write woke itself");

        assert_made_no_progress(&pair.client_stats);
    })
    .await
    .expect("the anti-livelock check timed out");
}

/// The waker-theft regression, writer-cancelled direction: the mirror image of
/// `dropping_a_reader_cannot_strand_a_parked_writer`, and the sequence that
/// FR-011b and FR-025 together forbid.
///
/// 1. A successful write leaves ciphertext queued behind a closed gate.
/// 2. A read polls, tries to drain that ciphertext, and parks with waker A.
/// 3. A *later* write polls with waker B and is then cancelled.
/// 4. The gate reopens with nothing inbound injected.
///
/// The only task that can move the session on now is the reader: it holds the
/// backlog the peer is waiting for, and the peer cannot reply until the backlog
/// arrives. So if step 3 could displace step 2's claim on transport write
/// readiness, step 4 would wake a dead task and the request would be stranded
/// forever — a genuine deadlock, not a slow path.
///
/// Nothing is injected inbound and the reader is never re-polled by hand: the
/// wait below returns only if the stream itself woke waker A.
#[tokio::test]
async fn a_cancelled_writer_cannot_strand_a_parked_reader() {
    timeout(LIMIT, async {
        let mut pair = connected().await;
        pair.client_controls.close_write_gate();

        // 1. The request is accepted by TLS but cannot reach the wire.
        let request = b"the request whose reply the reader is waiting for";
        assert_eq!(
            pair.client.write(request).await.expect("the request write"),
            request.len()
        );
        assert_eq!(
            pair.client_controls.queued_for_peer(),
            0,
            "the gate let the request through, so nothing is stranded"
        );

        // 2. The reader parks. Its drain of that backlog is the only reason it
        //    has any interest in transport write readiness.
        let (a, waker_a) = signal_waker();
        let mut cx_a = Context::from_waker(&waker_a);
        pair.client_stats.reset();
        park_read(&mut pair.client, &mut cx_a);
        assert_eq!(a.count(), 0, "parking must not wake immediately");

        // 3. A later write parks behind the same gate and is dropped where it
        //    stands, leaving a dead waker behind.
        let (b, waker_b) = counting_waker();
        {
            let mut write = Box::pin(pair.client.write(b"a write that is abandoned"));
            let polled = write.as_mut().poll(&mut Context::from_waker(&waker_b));
            assert!(polled.is_pending(), "the gated write must park");
        }
        assert_eq!(b.count(), 0, "parking must not wake immediately");
        assert_made_no_progress(&pair.client_stats);

        // 4. Transport write readiness, and nothing else: no inbound data, no
        //    re-poll of anything.
        pair.client_controls.open_write_gate();
        a.woken(
            "the cancelled writer took the parked reader's claim on transport \
             write readiness with it: the request is stranded and the reader \
             will never wake",
        )
        .await;

        // And the exchange completes: the stranded request reaches the peer and
        // the reply comes back.
        let reply = b"the reply that could not exist while the request was stuck";
        let (got, ()) = timeout(LIMIT, async {
            tokio::join!(
                async {
                    let mut buf = [0u8; 128];
                    let n = pair.client.read(&mut buf).await.expect("the resumed read");
                    buf[..n].to_vec()
                },
                async {
                    let mut got = vec![0u8; request.len()];
                    pair.server
                        .read_exact(&mut got)
                        .await
                        .expect("the peer never received the request");
                    assert_eq!(got, request, "the peer received the wrong request");
                    pair.server.write_all(reply).await.unwrap();
                    pair.server.flush().await.unwrap();
                }
            )
        })
        .await
        .expect("the request/reply exchange timed out");
        assert_eq!(got, reply, "the reader did not receive the peer's reply");
    })
    .await
    .expect("the cancelled-writer regression timed out");
}

/// Build a `Waker` whose `clone` and `drop` run `hook`.
///
/// `std::task::Wake` cannot express this: `Waker::from(Arc<W>)` clones and drops
/// the `Arc`, never user code. A hand-built vtable can, and the `Waker` contract
/// permits it — nothing says `clone` and `drop` are trivial, and a real
/// combinator may well wake something from either. So a registry that runs them
/// under its own lock is one re-entrant waker away from deadlocking.
fn reentrant_waker(hook: Arc<dyn Fn() + Send + Sync>) -> Waker {
    unsafe fn clone(data: *const ()) -> RawWaker {
        // SAFETY: `data` is the leaked `Arc` this vtable was built with, still
        // alive because the `Waker` owning it has not been dropped.
        let hook = unsafe { Arc::from_raw(data as *const HookFn) };
        (hook.0)();
        let cloned = hook.clone();
        std::mem::forget(hook);
        RawWaker::new(Arc::into_raw(cloned) as *const (), &VTABLE)
    }
    unsafe fn wake(data: *const ()) {
        // SAFETY: as above; this consumes the reference the waker owned.
        let hook = unsafe { Arc::from_raw(data as *const HookFn) };
        (hook.0)();
    }
    unsafe fn wake_by_ref(data: *const ()) {
        // SAFETY: as above, without consuming the reference.
        let hook = unsafe { Arc::from_raw(data as *const HookFn) };
        (hook.0)();
        std::mem::forget(hook);
    }
    unsafe fn drop_fn(data: *const ()) {
        // SAFETY: as above; releases the reference this waker held.
        let hook = unsafe { Arc::from_raw(data as *const HookFn) };
        (hook.0)();
    }
    static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, wake, wake_by_ref, drop_fn);

    let boxed = Arc::new(HookFn(hook));
    // SAFETY: the pointer comes from `Arc::into_raw` and the vtable above only
    // ever reconstitutes it with the matching `Arc::from_raw`.
    unsafe { Waker::from_raw(RawWaker::new(Arc::into_raw(boxed) as *const (), &VTABLE)) }
}

struct HookFn(Arc<dyn Fn() + Send + Sync>);

/// Registering a waker must not run caller code under the registry's lock.
///
/// The stream keeps one waker per direction behind a mutex, and the same mutex
/// is taken when the transport delivers write readiness. Cloning the incoming
/// waker, and dropping the one it displaces, therefore have to happen outside
/// the guard. A waker whose `clone`/`drop` wakes the stream would otherwise
/// re-enter that mutex and hang the task instead of failing it.
///
/// Driven on its own thread so a deadlock shows up as a failed assertion rather
/// than a hung suite.
#[tokio::test]
async fn registering_a_reentrant_waker_does_not_deadlock() {
    let (tx, rx) = std::sync::mpsc::channel();

    std::thread::spawn(move || {
        let body = async {
            let Pair {
                mut client,
                server,
                client_controls,
                ..
            } = connected().await;
            // Keep the peer alive; dropping it would close the transport and
            // make the read below fail instead of park.
            let _server = server;

            client_controls.close_write_gate();
            client.write_all(b"stranded").await.unwrap();

            // Park a read so the stream holds a registration, then re-poll with
            // a different waker so registration both clones the newcomer and
            // drops the one it displaces. Each of those fires the hook, which
            // wakes the stream's own stable transport waker.
            let reenter: Arc<dyn Fn() + Send + Sync> = {
                let controls = client_controls.clone();
                Arc::new(move || {
                    // Reaches the stream through the transport's retained
                    // registration, which is the stable waker under test.
                    controls.open_write_gate();
                    controls.close_write_gate();
                })
            };

            let mut buf = [0u8; 64];
            let mut read = Box::pin(client.read(&mut buf));
            assert!(
                read.as_mut()
                    .poll(&mut Context::from_waker(&reentrant_waker(reenter.clone())))
                    .is_pending(),
                "no reply can arrive while the gate is shut"
            );
            assert!(
                read.as_mut()
                    .poll(&mut Context::from_waker(&reentrant_waker(reenter)))
                    .is_pending(),
                "still nothing to read"
            );

            // Reaching here is the assertion: registration completed without
            // re-entering its own lock.
            drop(read);
        };

        ::tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(body);
        let _ = tx.send(());
    });

    rx.recv_timeout(std::time::Duration::from_secs(10))
        .expect("registering a re-entrant waker deadlocked the stream");
}
