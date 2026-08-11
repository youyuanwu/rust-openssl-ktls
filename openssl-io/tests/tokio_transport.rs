//! Tests for the tokio in-memory transport itself, with no TLS involved.
//!
//! If the fault hooks and instrumentation do not behave as advertised here,
//! every later tokio stream test that relies on them is worthless, so they are
//! verified in isolation first. This is the tokio counterpart of
//! `transport.rs`; the first seven tests are named after their compio
//! originals, and the rest cover the controls and instrumentation the compio
//! transport does not have.
//!
//! Parking is detected by polling a future once against a counting waker, not
//! by waiting. `tokio::time::timeout` appears only as a failure detector, so a
//! regression fails the suite instead of hanging it.

mod common;

use std::future::Future;
use std::pin::pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Wake, Waker};
use std::time::Duration;

use common::tokio_memory::{Event, Faults, MemoryStream, duplex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Long enough that a working implementation never reaches it, short enough
/// that a broken one fails quickly.
const LIMIT: Duration = Duration::from_secs(5);

/// A waker that records how often it was woken.
struct CountingWaker(AtomicUsize);

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

fn wakes(counter: &Arc<CountingWaker>) -> usize {
    counter.0.load(Ordering::SeqCst)
}

/// Poll `fut` exactly once and assert it parked, returning its waker's counter.
///
/// This is the deterministic alternative to "wait a while and see": one poll,
/// one observation, no clock involved.
fn assert_parks<F: Future>(fut: &mut std::pin::Pin<&mut F>) -> Arc<CountingWaker> {
    let (counter, waker) = counting_waker();
    let mut cx = Context::from_waker(&waker);
    assert!(
        fut.as_mut().poll(&mut cx).is_pending(),
        "expected the operation to park"
    );
    assert_eq!(wakes(&counter), 0, "parking must not wake immediately");
    counter
}

#[tokio::test]
async fn round_trips_bytes_in_both_directions() {
    let (mut a, mut b) = duplex();

    assert_eq!(a.write(b"ping").await.unwrap(), 4);
    let mut buf = [0u8; 16];
    let n = tokio::time::timeout(LIMIT, b.read(&mut buf))
        .await
        .expect("read timed out")
        .unwrap();
    assert_eq!(&buf[..n], b"ping");

    assert_eq!(b.write(b"pong").await.unwrap(), 4);
    let n = tokio::time::timeout(LIMIT, a.read(&mut buf))
        .await
        .expect("read timed out")
        .unwrap();
    assert_eq!(&buf[..n], b"pong");
}

#[tokio::test]
async fn max_read_fragments_delivery() {
    let (mut a, mut b) = duplex();
    b.set_faults(Faults {
        max_read: Some(3),
        ..Default::default()
    });

    assert_eq!(a.write(b"abcdefghij").await.unwrap(), 10);

    // The reader is capped at three bytes per call regardless of what is
    // buffered or how large its own buffer is.
    let mut got = Vec::new();
    while got.len() < 10 {
        let mut buf = [0u8; 64];
        let n = tokio::time::timeout(LIMIT, b.read(&mut buf))
            .await
            .expect("read timed out")
            .unwrap();
        assert!(n > 0 && n <= 3, "expected a capped read, got {n}");
        got.extend_from_slice(&buf[..n]);
    }
    assert_eq!(&got, b"abcdefghij");
}

#[tokio::test]
async fn max_write_produces_short_writes() {
    let (mut a, mut b) = duplex();
    a.set_faults(Faults {
        max_write: Some(4),
        ..Default::default()
    });

    let n = a.write(&[7u8; 100]).await.unwrap();
    assert_eq!(n, 4, "writer should accept only its cap");

    let mut buf = [0u8; 100];
    let n = tokio::time::timeout(LIMIT, b.read(&mut buf))
        .await
        .expect("read timed out")
        .unwrap();
    assert_eq!(n, 4);
}

#[tokio::test]
async fn close_write_yields_clean_end_of_stream_after_draining() {
    let (mut a, mut b) = duplex();

    assert_eq!(a.write(b"tail").await.unwrap(), 4);
    a.close_write();

    // Buffered bytes arrive first...
    let mut buf = [0u8; 16];
    let n = tokio::time::timeout(LIMIT, b.read(&mut buf))
        .await
        .expect("read timed out")
        .unwrap();
    assert_eq!(&buf[..n], b"tail");

    // ...then end of stream, repeatedly and without error.
    for _ in 0..2 {
        let n = tokio::time::timeout(LIMIT, b.read(&mut buf))
            .await
            .expect("read timed out")
            .unwrap();
        assert_eq!(n, 0);
    }
}

#[tokio::test]
async fn injected_errors_surface_once() {
    let (mut a, mut b) = duplex();
    b.controls()
        .inject_read_error(std::io::ErrorKind::ConnectionReset);

    let mut buf = [0u8; 16];
    let err = b.read(&mut buf).await.unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::ConnectionReset);

    // The fault is one-shot, so normal operation resumes.
    assert_eq!(a.write(b"ok").await.unwrap(), 2);
    let n = tokio::time::timeout(LIMIT, b.read(&mut buf))
        .await
        .expect("read timed out")
        .unwrap();
    assert_eq!(n, 2);

    // The same holds for the write direction.
    a.controls()
        .inject_write_error(std::io::ErrorKind::BrokenPipe);
    let err = a.write(b"nope").await.unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::BrokenPipe);
    assert_eq!(a.write(b"fine").await.unwrap(), 4);
}

/// A gated write must stay pending rather than reporting zero progress.
#[tokio::test]
async fn gated_writes_never_complete() {
    let (mut a, _b) = duplex();
    a.controls().close_write_gate();

    let mut write = pin!(a.write(&[1u8; 16]));
    assert_parks(&mut write);

    // And it stays parked: the gate is not a transient condition.
    let outcome = tokio::time::timeout(Duration::from_millis(50), write).await;
    assert!(outcome.is_err(), "gated write should not have completed");
}

#[tokio::test]
async fn reads_park_until_data_arrives() {
    let (mut a, mut b) = duplex();

    // No data yet: the read must park, not spin or return zero.
    let mut buf = [0u8; 8];
    {
        let mut read = pin!(b.read(&mut buf));
        assert_parks(&mut read);
    }

    assert_eq!(a.write(b"late").await.unwrap(), 4);

    let n = tokio::time::timeout(LIMIT, b.read(&mut buf))
        .await
        .expect("read timed out")
        .unwrap();
    assert_eq!(&buf[..n], b"late");
}

#[tokio::test]
async fn reopening_the_write_gate_wakes_the_retained_writer() {
    let (mut a, mut b) = duplex();
    let controls = a.controls();
    controls.close_write_gate();

    let mut write = pin!(a.write(b"gated"));
    let counter = assert_parks(&mut write);
    assert!(controls.has_write_waker(), "the writer must be retained");

    controls.open_write_gate();
    assert_eq!(
        wakes(&counter),
        1,
        "reopening the gate must wake the retained writer"
    );

    let n = tokio::time::timeout(LIMIT, write)
        .await
        .expect("write timed out")
        .unwrap();
    assert_eq!(n, 5);

    let mut buf = [0u8; 8];
    let n = tokio::time::timeout(LIMIT, b.read(&mut buf))
        .await
        .expect("read timed out")
        .unwrap();
    assert_eq!(&buf[..n], b"gated");
}

#[tokio::test]
async fn injected_inbound_wakes_the_retained_reader() {
    let (_a, mut b) = duplex();
    let controls = b.controls();

    let mut buf = [0u8; 8];
    let mut read = pin!(b.read(&mut buf));
    let counter = assert_parks(&mut read);
    assert!(controls.has_read_waker(), "the reader must be retained");

    controls.inject_inbound(b"peer");
    assert_eq!(
        wakes(&counter),
        1,
        "injected inbound data must wake the retained reader"
    );

    let n = tokio::time::timeout(LIMIT, read)
        .await
        .expect("read timed out")
        .unwrap();
    assert_eq!(&buf[..n], b"peer");
}

/// The two directions store wakers independently: parking a reader must not
/// disturb a parked writer, and vice versa.
#[tokio::test]
async fn read_and_write_wakers_are_stored_separately() {
    let (mut a, _b) = duplex();
    let controls = a.controls();
    controls.close_write_gate();

    let (a_read, a_write) = tokio::io::split(&mut a);
    let mut reader = pin!(async move {
        let mut half = a_read;
        let mut buf = [0u8; 8];
        tokio::io::AsyncReadExt::read(&mut half, &mut buf).await
    });
    let mut writer = pin!(async move {
        let mut half = a_write;
        half.write(b"gated").await
    });

    let write_counter = assert_parks(&mut writer);
    let read_counter = assert_parks(&mut reader);

    assert!(controls.has_read_waker());
    assert!(
        controls.has_write_waker(),
        "parking a reader must not evict the stored writer"
    );

    controls.open_write_gate();
    assert_eq!(wakes(&write_counter), 1);
    assert_eq!(
        wakes(&read_counter),
        0,
        "reopening the write gate must not wake the reader"
    );

    controls.inject_inbound(b"data");
    assert_eq!(wakes(&read_counter), 1);
}

#[tokio::test]
async fn poll_counters_and_byte_counters_track_traffic() {
    let (mut a, mut b) = duplex();
    let a_stats = a.stats();
    let b_stats = b.stats();

    // Nothing has been polled yet, which is the state a pre-handshake
    // rejection has to preserve.
    assert_eq!(a_stats.read_polls(), 0);
    assert_eq!(a_stats.write_polls(), 0);
    assert_eq!(a_stats.bytes_written(), 0);
    assert_eq!(b_stats.read_polls(), 0);
    assert_eq!(b_stats.bytes_read(), 0);

    assert_eq!(a.write(b"12345").await.unwrap(), 5);
    assert_eq!(a_stats.write_polls(), 1);
    assert_eq!(a_stats.bytes_written(), 5);
    assert_eq!(a_stats.read_polls(), 0, "writing must not poll for reads");

    let mut buf = [0u8; 16];
    let n = tokio::time::timeout(LIMIT, b.read(&mut buf))
        .await
        .expect("read timed out")
        .unwrap();
    assert_eq!(n, 5);
    assert_eq!(b_stats.read_polls(), 1);
    assert_eq!(b_stats.bytes_read(), 5);

    // A parked poll still counts as a poll but moves no bytes.
    {
        let mut read = pin!(b.read(&mut buf));
        assert_parks(&mut read);
    }
    assert_eq!(b_stats.read_polls(), 2);
    assert_eq!(b_stats.bytes_read(), 5);

    a_stats.reset();
    assert_eq!(a_stats.write_polls(), 0);
    assert_eq!(a_stats.bytes_written(), 0);
    assert!(a_stats.events().is_empty());
}

#[tokio::test]
async fn the_event_log_preserves_operation_order() {
    let (mut a, mut b) = duplex();
    let stats = a.stats();

    // A send, then a read that has to wait, then the reply: the shape a
    // handshake step has, where the outbound bytes must precede the first
    // inbound poll.
    assert_eq!(a.write(b"req").await.unwrap(), 3);
    let mut buf = [0u8; 16];
    {
        let mut read = pin!(a.read(&mut buf));
        assert_parks(&mut read);
    }
    assert_eq!(b.write(b"resp").await.unwrap(), 4);
    let n = tokio::time::timeout(LIMIT, a.read(&mut buf))
        .await
        .expect("read timed out")
        .unwrap();
    assert_eq!(&buf[..n], b"resp");

    a.flush().await.unwrap();

    assert_eq!(
        stats.events(),
        vec![
            Event::Write(3),
            Event::ReadPending,
            Event::Read(4),
            Event::Flush,
        ]
    );
    assert_eq!(stats.first_delivering_write_position(), Some(0));
    assert_eq!(stats.first_read_position(), Some(1));
    assert!(
        stats.first_delivering_write_position() < stats.first_read_position(),
        "bytes must go out before the first inbound poll"
    );

    // Failures are logged in order too, and are distinguishable from success.
    let stats_b = b.stats();
    stats_b.reset();
    b.controls().inject_write_error(std::io::ErrorKind::Other);
    assert!(b.write(b"x").await.is_err());
    b.controls()
        .inject_read_error(std::io::ErrorKind::ConnectionReset);
    assert!(b.read(&mut buf).await.is_err());
    assert_eq!(stats_b.events(), vec![Event::WriteError, Event::ReadError]);
}

#[tokio::test]
async fn shutdown_closes_only_the_write_direction() {
    let (mut a, mut b) = duplex();

    assert_eq!(a.write(b"last").await.unwrap(), 4);
    a.shutdown().await.unwrap();
    assert!(a.controls().write_closed());

    // The peer drains, then sees a clean end of stream.
    let mut buf = [0u8; 16];
    let n = tokio::time::timeout(LIMIT, b.read(&mut buf))
        .await
        .expect("read timed out")
        .unwrap();
    assert_eq!(&buf[..n], b"last");
    let n = tokio::time::timeout(LIMIT, b.read(&mut buf))
        .await
        .expect("read timed out")
        .unwrap();
    assert_eq!(n, 0, "peer should observe clean end of stream");

    // The shut-down endpoint's own read direction is still live.
    assert_eq!(b.write(b"reply").await.unwrap(), 5);
    let n = tokio::time::timeout(LIMIT, a.read(&mut buf))
        .await
        .expect("read timed out")
        .unwrap();
    assert_eq!(&buf[..n], b"reply");

    assert_eq!(a.stats().events().last().copied(), Some(Event::Read(5)));
}

#[tokio::test]
async fn writing_to_a_closed_half_is_a_broken_pipe() {
    let (mut a, mut b) = duplex();
    b.shutdown().await.unwrap();

    // `b` closed the direction `a` reads from, so `a`'s reads end cleanly
    // while `b`'s own writes are refused.
    let mut buf = [0u8; 8];
    let n = tokio::time::timeout(LIMIT, a.read(&mut buf))
        .await
        .expect("read timed out")
        .unwrap();
    assert_eq!(n, 0);

    let err = b.write(b"after").await.unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::BrokenPipe);
}

#[tokio::test]
async fn dropping_an_endpoint_is_observable_and_tears_down_both_directions() {
    let (a, mut b) = duplex();
    let watch = a.drop_watch();
    let a_controls = a.controls();
    assert!(!watch.is_dropped());

    let mut a = a;
    assert_eq!(a.write(b"bye").await.unwrap(), 3);
    drop(a);

    assert!(watch.is_dropped(), "the drop must be observable");
    assert_eq!(watch.count(), 1);

    // Queued bytes still arrive, then end of stream — truncation with no
    // orderly closure of its own.
    let mut buf = [0u8; 16];
    let n = tokio::time::timeout(LIMIT, b.read(&mut buf))
        .await
        .expect("read timed out")
        .unwrap();
    assert_eq!(&buf[..n], b"bye");
    let n = tokio::time::timeout(LIMIT, b.read(&mut buf))
        .await
        .expect("read timed out")
        .unwrap();
    assert_eq!(n, 0);

    // And the peer's writes now fail, unlike after a half-close.
    let err = b.write(b"hello?").await.unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::BrokenPipe);

    // Control and instrumentation handles outlive the endpoint.
    assert!(a_controls.write_closed());
}

#[tokio::test]
async fn dropping_wakes_a_parked_peer_reader() {
    let (a, mut b) = duplex();
    let mut buf = [0u8; 8];
    let mut read = pin!(b.read(&mut buf));
    let counter = assert_parks(&mut read);

    drop(a);
    assert_eq!(wakes(&counter), 1, "drop must wake the parked peer reader");

    let n = tokio::time::timeout(LIMIT, read)
        .await
        .expect("read timed out")
        .unwrap();
    assert_eq!(n, 0);
}

/// The transport has no operating-system handle, and its halves are `Send`, so
/// they can be moved into spawned tasks.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn halves_are_send_and_usable_from_separate_tasks() {
    fn assert_send<T: Send>() {}
    assert_send::<MemoryStream>();
    assert_send::<common::tokio_memory::Controls>();
    assert_send::<common::tokio_memory::StatsHandle>();
    assert_send::<common::tokio_memory::DropWatch>();

    let (a, b) = duplex();
    let (mut a_read, mut a_write) = tokio::io::split(a);
    let (mut b_read, mut b_write) = tokio::io::split(b);

    let echo = tokio::spawn(async move {
        let mut buf = [0u8; 5];
        b_read.read_exact(&mut buf).await.unwrap();
        b_write.write_all(&buf).await.unwrap();
    });

    let send = tokio::spawn(async move {
        a_write.write_all(b"hello").await.unwrap();
        let mut buf = [0u8; 5];
        a_read.read_exact(&mut buf).await.unwrap();
        buf
    });

    tokio::time::timeout(LIMIT, echo).await.unwrap().unwrap();
    let echoed = tokio::time::timeout(LIMIT, send).await.unwrap().unwrap();
    assert_eq!(&echoed, b"hello");
}

#[tokio::test]
async fn empty_buffers_are_no_ops() {
    let (mut a, mut b) = duplex();

    assert_eq!(a.write(&[]).await.unwrap(), 0);
    let n = b.read(&mut []).await.unwrap();
    assert_eq!(n, 0);

    assert_eq!(a.stats().events(), vec![Event::Write(0)]);
    assert_eq!(b.stats().events(), vec![Event::Read(0)]);
    assert_eq!(a.stats().bytes_written(), 0);
    assert_eq!(b.stats().bytes_read(), 0);
}

#[tokio::test]
async fn queued_bytes_are_inspectable_without_consuming_them() {
    let (mut a, mut b) = duplex();
    let controls = a.controls();

    assert_eq!(a.write(b"tagged").await.unwrap(), 6);
    assert_eq!(controls.queued_for_peer(), 6);
    assert_eq!(controls.peek_queued_for_peer(), b"tagged");
    assert_eq!(controls.queued_for_peer(), 6, "peeking must not consume");

    let mut buf = [0u8; 16];
    let n = tokio::time::timeout(LIMIT, b.read(&mut buf))
        .await
        .expect("read timed out")
        .unwrap();
    assert_eq!(&buf[..n], b"tagged");
    assert_eq!(controls.queued_for_peer(), 0);
}
