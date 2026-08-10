//! End-to-end tests for the tokio stream over the deterministic in-memory
//! transport.
//!
//! This target covers what the adapter's first half implements: construction,
//! the two explicit handshakes, session inspection, the pre-handshake guard,
//! and the read pump. The write half arrives in a later phase, so the read
//! tests take their plaintext from an independently implemented peer —
//! `tokio-openssl` — rather than from this crate talking to itself. That is
//! test scaffolding for reviewability, not the two-role interoperability
//! assertion, which needs both halves of this stream.
//!
//! Every test that can park runs under a bounded timeout, so a lost wakeup
//! fails the suite instead of hanging it.

mod common;

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll, Wake, Waker};
use std::time::Duration;

use common::certs;
use common::tokio_memory::{Controls, Event, MemoryStream, StatsHandle, duplex};
use openssl_io::Error;
use openssl_io::tokio::SslStream;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt, ReadBuf};
use tokio::time::timeout;

/// Long enough that a working implementation never reaches it, short enough
/// that a broken one fails quickly.
const LIMIT: Duration = Duration::from_secs(5);

type Stream = SslStream<MemoryStream>;

/// A handshaken client/server pair, both driven by this crate's stream, with
/// each endpoint's instrumentation retained after the transport was moved in.
struct Pair {
    client: Stream,
    server: Stream,
    client_stats: StatsHandle,
    server_stats: StatsHandle,
    client_controls: Controls,
}

/// Build a connected, handshaken pair over memory.
///
/// Both handshakes are driven concurrently because each waits on the other.
async fn connected() -> Pair {
    let (c_ssl, s_ssl) = certs::engine_ssl_pair();
    let (c_tp, s_tp) = duplex();
    let client_stats = c_tp.stats();
    let server_stats = s_tp.stats();
    let client_controls = c_tp.controls();

    let mut client = SslStream::new(c_ssl, c_tp).unwrap();
    let mut server = SslStream::new(s_ssl, s_tp).unwrap();

    let (c, s) = timeout(LIMIT, async {
        tokio::join!(client.connect(), server.accept())
    })
    .await
    .expect("handshake timed out");
    c.expect("client handshake");
    s.expect("server handshake");

    Pair {
        client,
        server,
        client_stats,
        server_stats,
        client_controls,
    }
}

/// This crate's stream as the client, an independently implemented
/// `tokio-openssl` stream as the server.
async fn connected_to_external_peer() -> (Stream, tokio_openssl::SslStream<MemoryStream>) {
    let (c_ssl, s_ssl) = certs::engine_ssl_pair();
    let (c_tp, s_tp) = duplex();

    let mut client = SslStream::new(c_ssl, c_tp).unwrap();
    let mut peer = tokio_openssl::SslStream::new(s_ssl, s_tp).unwrap();

    let (c, s) = timeout(LIMIT, async {
        tokio::join!(client.connect(), Pin::new(&mut peer).accept())
    })
    .await
    .expect("handshake timed out");
    c.expect("client handshake");
    s.expect("peer handshake");

    (client, peer)
}

/// Indices of the reads that actually delivered bytes.
fn delivering_reads(events: &[Event]) -> Vec<usize> {
    events
        .iter()
        .enumerate()
        .filter(|(_, e)| matches!(e, Event::Read(n) if *n > 0))
        .map(|(i, _)| i)
        .collect()
}

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

#[tokio::test]
async fn explicit_handshake_completes_in_both_roles() {
    let pair = connected().await;

    assert!(!pair.client.version().is_empty());
    assert_eq!(pair.client.version(), pair.server.version());
    assert_eq!(pair.client.cipher(), pair.server.cipher());
    assert!(!pair.client.is_peer_closed());
    assert!(!pair.server.is_peer_closed());
}

/// SC-005 for the initiating role: the ClientHello must be on the wire before
/// the client ever polls the transport for a reply. A pump that waited on the
/// peer first would deadlock with its own bytes still queued.
#[tokio::test]
async fn client_handshake_sends_before_it_polls_for_inbound() {
    let pair = connected().await;
    let events = pair.client_stats.events();

    let first_write = pair
        .client_stats
        .first_delivering_write_position()
        .expect("the client must have delivered ciphertext");
    let first_read = pair
        .client_stats
        .first_read_position()
        .expect("the client must have polled for the server's reply");

    assert!(
        first_write < first_read,
        "the client polled inbound at {first_read} before delivering at {first_write}: {events:?}"
    );
}

/// SC-005 for the accepting role. A server necessarily reads first — it has
/// nothing to say until the ClientHello arrives — so the assertion is that once
/// it has a flight to send, it sends it before the *next* inbound poll it
/// requires, which is the client's Finished.
#[tokio::test]
async fn server_handshake_sends_before_it_polls_for_the_next_flight() {
    let pair = connected().await;
    let events = pair.server_stats.events();

    let first_read = pair
        .server_stats
        .first_read_position()
        .expect("the server must have read the ClientHello");
    let first_write = pair
        .server_stats
        .first_delivering_write_position()
        .expect("the server must have delivered its flight");
    assert!(
        first_read < first_write,
        "the server wrote at {first_write} before reading at {first_read}: {events:?}"
    );

    let reads = delivering_reads(&events);
    assert!(
        reads.len() >= 2,
        "expected the server to need a second client flight: {events:?}"
    );
    assert!(
        first_write < reads[1],
        "the server waited for the client's Finished at {} with its own flight \
         still queued at {first_write}: {events:?}",
        reads[1]
    );
}

/// The pump itself services every byte the handshake needs; no application
/// write is involved, and none is even available yet.
#[tokio::test]
async fn handshake_moves_ciphertext_without_any_application_write() {
    let pair = connected().await;

    assert!(
        pair.client_stats.bytes_written() > 0,
        "the client's handshake produced no transport bytes"
    );
    assert!(
        pair.server_stats.bytes_written() > 0,
        "the server's handshake produced no transport bytes"
    );
    assert!(pair.client_stats.bytes_read() > 0);
    assert!(pair.server_stats.bytes_read() > 0);
    // Everything either side produced was consumed by the other.
    assert_eq!(pair.client_controls.queued_for_peer(), 0);
}

/// SC-004, read half: the guard is checked before the empty-buffer short
/// circuit, before OpenSSL, and before any transport poll, so a caller that
/// forgot to handshake observes no I/O whatsoever.
#[tokio::test]
async fn read_before_the_handshake_is_refused_without_touching_the_transport() {
    let (c_ssl, s_ssl) = certs::engine_ssl_pair();
    let (c_tp, s_tp) = duplex();
    let stats = c_tp.stats();

    let mut client = SslStream::new(c_ssl, c_tp).unwrap();
    let mut server = SslStream::new(s_ssl, s_tp).unwrap();

    let mut buf = [0xABu8; 64];
    let err = client.read(&mut buf).await.unwrap_err();

    // Matched by value through the documented route, never by message text.
    assert!(matches!(
        Error::downcast_io(&err),
        Some(Error::HandshakeRequired)
    ));
    // And distinct from every operational classification.
    assert!(!matches!(
        Error::downcast_io(&err),
        Some(
            Error::Tls(_)
                | Error::Verification { .. }
                | Error::Transport(_)
                | Error::UnexpectedEof
                | Error::Closed
        )
    ));
    assert_eq!(err.kind(), io::ErrorKind::InvalidInput);

    assert_eq!(
        stats.read_polls(),
        0,
        "the transport was polled for reading"
    );
    assert_eq!(
        stats.write_polls(),
        0,
        "the transport was polled for writing"
    );
    assert_eq!(stats.bytes_read(), 0);
    assert_eq!(stats.bytes_written(), 0);
    assert!(stats.events().is_empty(), "{:?}", stats.events());
    assert_eq!(buf, [0xABu8; 64], "the caller's buffer was modified");

    // An explicit handshake afterwards still succeeds.
    let (c, s) = timeout(LIMIT, async {
        tokio::join!(client.connect(), server.accept())
    })
    .await
    .expect("handshake timed out");
    c.expect("client handshake");
    s.expect("server handshake");
    assert!(!client.version().is_empty());
}

/// An empty caller buffer is a no-op once the handshake has completed: it must
/// not be mistaken for end of stream and must not drive the transport.
#[tokio::test]
async fn an_empty_buffer_after_the_handshake_is_a_no_op() {
    let mut pair = connected().await;
    pair.client_stats.reset();

    let n = timeout(LIMIT, pair.client.read(&mut []))
        .await
        .expect("read timed out")
        .unwrap();
    assert_eq!(n, 0);
    assert_eq!(pair.client_stats.read_polls(), 0);
    assert_eq!(pair.client_stats.write_polls(), 0);
}

#[tokio::test]
async fn inspection_reaches_the_negotiated_session() {
    let pair = connected().await;

    let version = pair.client.with_ssl(|ssl| ssl.version_str().to_owned());
    assert_eq!(version, pair.client.version());
    let cipher = pair
        .client
        .with_ssl(|ssl| ssl.current_cipher().map(|c| c.name().to_owned()));
    assert_eq!(cipher, pair.client.cipher());
    assert!(cipher.is_some(), "an established session has a cipher");
    assert_eq!(
        pair.server.with_ssl(|ssl| ssl.version_str()),
        pair.client.version()
    );
}

/// Plaintext produced by an independently implemented peer arrives intact.
#[tokio::test]
async fn reads_plaintext_written_by_an_independent_peer() {
    let (mut client, mut peer) = connected_to_external_peer().await;

    peer.write_all(b"a reply from the other implementation")
        .await
        .unwrap();
    peer.flush().await.unwrap();

    let mut buf = [0u8; 64];
    let n = timeout(LIMIT, client.read(&mut buf))
        .await
        .expect("read timed out")
        .unwrap();
    assert_eq!(&buf[..n], b"a reply from the other implementation");
}

/// A buffer smaller than the record leaves the remainder for the next read
/// rather than discarding it.
#[tokio::test]
async fn a_small_buffer_leaves_the_remainder_for_the_next_read() {
    let (mut client, mut peer) = connected_to_external_peer().await;

    let payload = b"0123456789abcdef";
    peer.write_all(payload).await.unwrap();
    peer.flush().await.unwrap();

    let mut got = Vec::new();
    while got.len() < payload.len() {
        let mut small = [0u8; 5];
        let n = timeout(LIMIT, client.read(&mut small))
            .await
            .expect("read timed out")
            .unwrap();
        assert!(n > 0 && n <= 5, "expected a bounded read, got {n}");
        got.extend_from_slice(&small[..n]);
    }
    assert_eq!(got, payload);
}

/// FR-019: a peer's `close_notify` reads as a clean end of stream, and stays
/// one. Buffered plaintext is delivered first, so closure never truncates.
#[tokio::test]
async fn peer_closure_reads_as_sticky_end_of_stream() {
    let (mut client, mut peer) = connected_to_external_peer().await;

    peer.write_all(b"last words").await.unwrap();
    peer.flush().await.unwrap();
    timeout(LIMIT, Pin::new(&mut peer).shutdown())
        .await
        .expect("peer shutdown timed out")
        .unwrap();

    let mut buf = [0u8; 64];
    let n = timeout(LIMIT, client.read(&mut buf))
        .await
        .expect("read timed out")
        .unwrap();
    assert_eq!(&buf[..n], b"last words");

    for attempt in 0..2 {
        let n = timeout(LIMIT, client.read(&mut buf))
            .await
            .expect("read timed out")
            .unwrap();
        assert_eq!(n, 0, "attempt {attempt} should report end of stream");
    }
    assert!(client.is_peer_closed());
}

/// The invariant that keeps a reader from being lost: a read that parks has
/// polled the transport for readability in that very poll, so the transport
/// holds the waker that will revive it. It has also left the caller's buffer
/// exactly as it found it, which is what makes cancelling it free.
#[tokio::test]
async fn a_pending_read_polls_the_transport_and_leaves_the_buffer_untouched() {
    let (mut client, mut peer) = connected_to_external_peer().await;

    let mut storage = [0xCDu8; 128];
    let (counter, waker) = counting_waker();
    let mut cx = Context::from_waker(&waker);

    let parked = {
        let mut buf = ReadBuf::new(&mut storage);
        let poll = Pin::new(&mut client).poll_read(&mut cx, &mut buf);
        assert!(poll.is_pending(), "no peer data, so the read must park");
        assert_eq!(buf.filled().len(), 0, "a pending read filled the buffer");
        buf.remaining()
    };
    assert_eq!(parked, storage.len());
    assert_eq!(storage, [0xCDu8; 128], "the caller's buffer was modified");
    assert_eq!(
        counter.0.load(Ordering::SeqCst),
        0,
        "parking must not wake immediately"
    );

    // Cancelling that read loses nothing: the peer's bytes arrive afterwards,
    // in order, through an ordinary read.
    peer.write_all(b"after the cancelled read").await.unwrap();
    peer.flush().await.unwrap();

    let mut buf = [0u8; 64];
    let n = timeout(LIMIT, client.read(&mut buf))
        .await
        .expect("read timed out")
        .unwrap();
    assert_eq!(&buf[..n], b"after the cancelled read");
}

/// Split halves have to reach `tokio::spawn`, which means the stream must be
/// `Send` whenever its transport is. Proven by compilation; no `Sync` promise
/// is made or needed.
#[test]
fn the_stream_is_send_when_its_transport_is() {
    fn assert_send<T: Send>() {}
    assert_send::<SslStream<MemoryStream>>();
    assert_send::<SslStream<tokio::net::TcpStream>>();
}

/// A read that parks because the transport has no data must be woken by that
/// transport. The park is observed exactly — one poll, one observation — and
/// the wake then comes from the peer's own bytes rather than from a clock.
#[tokio::test]
async fn a_parked_read_is_woken_by_the_transports_own_inbound_wakeup() {
    let (mut client, mut peer) = connected_to_external_peer().await;

    let mut storage = [0u8; 128];
    let (counter, waker) = counting_waker();
    let mut cx = Context::from_waker(&waker);

    {
        let mut buf = ReadBuf::new(&mut storage);
        assert!(matches!(
            Pin::new(&mut client).poll_read(&mut cx, &mut buf),
            Poll::Pending
        ));
    }
    assert_eq!(counter.0.load(Ordering::SeqCst), 0);

    peer.write_all(b"wake up").await.unwrap();
    peer.flush().await.unwrap();
    assert!(
        counter.0.load(Ordering::SeqCst) > 0,
        "the transport did not hold the parked reader's waker"
    );

    let mut buf = [0u8; 16];
    let n = timeout(LIMIT, client.read(&mut buf))
        .await
        .expect("read timed out")
        .unwrap();
    assert_eq!(&buf[..n], b"wake up");
}
