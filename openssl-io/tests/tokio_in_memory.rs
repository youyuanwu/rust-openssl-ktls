//! End-to-end tests for the tokio stream over the deterministic in-memory
//! transport.
//!
//! This target covers the whole adapter apart from the directional waker
//! schedules, which live in `tokio_wakers.rs`: construction, the two explicit
//! handshakes, session inspection, the pre-handshake guard, the read and write
//! pumps, flush, closure, cancellation, transport recovery, and the fault
//! matrix — fragmented reads, truncated writes, a transport that accepts
//! nothing, injected read and write failures, truncation without
//! `close_notify`, and corrupted ciphertext.
//!
//! Some of the read tests take their plaintext from an independently
//! implemented peer — `tokio-openssl` — rather than from this crate talking to
//! itself. That is test scaffolding for reviewability, not the two-role
//! interoperability assertion, which lives in the external-boundary target.
//!
//! Every test that can park runs under a bounded timeout, so a lost wakeup
//! fails the suite instead of hanging it. The timeout is a failure detector
//! only: nothing here is synchronised by waiting.

mod common;

use std::future::Future;
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
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
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
    server_controls: Controls,
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
    let server_controls = s_tp.controls();

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
        server_controls,
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
    // SC-016: both sides must report the same negotiated parameters, not merely
    // report something.
    assert_eq!(
        pair.server.cipher(),
        cipher,
        "the peers disagree about the negotiated cipher"
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

// --- write, flush, shutdown, and recovery -----------------------------------

/// The most plaintext one `SSL_write_ex` accepts, and the measured ciphertext
/// one such record produces. Both are properties of OpenSSL rather than of this
/// crate, and both are what the admission rule is sized against.
const MAX_RECORD: usize = 16_384;
const ONE_RECORD_CIPHERTEXT: usize = 16_406;

/// Send `payload` from `from` to `to` and return what arrived.
async fn round_trip(from: &mut Stream, to: &mut Stream, payload: &[u8]) -> Vec<u8> {
    from.write_all(payload).await.unwrap();
    from.flush().await.unwrap();
    let mut got = vec![0u8; payload.len()];
    to.read_exact(&mut got).await.unwrap();
    got
}

/// SC-002: plaintext survives byte-for-byte in both directions, for a payload
/// inside one TLS record and for one spanning several.
#[tokio::test]
async fn small_and_multi_record_payloads_round_trip_in_both_directions() {
    let mut pair = connected().await;

    let small = b"well under one record".to_vec();
    let large: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();

    timeout(LIMIT, async {
        assert_eq!(
            round_trip(&mut pair.client, &mut pair.server, &small).await,
            small
        );
        assert_eq!(
            round_trip(&mut pair.server, &mut pair.client, &small).await,
            small
        );
        assert_eq!(
            round_trip(&mut pair.client, &mut pair.server, &large).await,
            large
        );
        assert_eq!(
            round_trip(&mut pair.server, &mut pair.client, &large).await,
            large
        );
    })
    .await
    .expect("the exchange timed out");
}

/// FR-012: one `SSL_write_ex` takes at most a record, so an oversized buffer
/// reports a partial count rather than stalling. An empty buffer is a no-op that
/// drives neither OpenSSL nor the transport.
#[tokio::test]
async fn an_oversized_write_reports_one_record_and_an_empty_write_is_a_no_op() {
    let mut pair = connected().await;

    let oversized = vec![0x5Au8; MAX_RECORD * 3];
    let n = timeout(LIMIT, pair.client.write(&oversized))
        .await
        .expect("write timed out")
        .unwrap();
    assert_eq!(n, MAX_RECORD, "expected exactly one record to be admitted");

    pair.client_stats.reset();
    let n = timeout(LIMIT, pair.client.write(&[]))
        .await
        .expect("write timed out")
        .unwrap();
    assert_eq!(n, 0);
    assert_eq!(pair.client_stats.read_polls(), 0);
    assert_eq!(pair.client_stats.write_polls(), 0);
}

/// SC-004, write half: the guard runs before the empty-slice short circuit,
/// before OpenSSL, and before any transport poll, so a caller that forgot to
/// handshake observes no I/O at all — and no plaintext is consumed.
#[tokio::test]
async fn write_before_the_handshake_is_refused_without_touching_the_transport() {
    let (c_ssl, s_ssl) = certs::engine_ssl_pair();
    let (c_tp, s_tp) = duplex();
    let stats = c_tp.stats();

    let mut client = SslStream::new(c_ssl, c_tp).unwrap();
    let mut server = SslStream::new(s_ssl, s_tp).unwrap();

    let payload = b"much too early".to_vec();
    let err = client.write(&payload).await.unwrap_err();

    assert!(matches!(
        Error::downcast_io(&err),
        Some(Error::HandshakeRequired)
    ));
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

    // An empty slice is refused too: the guard precedes the short circuit.
    let err = client.write(&[]).await.unwrap_err();
    assert!(matches!(
        Error::downcast_io(&err),
        Some(Error::HandshakeRequired)
    ));

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
    assert_eq!(stats.bytes_written(), 0);
    assert!(stats.events().is_empty(), "{:?}", stats.events());
    assert_eq!(
        payload, b"much too early",
        "the caller's buffer was modified"
    );

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

/// SC-008: a write reports what TLS accepted, not what the transport took. With
/// the transport refusing everything the peer sees nothing; flush is the
/// delivery boundary.
#[tokio::test]
async fn a_gated_transport_accepts_the_write_but_delivers_only_after_flush() {
    let mut pair = connected().await;
    pair.client_stats.reset();
    pair.client_controls.close_write_gate();

    let payload = b"queued behind a closed gate".to_vec();
    let n = timeout(LIMIT, pair.client.write(&payload))
        .await
        .expect("write timed out")
        .unwrap();
    assert_eq!(n, payload.len(), "TLS accepted the whole payload");
    assert_eq!(
        pair.client_stats.bytes_written(),
        0,
        "a gated transport must not have taken anything"
    );
    assert_eq!(pair.client_controls.queued_for_peer(), 0);

    pair.client_controls.open_write_gate();
    timeout(LIMIT, pair.client.flush())
        .await
        .expect("flush timed out")
        .unwrap();
    assert!(pair.client_stats.bytes_written() > 0);

    let mut got = vec![0u8; payload.len()];
    timeout(LIMIT, pair.server.read_exact(&mut got))
        .await
        .expect("read timed out")
        .unwrap();
    assert_eq!(got, payload);
}

/// FR-011a / FR-013: admission is decided before OpenSSL is entered, so a second
/// write against a stalled transport parks having consumed nothing. Reopening
/// and flushing then delivers exactly the first write, and only the first.
#[tokio::test]
async fn a_second_write_against_a_stalled_transport_parks_consuming_nothing() {
    let mut pair = connected().await;
    pair.client_controls.close_write_gate();

    let accepted = b"the first write".to_vec();
    let refused = b"the second write".to_vec();

    let n = timeout(LIMIT, pair.client.write(&accepted))
        .await
        .expect("write timed out")
        .unwrap();
    assert_eq!(n, accepted.len());

    let (counter, waker) = counting_waker();
    let mut cx = Context::from_waker(&waker);
    assert!(
        Pin::new(&mut pair.client)
            .poll_write(&mut cx, &refused)
            .is_pending(),
        "a stalled transport must park the next write rather than admit it"
    );
    assert_eq!(counter.0.load(Ordering::SeqCst), 0);

    pair.client_controls.open_write_gate();
    timeout(LIMIT, pair.client.flush())
        .await
        .expect("flush timed out")
        .unwrap();

    let mut got = vec![0u8; accepted.len()];
    timeout(LIMIT, pair.server.read_exact(&mut got))
        .await
        .expect("read timed out")
        .unwrap();
    assert_eq!(
        got, accepted,
        "the cancelled write must have delivered nothing"
    );
}

/// The operational bound, as distinct from the structural one: after any
/// admitted write the backlog holds at most a single measured record. The
/// 65,536-byte ceiling exists to absorb a completely full BIO pair, not because
/// a write is expected to fill it.
#[tokio::test]
async fn an_admitted_write_leaves_at_most_one_record_of_ciphertext_queued() {
    let mut pair = connected().await;
    pair.client_stats.reset();
    pair.client_controls.close_write_gate();

    // Far more than one record is offered; only one may be admitted.
    let oversized = vec![0x27u8; MAX_RECORD * 4];
    let n = timeout(LIMIT, pair.client.write(&oversized))
        .await
        .expect("write timed out")
        .unwrap();
    assert_eq!(n, MAX_RECORD);

    // Nothing was delivered, so whatever the flush now moves is exactly the
    // backlog that write left behind.
    assert_eq!(pair.client_stats.bytes_written(), 0);
    pair.client_controls.open_write_gate();
    timeout(LIMIT, pair.client.flush())
        .await
        .expect("flush timed out")
        .unwrap();

    let backlog = pair.client_stats.bytes_written();
    assert!(backlog > 0);
    assert!(
        backlog <= ONE_RECORD_CIPHERTEXT,
        "an admitted write left {backlog} bytes queued, more than one record"
    );
}

/// SC-008a / FR-011b: the transport stalls while delivering the request, yet
/// `write_all` completes and the following read — with no flush between them —
/// still gets the reply. The read path's mandatory backlog drain is the only
/// thing that can close that gap.
#[tokio::test]
async fn write_all_then_read_round_trip_without_explicit_flush_when_transport_stalls() {
    let pair = connected().await;
    let Pair {
        mut client,
        mut server,
        client_stats,
        client_controls,
        ..
    } = pair;

    let request: Vec<u8> = (0..MAX_RECORD as u32).map(|i| (i % 251) as u8).collect();
    let reply: Vec<u8> = (0..9_000u32).map(|i| (i % 233) as u8).collect();

    client_stats.reset();
    // The transport takes a prefix of the resulting ciphertext and only then
    // goes pending. A closed gate would accept nothing at all; a budget strands
    // the record *mid-write*, which is the case FR-011b's second clause is
    // about — ciphertext already partly on the wire and the rest queued.
    client_controls.set_write_budget(Some(64));

    let expected = request.clone();
    let answer = reply.clone();
    let server_task = tokio::spawn(async move {
        let mut got = vec![0u8; expected.len()];
        server.read_exact(&mut got).await.unwrap();
        assert_eq!(got, expected);
        server.write_all(&answer).await.unwrap();
        server.flush().await.unwrap();
    });

    timeout(LIMIT, client.write_all(&request))
        .await
        .expect("the write timed out")
        .expect("a stalled transport must not fail an accepted write");
    let delivered = client_stats.bytes_written();
    assert_eq!(
        delivered, 64,
        "the budget should have let exactly a prefix through"
    );
    assert!(
        client_stats.events().contains(&Event::WritePending),
        "the transport never actually stalled: {:?}",
        client_stats.events()
    );

    // No flush: this is the whole point. The read is now the only thing that
    // can move the queued record, and it must try before waiting on the peer.
    let mut got = vec![0u8; reply.len()];
    let (wakes, waker) = counting_waker();
    let mut read = Box::pin(client.read_exact(&mut got));
    let polls_before = client_stats.write_polls();
    assert!(
        read.as_mut()
            .poll(&mut Context::from_waker(&waker))
            .is_pending(),
        "nothing has arrived yet, so the read must park"
    );
    assert!(
        client_stats.write_polls() > polls_before,
        "the read never attempted the ciphertext its own write left queued"
    );
    assert_eq!(
        client_stats.bytes_written(),
        delivered,
        "the budget is still exhausted, so nothing further moved"
    );

    // Reopening wakes whoever holds the transport's write registration. That
    // it is the parked reader is exactly what SC-008a asks for.
    client_controls.open_write_gate();
    assert_eq!(
        wakes.0.load(Ordering::SeqCst),
        1,
        "opening the gate must wake the parked reader"
    );

    timeout(LIMIT, read)
        .await
        .expect("the round trip timed out")
        .expect("the reply should arrive once the ciphertext is delivered");
    assert_eq!(got, reply);

    timeout(LIMIT, server_task)
        .await
        .expect("the peer timed out")
        .unwrap();
}

/// D-E's skip guard. Ciphertext is left queued behind a stalled transport, the
/// write side is put into shutdown, and a write failure is armed. A read must
/// then report a read-side outcome and must not touch the write side at all —
/// otherwise a half-shutdown read resurfaces a write error and the usable read
/// half of FR-018 becomes unusable.
#[tokio::test]
async fn read_after_write_shutdown_does_not_surface_a_write_side_error() {
    let pair = connected().await;
    let Pair {
        mut client,
        mut server,
        client_stats,
        client_controls,
        ..
    } = pair;

    // Something for the read to actually return.
    timeout(LIMIT, async {
        server
            .write_all(b"a reply the reader must still see")
            .await
            .unwrap();
        server.flush().await.unwrap();
    })
    .await
    .expect("the peer timed out");

    // Stall the transport, then start closing. `close_notify` reaches the
    // backlog and stays there, so the shutdown parks with the write direction
    // already past `Open` and ciphertext still queued.
    client_controls.close_write_gate();
    let (_counter, waker) = counting_waker();
    let mut cx = Context::from_waker(&waker);
    assert!(
        Pin::new(&mut client).poll_shutdown(&mut cx).is_pending(),
        "a stalled transport must park the shutdown"
    );

    // Arm a failure the read must neither trigger nor report.
    client_controls.inject_write_error(io::ErrorKind::ConnectionReset);
    client_stats.reset();

    let mut buf = [0u8; 64];
    let n = timeout(LIMIT, client.read(&mut buf))
        .await
        .expect("read timed out")
        .expect("the read reported a write-side failure");
    assert_eq!(&buf[..n], b"a reply the reader must still see");

    assert_eq!(
        client_stats.write_polls(),
        0,
        "the read polled the suppressed write side: {:?}",
        client_stats.events()
    );
    assert!(
        client_controls.faults().write_error.is_some(),
        "the read consumed the injected write error"
    );
}

/// SC-011 / FR-015 / FR-016: shutdown flushes, sends one `close_notify`, and
/// returns without waiting for the peer's — this peer never sends one. The peer
/// gets the data first and then a sticky clean end of stream.
#[tokio::test]
async fn shutdown_sends_close_notify_and_the_peer_sees_sticky_end_of_stream() {
    let pair = connected().await;
    let Pair {
        mut client,
        mut server,
        ..
    } = pair;

    timeout(LIMIT, async {
        client.write_all(b"final message").await.unwrap();
        // Deliberately no flush: shutdown is a delivery boundary too.
        client.shutdown().await.unwrap();
    })
    .await
    .expect("shutdown timed out");

    let mut buf = [0u8; 64];
    let n = timeout(LIMIT, server.read(&mut buf))
        .await
        .expect("read timed out")
        .unwrap();
    assert_eq!(&buf[..n], b"final message");

    for attempt in 0..2 {
        let n = timeout(LIMIT, server.read(&mut buf))
            .await
            .expect("read timed out")
            .unwrap();
        assert_eq!(
            n, 0,
            "attempt {attempt} should report a clean end of stream"
        );
    }
    assert!(server.is_peer_closed());
}

/// FR-017: closing twice succeeds and emits nothing the second time.
#[tokio::test]
async fn repeated_shutdown_succeeds_without_a_second_close_notify() {
    let pair = connected().await;
    let Pair {
        mut client,
        mut server,
        client_stats,
        ..
    } = pair;

    client_stats.reset();
    timeout(LIMIT, client.shutdown())
        .await
        .expect("shutdown timed out")
        .unwrap();
    let after_first = client_stats.bytes_written();
    assert!(after_first > 0, "the first close should emit close_notify");

    timeout(LIMIT, client.shutdown())
        .await
        .expect("the repeated shutdown timed out")
        .unwrap();
    assert_eq!(
        client_stats.bytes_written(),
        after_first,
        "the second close emitted something"
    );

    let mut buf = [0u8; 16];
    let n = timeout(LIMIT, server.read(&mut buf))
        .await
        .expect("read timed out")
        .unwrap();
    assert_eq!(n, 0);
}

/// FR-020 / SC-014: a write on a closed session fails as a closed session,
/// recovered by value through the documented route, and never as a zero-length
/// success. The classification repeats without re-entering OpenSSL.
#[tokio::test]
async fn a_write_after_closure_is_classified_as_a_closed_session() {
    let pair = connected().await;
    let Pair { mut client, .. } = pair;

    timeout(LIMIT, client.shutdown())
        .await
        .expect("shutdown timed out")
        .unwrap();

    for attempt in 0..2 {
        let err = timeout(LIMIT, client.write(b"too late"))
            .await
            .expect("write timed out")
            .expect_err("a write after closure reported success");
        assert!(
            matches!(Error::downcast_io(&err), Some(Error::Closed)),
            "attempt {attempt} was not classified as a closed session"
        );
    }
}

/// A `Closed` latch means the session is finished, not that it failed, so
/// shutdown must still deliver a closure notification and the peer must still
/// observe a clean end of stream rather than a truncation.
#[tokio::test]
async fn shutdown_after_a_closed_latch_still_delivers_one_close_notify() {
    let pair = connected().await;
    let Pair {
        mut client,
        mut server,
        client_stats,
        ..
    } = pair;

    // The peer closes first, and the client observes it.
    timeout(LIMIT, server.shutdown())
        .await
        .expect("the peer's shutdown timed out")
        .unwrap();
    let mut buf = [0u8; 16];
    let n = timeout(LIMIT, client.read(&mut buf))
        .await
        .expect("read timed out")
        .unwrap();
    assert_eq!(n, 0, "the peer's close_notify should read as end of stream");
    assert!(client.is_peer_closed());

    client_stats.reset();
    timeout(LIMIT, client.shutdown())
        .await
        .expect("shutdown timed out")
        .unwrap();
    assert!(
        client_stats.bytes_written() > 0,
        "a peer-closed session must still send its own close_notify"
    );

    let n = timeout(LIMIT, server.read(&mut buf))
        .await
        .expect("read timed out")
        .unwrap();
    assert_eq!(n, 0, "the peer must observe a clean end of stream");
    assert!(server.is_peer_closed());
}

/// SC-016: an idle stream gives its transport back, and the transport works
/// directly afterwards.
#[tokio::test]
async fn into_inner_returns_an_idle_transport() {
    let pair = connected().await;
    let Pair {
        client,
        server: _server,
        client_controls,
        ..
    } = pair;

    let Ok(mut transport) = client.into_inner() else {
        panic!("an idle stream should recover its transport");
    };

    timeout(LIMIT, async {
        transport.write_all(b"raw bytes, no TLS").await.unwrap();
        transport.flush().await.unwrap();
    })
    .await
    .expect("the recovered transport timed out");
    assert_eq!(
        client_controls.peek_queued_for_peer(),
        b"raw bytes, no TLS".to_vec()
    );
}

/// SC-016, the other outcome: recovery is refused while ciphertext is queued,
/// and the refusal hands the intact stream back, which then works.
#[tokio::test]
async fn into_inner_refuses_with_queued_ciphertext_and_returns_the_intact_stream() {
    let pair = connected().await;
    let Pair {
        client,
        mut server,
        client_controls,
        ..
    } = pair;

    let mut client = client;
    client_controls.close_write_gate();
    let payload = b"still on this side of the wire".to_vec();
    timeout(LIMIT, client.write_all(&payload))
        .await
        .expect("write timed out")
        .unwrap();

    let Err((client, err)) = client.into_inner() else {
        panic!("recovery must be refused while ciphertext is queued");
    };
    assert!(matches!(
        Error::downcast_io(&io::Error::from(err)),
        Some(Error::Transport(_))
    ));

    // The refusal returned the stream itself, so nothing was lost.
    let mut client = client;
    client_controls.open_write_gate();
    timeout(LIMIT, async {
        client.flush().await.unwrap();
        let mut got = vec![0u8; payload.len()];
        server.read_exact(&mut got).await.unwrap();
        assert_eq!(got, payload);
        assert_eq!(
            round_trip(&mut client, &mut server, b"and it still works").await,
            b"and it still works".to_vec()
        );
    })
    .await
    .expect("the recovered stream timed out");
}

/// D-D step 5: once TLS has accepted plaintext, a failure of the best-effort
/// delivery attempt cannot be the write's result — reporting it would lose
/// bytes the session has already committed to. It is latched and surfaced by
/// the next write-side call instead, exactly once, and never dropped.
#[tokio::test]
async fn a_write_reports_acceptance_and_defers_a_transport_failure_to_the_next_call() {
    let mut pair = connected().await;
    pair.client_controls
        .inject_write_error(io::ErrorKind::ConnectionReset);

    let payload = b"accepted by TLS, refused by the wire".to_vec();
    let n = timeout(LIMIT, pair.client.write(&payload))
        .await
        .expect("write timed out")
        .expect("TLS accepted the plaintext, so the write must report it");
    assert_eq!(n, payload.len());

    let err = timeout(LIMIT, pair.client.flush())
        .await
        .expect("flush timed out")
        .expect_err("the deferred transport failure was dropped");
    assert!(matches!(
        Error::downcast_io(&err),
        Some(Error::Transport(_))
    ));

    // Reported once, and only once: the injected fault was one-shot, so the
    // retry now delivers the plaintext that was accepted all along.
    timeout(LIMIT, async {
        pair.client.flush().await.unwrap();
        let mut got = vec![0u8; payload.len()];
        pair.server.read_exact(&mut got).await.unwrap();
        assert_eq!(got, payload);
    })
    .await
    .expect("the retry timed out");
}

// --- deterministic fault injection ------------------------------------------

/// The per-record overhead one TLS 1.3 application-data record adds to its
/// plaintext: a five-byte header, the inner content type, and the AEAD tag.
/// Measured rather than assumed — it is exactly the difference between one full
/// record's plaintext and its ciphertext.
const RECORD_OVERHEAD: usize = ONE_RECORD_CIPHERTEXT - MAX_RECORD;

/// Drive both futures but return as soon as `a` resolves.
///
/// Needed whenever one side is expected to fail: the peer would otherwise wait
/// forever for a flight that is never coming, and joining would hang instead of
/// reporting the failure under test.
async fn drive_until<A, B>(a: A, b: B) -> A::Output
where
    A: Future,
    B: Future,
{
    let mut a = Box::pin(a);
    let mut b = Box::pin(b);
    std::future::poll_fn(|cx| {
        if let Poll::Ready(value) = a.as_mut().poll(cx) {
            return Poll::Ready(value);
        }
        // The peer is driven only to keep the exchange moving; whatever it
        // returns is not this helper's result.
        let _ = b.as_mut().poll(cx);
        Poll::Pending
    })
    .await
}

/// SC-024: ciphertext arriving in fragments far below a record must never look
/// like end of stream, and must reassemble byte for byte.
#[tokio::test]
async fn reads_fragmented_below_a_record_deliver_intact_plaintext() {
    let pair = connected().await;
    let Pair {
        mut client,
        mut server,
        client_stats,
        client_controls,
        ..
    } = pair;

    let payload: Vec<u8> = (0..20_000u32).map(|i| (i % 251) as u8).collect();
    client_stats.reset();
    client_controls.set_max_read(Some(3));

    timeout(LIMIT, async {
        server.write_all(&payload).await.unwrap();
        server.flush().await.unwrap();
        let mut got = vec![0u8; payload.len()];
        client.read_exact(&mut got).await.unwrap();
        assert_eq!(got, payload, "fragmented delivery corrupted the plaintext");
    })
    .await
    .expect("the fragmented exchange timed out");

    let events = client_stats.events();
    assert!(
        events
            .iter()
            .all(|e| !matches!(e, Event::Read(n) if *n > 3)),
        "the cap was not applied, so nothing was actually fragmented"
    );
    assert!(
        delivering_reads(&events).len() > payload.len() / 3,
        "expected the record to arrive in thousands of pieces, got {} reads",
        delivering_reads(&events).len()
    );
    assert!(
        !events.contains(&Event::ReadEof),
        "a fragment was mistaken for end of stream: {events:?}"
    );
}

/// SC-024: a transport that accepts only a few bytes per call must not lose
/// ciphertext or report a plaintext count the session did not accept.
#[tokio::test]
async fn transport_writes_truncated_to_a_few_bytes_still_deliver_every_record() {
    let pair = connected().await;
    let Pair {
        mut client,
        mut server,
        client_stats,
        client_controls,
        ..
    } = pair;

    let payload: Vec<u8> = (0..20_000u32).map(|i| (i % 241) as u8).collect();
    client_stats.reset();
    client_controls.set_max_write(Some(5));

    timeout(LIMIT, async {
        client.write_all(&payload).await.unwrap();
        client.flush().await.unwrap();
        let mut got = vec![0u8; payload.len()];
        server.read_exact(&mut got).await.unwrap();
        assert_eq!(got, payload, "short transport writes corrupted the stream");
    })
    .await
    .expect("the short-write exchange timed out");

    let events = client_stats.events();
    assert!(
        events
            .iter()
            .all(|e| !matches!(e, Event::Write(n) if *n > 5)),
        "the cap was not applied, so nothing was actually truncated"
    );
    assert!(
        events.iter().filter(|e| e.delivered_bytes()).count() > payload.len() / 5,
        "expected the ciphertext to be handed over five bytes at a time"
    );
    assert_eq!(
        client_stats.bytes_written(),
        payload.len() + 2 * RECORD_OVERHEAD,
        "two records' worth of ciphertext should have reached the peer"
    );
}

// --- error classification ---------------------------------------------------

/// SC-012's first classification: ciphertext the record layer cannot
/// authenticate is a TLS protocol failure.
async fn provoke_tls_protocol_failure() -> io::Error {
    let pair = connected().await;
    let Pair {
        mut client,
        server: _server,
        client_controls,
        ..
    } = pair;

    // A well-formed application-data header over nonsense: the framing is
    // accepted and the AEAD check then fails.
    let mut record = vec![0x17, 0x03, 0x03, 0x00, 0x20];
    record.extend_from_slice(&[0x5Au8; 0x20]);
    client_controls.inject_inbound(&record);

    let mut buf = [0u8; 64];
    timeout(LIMIT, client.read(&mut buf))
        .await
        .expect("the read timed out")
        .expect_err("corrupted ciphertext must not read as plaintext")
}

/// SC-012's second classification, and SC-013: a certificate the client has no
/// reason to trust.
async fn provoke_verification_failure() -> io::Error {
    let (c_ssl, s_ssl) = certs::untrusted_ssl_pair();
    let (c_tp, s_tp) = duplex();
    let mut client = SslStream::new(c_ssl, c_tp).unwrap();
    let mut server = SslStream::new(s_ssl, s_tp).unwrap();

    let err = timeout(LIMIT, drive_until(client.connect(), server.accept()))
        .await
        .expect("the handshake timed out")
        .expect_err("an untrusted certificate must fail the handshake");
    // Converted exactly once, as the trait boundary would convert it.
    io::Error::from(err)
}

/// SC-012's third classification: the transport itself fails.
async fn provoke_transport_failure() -> io::Error {
    let mut pair = connected().await;
    pair.client_controls
        .inject_read_error(io::ErrorKind::ConnectionReset);

    let mut buf = [0u8; 64];
    timeout(LIMIT, pair.client.read(&mut buf))
        .await
        .expect("the read timed out")
        .expect_err("a failing transport must surface as an error")
}

/// SC-012's fourth classification: the transport ends with no `close_notify`.
async fn provoke_unexpected_eof() -> io::Error {
    let pair = connected().await;
    let Pair {
        mut client,
        server,
        server_controls,
        ..
    } = pair;

    // The peer's transport dies underneath an intact TLS session.
    drop(server.into_inner().map_err(|_| ()).expect("an idle stream"));
    assert!(server_controls.write_closed());

    let mut buf = [0u8; 64];
    timeout(LIMIT, client.read(&mut buf))
        .await
        .expect("the read timed out")
        .expect_err("truncation must not read as a clean close")
}

/// SC-012's fifth classification: the session is finished.
async fn provoke_closed_session() -> io::Error {
    let pair = connected().await;
    let Pair {
        mut client,
        server: _server,
        ..
    } = pair;

    timeout(LIMIT, client.shutdown())
        .await
        .expect("the shutdown timed out")
        .unwrap();
    timeout(LIMIT, client.write(b"too late"))
        .await
        .expect("the write timed out")
        .expect_err("a write after closure must fail")
}

/// The caller-sequencing marker, which is deliberately *not* one of the five.
async fn provoke_handshake_required() -> io::Error {
    let (c_ssl, _s_ssl) = certs::engine_ssl_pair();
    let (c_tp, _s_tp) = duplex();
    let mut client = SslStream::new(c_ssl, c_tp).unwrap();
    let mut buf = [0u8; 16];
    client
        .read(&mut buf)
        .await
        .expect_err("a read before the handshake must fail")
}

/// SC-012 / FR-023: every operational classification is provoked through the
/// tokio stream and recovered from the returned `std::io::Error` by value.
///
/// Nothing here inspects a message: the point of the crate's public recovery
/// route is that text never has to be parsed. The caller-sequencing marker is
/// carried through the same route and shown to be distinct from all five.
#[tokio::test]
async fn every_operational_classification_is_recovered_by_value() {
    let tls = provoke_tls_protocol_failure().await;
    assert!(
        matches!(Error::downcast_io(&tls), Some(Error::Tls(_))),
        "corrupted ciphertext was not classified as a TLS failure"
    );
    assert_eq!(tls.kind(), io::ErrorKind::InvalidData);

    let verification = provoke_verification_failure().await;
    assert!(
        matches!(
            Error::downcast_io(&verification),
            Some(Error::Verification { .. })
        ),
        "an untrusted certificate was not classified as a verification failure"
    );

    let transport = provoke_transport_failure().await;
    assert!(
        matches!(Error::downcast_io(&transport), Some(Error::Transport(_))),
        "a transport failure was not classified as one"
    );

    let truncated = provoke_unexpected_eof().await;
    assert!(
        matches!(Error::downcast_io(&truncated), Some(Error::UnexpectedEof)),
        "truncation was not classified as an unexpected end of transport"
    );
    assert_eq!(truncated.kind(), io::ErrorKind::UnexpectedEof);

    let closed = provoke_closed_session().await;
    assert!(
        matches!(Error::downcast_io(&closed), Some(Error::Closed)),
        "a closed session was not classified as one"
    );
    assert_eq!(closed.kind(), io::ErrorKind::NotConnected);

    // All five are operational, and none of them is the sequencing marker.
    for (name, err) in [
        ("tls", &tls),
        ("verification", &verification),
        ("transport", &transport),
        ("unexpected eof", &truncated),
        ("closed", &closed),
    ] {
        assert!(
            matches!(
                Error::downcast_io(err),
                Some(
                    Error::Tls(_)
                        | Error::Verification { .. }
                        | Error::Transport(_)
                        | Error::UnexpectedEof
                        | Error::Closed
                )
            ),
            "{name} is not an operational classification"
        );
        assert!(
            !matches!(Error::downcast_io(err), Some(Error::HandshakeRequired)),
            "{name} collided with the caller-sequencing marker"
        );
    }

    // And the marker is neither of them.
    let marker = provoke_handshake_required().await;
    assert!(matches!(
        Error::downcast_io(&marker),
        Some(Error::HandshakeRequired)
    ));
    assert!(
        !matches!(
            Error::downcast_io(&marker),
            Some(
                Error::Tls(_)
                    | Error::Verification { .. }
                    | Error::Transport(_)
                    | Error::UnexpectedEof
                    | Error::Closed
            )
        ),
        "the caller-sequencing marker was reported as an operational failure"
    );
}

/// SC-013 on its own, because it is the one classification that can only be
/// provoked during the handshake: the verify result is carried by value, so the
/// specific reason is available without string matching.
#[tokio::test]
async fn an_untrusted_certificate_fails_the_handshake_by_value() {
    let err = provoke_verification_failure().await;
    let Some(Error::Verification { code, .. }) = Error::downcast_io(&err) else {
        panic!("expected a verification failure, got {err:?}");
    };
    assert_ne!(
        *code, 0,
        "the verify result should name the reason the chain was rejected"
    );
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);
}

/// SC-014's third clause: truncation and a clean end of stream are different
/// outcomes, asserted side by side so neither can drift into the other.
#[tokio::test]
async fn truncation_is_distinct_from_a_clean_end_of_stream() {
    // Clean: the peer sends `close_notify`, and every later read agrees.
    let pair = connected().await;
    let Pair {
        mut client,
        mut server,
        ..
    } = pair;
    timeout(LIMIT, server.shutdown())
        .await
        .expect("the peer's shutdown timed out")
        .unwrap();

    let mut buf = [0u8; 64];
    for attempt in 0..2 {
        let n = timeout(LIMIT, client.read(&mut buf))
            .await
            .expect("the read timed out")
            .unwrap_or_else(|e| panic!("attempt {attempt} reported an error: {e:?}"));
        assert_eq!(n, 0, "attempt {attempt} should report end of stream");
    }
    assert!(client.is_peer_closed());

    // Truncated: the transport ends with no notification at all.
    let err = provoke_unexpected_eof().await;
    assert!(
        matches!(Error::downcast_io(&err), Some(Error::UnexpectedEof)),
        "a truncated transport must not read as a clean close"
    );
    assert_ne!(
        err.kind(),
        io::ErrorKind::NotConnected,
        "truncation must not be reported as an orderly closure"
    );
}

// --- cancellation -----------------------------------------------------------

/// SC-006 / FR-013: a pending write is cancelled, and not one byte of the
/// plaintext it was carrying reaches the peer.
///
/// Each call is tagged with its own byte value, so the recovered plaintext
/// names exactly which calls survived. The ciphertext queued for the peer is
/// checked too, and by exact length: the cancelled call never entered OpenSSL,
/// so it can have produced no record at all — an inequality would also pass if
/// a stray record had been produced and then dropped somewhere.
#[tokio::test]
async fn a_cancelled_pending_write_delivers_none_of_its_own_plaintext() {
    const TAGGED: usize = 4_096;

    let pair = connected().await;
    let Pair {
        mut client,
        mut server,
        client_stats,
        client_controls,
        ..
    } = pair;

    client_stats.reset();
    client_controls.close_write_gate();

    let (_idle, waker) = counting_waker();
    let mut cx = Context::from_waker(&waker);
    let mut accepted: Vec<u8> = Vec::new();
    let mut cancelled_tag = None;

    // Issue uniquely tagged single-call writes until bounded buffering forces
    // one to park. That one is dropped where it stands.
    for i in 0..8u8 {
        let tag = 0xA0 | i;
        let payload = vec![tag; TAGGED];
        let mut write = Box::pin(client.write(&payload));
        let polled = write.as_mut().poll(&mut cx);
        match polled {
            Poll::Ready(result) => {
                let n = result.expect("a gated transport must not fail an accepted write");
                assert_eq!(n, TAGGED, "the whole tagged payload should be admitted");
                accepted.extend(std::iter::repeat_n(tag, n));
            }
            Poll::Pending => {
                drop(write);
                cancelled_tag = Some(tag);
                break;
            }
        }
    }

    let cancelled_tag = cancelled_tag.expect("bounded buffering never forced a write to park");
    let records = accepted.len() / TAGGED;
    assert!(records >= 1, "no write was admitted, so nothing is proven");
    assert_eq!(
        client_stats.bytes_written(),
        0,
        "the gate let ciphertext through, so the flush below proves nothing"
    );

    // Reopen and flush: this is the delivery boundary, so everything the
    // surviving writes produced is now on the wire and nothing else can be.
    client_controls.open_write_gate();
    timeout(LIMIT, client.flush())
        .await
        .expect("the flush timed out")
        .unwrap();

    let on_the_wire = client_controls.peek_queued_for_peer();
    assert_eq!(
        on_the_wire.len(),
        records * (TAGGED + RECORD_OVERHEAD),
        "the wire carries something other than exactly the accepted writes"
    );

    let mut got = vec![0u8; accepted.len()];
    timeout(LIMIT, server.read_exact(&mut got))
        .await
        .expect("the read timed out")
        .unwrap();
    assert_eq!(
        got, accepted,
        "the peer did not receive the accepted writes"
    );
    assert!(
        !got.contains(&cancelled_tag),
        "a byte of the cancelled write reached the peer"
    );
    assert_eq!(
        client_controls.queued_for_peer(),
        0,
        "ciphertext beyond the accepted writes was left on the wire"
    );

    // And the session is still correct afterwards, in both directions.
    timeout(LIMIT, async {
        assert_eq!(
            round_trip(&mut client, &mut server, b"the session survived").await,
            b"the session survived".to_vec()
        );
        assert_eq!(
            round_trip(&mut server, &mut client, b"and so does the reply").await,
            b"and so does the reply".to_vec()
        );
    })
    .await
    .expect("the follow-up exchange timed out");
}

/// SC-007 / FR-013a: a cancelled read loses nothing, repeatedly.
///
/// The repetition is not padding: a stale waiter or a half-updated buffer
/// offset only shows up once the same state has been reused, and each round
/// checks the peer's bytes arrive in order with nothing dropped in between.
#[tokio::test]
async fn a_cancelled_pending_read_loses_no_plaintext() {
    let pair = connected().await;
    let Pair {
        mut client,
        mut server,
        ..
    } = pair;

    let mut expected: Vec<u8> = Vec::new();
    let mut received: Vec<u8> = Vec::new();

    timeout(LIMIT, async {
        for round in 0..4u8 {
            // Park a read on a transport with nothing to give, then abandon it.
            let (counter, waker) = counting_waker();
            let mut buf = [0xEEu8; 64];
            {
                let mut read = Box::pin(client.read(&mut buf));
                let polled = read.as_mut().poll(&mut Context::from_waker(&waker));
                assert!(
                    polled.is_pending(),
                    "round {round}: nothing has arrived, so the read must park"
                );
            }
            assert_eq!(
                counter.0.load(Ordering::SeqCst),
                0,
                "round {round}: parking must not wake immediately"
            );
            assert_eq!(
                buf, [0xEEu8; 64],
                "round {round}: a pending read wrote into the caller's buffer"
            );

            let chunk = vec![0x10 + round; 100];
            server.write_all(&chunk).await.unwrap();
            server.flush().await.unwrap();
            expected.extend_from_slice(&chunk);

            let mut got = vec![0u8; chunk.len()];
            client.read_exact(&mut got).await.unwrap();
            received.extend_from_slice(&got);
        }
    })
    .await
    .expect("the cancellation rounds timed out");

    assert_eq!(
        received, expected,
        "cancelled reads lost or reordered the peer's plaintext"
    );
}

// --- closure, drop, and the usable read half --------------------------------

/// SC-010 / FR-018 over memory: this transport's shutdown closes only its write
/// direction, so shutting the stream's write side down must leave reads working
/// right up until the peer closes.
#[tokio::test]
async fn a_half_shutdown_stream_keeps_reading_until_the_peer_closes() {
    let pair = connected().await;
    let Pair {
        mut client,
        mut server,
        client_controls,
        ..
    } = pair;

    timeout(LIMIT, async {
        client.shutdown().await.unwrap();
        assert!(
            client_controls.write_closed(),
            "the transport's write direction should be closed"
        );

        // The peer has not closed, so the read half is still live.
        server
            .write_all(b"a reply after the local close")
            .await
            .unwrap();
        server.flush().await.unwrap();

        let mut buf = [0u8; 64];
        let n = client.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"a reply after the local close");

        // Only the peer's own closure ends it, and it stays ended.
        server.shutdown().await.unwrap();
        for attempt in 0..2 {
            let n = client.read(&mut buf).await.unwrap();
            assert_eq!(n, 0, "attempt {attempt} should report end of stream");
        }
    })
    .await
    .expect("the half-shutdown exchange timed out");
    assert!(client.is_peer_closed());
}

/// SC-015 / FR-022: dropping a session without shutting it down neither panics
/// nor blocks, and actually releases the transport.
///
/// The release is observed rather than assumed — the transport counts its own
/// drops through a handle that outlives it — and the drop is made to happen
/// with work still outstanding, which is the case where a binding might be
/// tempted to block.
#[tokio::test]
async fn dropping_without_shutdown_neither_blocks_nor_leaks_the_transport() {
    let (c_ssl, s_ssl) = certs::engine_ssl_pair();
    let (c_tp, s_tp) = duplex();
    let watch = c_tp.drop_watch();
    let controls = c_tp.controls();

    let mut client = SslStream::new(c_ssl, c_tp).unwrap();
    let mut server = SslStream::new(s_ssl, s_tp).unwrap();
    let (c, s) = timeout(LIMIT, async {
        tokio::join!(client.connect(), server.accept())
    })
    .await
    .expect("handshake timed out");
    c.expect("client handshake");
    s.expect("server handshake");

    // Leave real work outstanding: plaintext TLS accepted whose ciphertext the
    // transport never took, and no closure notification at all.
    controls.close_write_gate();
    timeout(LIMIT, client.write(b"never delivered"))
        .await
        .expect("the write timed out")
        .unwrap();
    assert!(!watch.is_dropped());

    timeout(LIMIT, async { drop(client) })
        .await
        .expect("dropping the stream blocked");
    assert_eq!(
        watch.count(),
        1,
        "the transport was not released exactly once"
    );

    // The peer sees the consequence: a truncation, not a clean close. That is
    // also proof the drop really did tear the transport down.
    let mut buf = [0u8; 64];
    let err = timeout(LIMIT, server.read(&mut buf))
        .await
        .expect("the peer's read timed out")
        .expect_err("a dropped session must not look like an orderly close");
    assert!(matches!(
        Error::downcast_io(&err),
        Some(Error::UnexpectedEof)
    ));
}
