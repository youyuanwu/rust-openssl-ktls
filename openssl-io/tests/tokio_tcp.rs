//! The tokio stream over a real socket.
//!
//! The deterministic suite lives in `tokio_in_memory.rs` and `tokio_wakers.rs`,
//! over a transport with no operating-system handle. This target exists to show
//! the adapter is not quietly coupled to that transport: the same
//! `SslStream<S>`, constructed the same way, is handed a
//! [`tokio::net::TcpStream`] instead, which satisfies SC-003's "at least two
//! distinct transport types" with the one that does have a handle.
//!
//! It also carries the TCP half of SC-010 / FR-018. `TcpStream::poll_shutdown`
//! shuts only the write direction down, so this is a transport whose contract
//! keeps reads alive after a local close, and the stream must follow it.
//!
//! Nothing here is synchronised by waiting. The listener binds to port 0 and the
//! assigned port is read back, so no port is ever hardcoded, and every step runs
//! under a bounded timeout that serves purely as a failure detector: a stall
//! fails the suite instead of hanging it.

mod common;

use std::time::Duration;

use common::certs;
use openssl_io::tokio::SslStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

/// Long enough that a working implementation never reaches it, short enough
/// that a broken one fails quickly. Larger than the in-memory suite's bound
/// only because a real socket and a real handshake are involved.
const LIMIT: Duration = Duration::from_secs(10);

/// The very same type the handle-free transport is used through — SC-003 turns
/// on there being no socket-specialised stream.
type Stream = SslStream<TcpStream>;

/// A connected loopback pair, client first.
///
/// The listener binds to port 0 and its assigned address is read back, so
/// concurrent runs of this target cannot collide on a port.
async fn tcp_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    timeout(LIMIT, async {
        tokio::join!(async { TcpStream::connect(addr).await.unwrap() }, async {
            listener.accept().await.unwrap().0
        },)
    })
    .await
    .expect("the loopback connection timed out")
}

/// A handshaken client/server pair over loopback TCP.
///
/// Both handshakes are driven concurrently because each waits on the other.
async fn connected() -> (Stream, Stream) {
    let (c_tp, s_tp) = tcp_pair().await;
    let (c_ssl, s_ssl) = certs::engine_ssl_pair();

    let mut client = SslStream::new(c_ssl, c_tp).unwrap();
    let mut server = SslStream::new(s_ssl, s_tp).unwrap();

    let (c, s) = timeout(LIMIT, async {
        tokio::join!(client.connect(), server.accept())
    })
    .await
    .expect("the handshake over tcp timed out");
    c.expect("client handshake over tcp");
    s.expect("server handshake over tcp");

    (client, server)
}

/// A payload spanning several TLS records, so it cannot ride in one.
fn multi_record() -> Vec<u8> {
    (0..70_000u32).map(|i| (i % 241) as u8).collect()
}

/// SC-003 / SC-002: a full session over a transport with an operating-system
/// handle — handshake, session inspection, a sub-record and a multi-record
/// round trip in both directions, flush, and a clean close.
#[tokio::test]
async fn handshake_and_round_trip_over_tcp() {
    let (mut client, mut server) = connected().await;

    // Both ends agree on what was negotiated, and the session object is
    // reachable for inspection.
    assert_eq!(client.version(), server.version());
    assert_eq!(client.cipher(), server.cipher());
    assert!(client.cipher().is_some());
    client.with_ssl(|ssl| assert!(ssl.current_cipher().is_some()));

    // Smaller than one record.
    const REQUEST: &[u8] = b"a request that fits inside a single tls record";
    const REPLY: &[u8] = b"and the reply to it";

    timeout(LIMIT, async {
        client.write_all(REQUEST).await.unwrap();
        client.flush().await.unwrap();

        let mut got = [0u8; REQUEST.len()];
        server.read_exact(&mut got).await.unwrap();
        assert_eq!(&got[..], REQUEST, "plaintext corrupted over tcp");

        server.write_all(REPLY).await.unwrap();
        server.flush().await.unwrap();

        let mut got = [0u8; REPLY.len()];
        client.read_exact(&mut got).await.unwrap();
        assert_eq!(&got[..], REPLY, "reply plaintext corrupted over tcp");
    })
    .await
    .expect("the sub-record exchange over tcp timed out");

    // Larger than one record, in both directions at once. The two directions
    // are driven concurrently rather than in sequence because neither the
    // socket buffers nor the stream's own bound are large enough to promise
    // that a whole payload can be parked before anyone reads it.
    let up = multi_record();
    let down: Vec<u8> = multi_record().into_iter().rev().collect();

    let (client_got, server_got) = timeout(LIMIT, async {
        tokio::join!(
            async {
                client.write_all(&up).await.unwrap();
                client.flush().await.unwrap();
                let mut got = vec![0u8; down.len()];
                client.read_exact(&mut got).await.unwrap();
                got
            },
            async {
                server.write_all(&down).await.unwrap();
                server.flush().await.unwrap();
                let mut got = vec![0u8; up.len()];
                server.read_exact(&mut got).await.unwrap();
                got
            },
        )
    })
    .await
    .expect("the multi-record exchange over tcp timed out");

    assert_eq!(
        client_got, down,
        "multi-record plaintext corrupted over tcp, server to client"
    );
    assert_eq!(
        server_got, up,
        "multi-record plaintext corrupted over tcp, client to server"
    );

    // A clean, mutual close: each side's closure notification is seen by the
    // other as an end of stream, not as a truncation.
    timeout(LIMIT, async {
        client.shutdown().await.unwrap();

        let mut sink = [0u8; 64];
        assert_eq!(server.read(&mut sink).await.unwrap(), 0);
        assert!(server.is_peer_closed());

        server.shutdown().await.unwrap();
        assert_eq!(client.read(&mut sink).await.unwrap(), 0);
    })
    .await
    .expect("the closure over tcp timed out");
    assert!(client.is_peer_closed());
}

/// SC-010 / FR-018 over TCP: `TcpStream::poll_shutdown` calls `shutdown(Write)`
/// and leaves the read direction open, so shutting the stream's write side down
/// must leave reads working right up until the peer closes.
///
/// This is the socket-backed half of the criterion; the handle-free half lives
/// in `tokio_in_memory.rs`.
#[tokio::test]
async fn a_half_shutdown_stream_keeps_reading_until_the_peer_closes_over_tcp() {
    let (mut client, mut server) = connected().await;

    const REPLY: &[u8] = b"a reply sent after the peer closed its write half";

    timeout(LIMIT, async {
        client.shutdown().await.unwrap();

        // The peer has not closed, so the read half is still live and the
        // socket still carries data in the surviving direction.
        server.write_all(REPLY).await.unwrap();
        server.flush().await.unwrap();

        let mut got = [0u8; REPLY.len()];
        client.read_exact(&mut got).await.unwrap();
        assert_eq!(&got[..], REPLY, "the read half died with the write half");

        // Only the peer's own closure ends it, and it stays ended.
        server.shutdown().await.unwrap();
        let mut sink = [0u8; 64];
        for attempt in 0..2 {
            let n = client.read(&mut sink).await.unwrap();
            assert_eq!(n, 0, "attempt {attempt} should report end of stream");
        }
    })
    .await
    .expect("the half-shutdown exchange over tcp timed out");
    assert!(client.is_peer_closed());
}
