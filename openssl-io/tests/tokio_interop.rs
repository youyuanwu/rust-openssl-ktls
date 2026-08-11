//! SC-017 / FR-028: two-role interoperability with an independently
//! implemented OpenSSL-backed async TLS stream.
//!
//! The peer is [`tokio_openssl::SslStream`] 0.6.5, which drives the same
//! OpenSSL library through a completely different adapter: it smuggles the
//! task [`Context`](std::task::Context) into a synchronous BIO over the
//! transport, where this crate feeds a BIO pair from an explicit pump. That
//! makes it an independent implementation of the *adapter*, and therefore a
//! real test of this crate's pump, framing, and closure sequence — it is
//! deliberately not a claim of interoperability with a TLS stack other than
//! OpenSSL, which FR-028 leaves out of scope.
//!
//! Both role assignments are covered, because the two roles exercise different
//! code: the client sends the first flight and the server the first response,
//! and the shutdown initiator differs from the responder. Each test verifies
//! plaintext in *both* directions and that *both* peers observe a clean end of
//! stream after closure. The two tests also close in opposite orders, so
//! neither side is only ever tested as the initiator.
//!
//! Closure needs care, and that is a property of the peer rather than an
//! accident: `tokio_openssl`'s `poll_shutdown` sends `close_notify` and *then*
//! shuts the underlying transport down as well. Over a `TcpStream` that is
//! `shutdown(Write)`, which leaves the peer's read direction alive, so the
//! surviving direction still carries the responder's own `close_notify` back.
//! A transport that closed both directions would truncate it — hence the real
//! socket here rather than a duplex, and hence the assertion that the closure
//! is seen as an end of stream and never as a truncation.
//!
//! Note that `tokio_in_memory.rs` also uses this crate as read-test
//! scaffolding. That is not this assertion: only this target drives both roles
//! and both closure directions.
//!
//! The listener binds to port 0 and the assigned port is read back, and every
//! step is bounded by a timeout used purely as a failure detector.

mod common;

use std::pin::Pin;
use std::time::Duration;

use common::certs;
use openssl_io::tokio::SslStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

/// Long enough that a working implementation never reaches it, short enough
/// that a broken one fails quickly.
const LIMIT: Duration = Duration::from_secs(10);

const REQUEST: &[u8] = b"a request from the client to the server";
const REPLY: &[u8] = b"a reply from the server to the client";

/// A connected loopback pair, client first.
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

/// A payload spanning several TLS records, so the exchange cannot pass as
/// correct on a single record's worth of luck.
fn multi_record(seed: u32) -> Vec<u8> {
    (0..70_000u32)
        .map(|i| ((i.wrapping_mul(7) + seed) % 241) as u8)
        .collect()
}

/// SC-017, first role assignment: this crate connects, `tokio-openssl` accepts.
#[tokio::test]
async fn this_crate_as_client_against_a_tokio_openssl_server() {
    let (c_tp, s_tp) = tcp_pair().await;
    let (c_ssl, s_ssl) = certs::engine_ssl_pair();

    let mut client = SslStream::new(c_ssl, c_tp).unwrap();
    let mut server = tokio_openssl::SslStream::new(s_ssl, s_tp).unwrap();

    let (c, s) = timeout(LIMIT, async {
        tokio::join!(client.connect(), Pin::new(&mut server).accept())
    })
    .await
    .expect("the interoperating handshake timed out");
    c.expect("this crate's client handshake against tokio-openssl");
    s.expect("the tokio-openssl server handshake against this crate");

    // Both adapters agree on the session they negotiated.
    assert_eq!(client.version(), server.ssl().version_str());
    assert!(client.cipher().is_some());

    // Plaintext in both directions, sub-record first.
    timeout(LIMIT, async {
        client.write_all(REQUEST).await.unwrap();
        client.flush().await.unwrap();

        let mut got = [0u8; REQUEST.len()];
        Pin::new(&mut server).read_exact(&mut got).await.unwrap();
        assert_eq!(
            &got[..],
            REQUEST,
            "the external peer received corrupt plaintext"
        );

        Pin::new(&mut server).write_all(REPLY).await.unwrap();
        Pin::new(&mut server).flush().await.unwrap();

        let mut got = [0u8; REPLY.len()];
        client.read_exact(&mut got).await.unwrap();
        assert_eq!(&got[..], REPLY, "this crate received corrupt plaintext");
    })
    .await
    .expect("the interoperating sub-record exchange timed out");

    // And again spanning several records, driven concurrently so neither side
    // depends on the other's buffering.
    let up = multi_record(1);
    let down = multi_record(2);
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
                Pin::new(&mut server).write_all(&down).await.unwrap();
                Pin::new(&mut server).flush().await.unwrap();
                let mut got = vec![0u8; up.len()];
                Pin::new(&mut server).read_exact(&mut got).await.unwrap();
                got
            },
        )
    })
    .await
    .expect("the interoperating multi-record exchange timed out");
    assert_eq!(
        client_got, down,
        "multi-record plaintext corrupted from the external peer"
    );
    assert_eq!(
        server_got, up,
        "multi-record plaintext corrupted to the external peer"
    );

    // Closure, this crate first. Each side must see the other's notification as
    // an end of stream, never as a truncation.
    timeout(LIMIT, async {
        client.shutdown().await.unwrap();

        let mut sink = [0u8; 64];
        let n = Pin::new(&mut server)
            .read(&mut sink)
            .await
            .expect("the external peer saw a truncation, not a clean close");
        assert_eq!(n, 0, "the external peer must observe end of stream");

        Pin::new(&mut server).shutdown().await.unwrap();

        let n = client
            .read(&mut sink)
            .await
            .expect("this crate saw a truncation, not a clean close");
        assert_eq!(n, 0, "this crate must observe end of stream");
    })
    .await
    .expect("the interoperating closure timed out");
    assert!(client.is_peer_closed());
}

/// SC-017, reversed role assignment: `tokio-openssl` connects, this crate
/// accepts. The external peer also initiates the closure here, so both closure
/// orders are covered across the two tests.
#[tokio::test]
async fn this_crate_as_server_against_a_tokio_openssl_client() {
    let (c_tp, s_tp) = tcp_pair().await;
    let (c_ssl, s_ssl) = certs::engine_ssl_pair();

    let mut client = tokio_openssl::SslStream::new(c_ssl, c_tp).unwrap();
    let mut server = SslStream::new(s_ssl, s_tp).unwrap();

    let (c, s) = timeout(LIMIT, async {
        tokio::join!(Pin::new(&mut client).connect(), server.accept())
    })
    .await
    .expect("the interoperating handshake timed out");
    c.expect("the tokio-openssl client handshake against this crate");
    s.expect("this crate's server handshake against tokio-openssl");

    assert_eq!(server.version(), client.ssl().version_str());
    assert!(server.cipher().is_some());

    timeout(LIMIT, async {
        Pin::new(&mut client).write_all(REQUEST).await.unwrap();
        Pin::new(&mut client).flush().await.unwrap();

        let mut got = [0u8; REQUEST.len()];
        server.read_exact(&mut got).await.unwrap();
        assert_eq!(&got[..], REQUEST, "this crate received corrupt plaintext");

        server.write_all(REPLY).await.unwrap();
        server.flush().await.unwrap();

        let mut got = [0u8; REPLY.len()];
        Pin::new(&mut client).read_exact(&mut got).await.unwrap();
        assert_eq!(
            &got[..],
            REPLY,
            "the external peer received corrupt plaintext"
        );
    })
    .await
    .expect("the interoperating sub-record exchange timed out");

    let up = multi_record(3);
    let down = multi_record(4);
    let (client_got, server_got) = timeout(LIMIT, async {
        tokio::join!(
            async {
                Pin::new(&mut client).write_all(&up).await.unwrap();
                Pin::new(&mut client).flush().await.unwrap();
                let mut got = vec![0u8; down.len()];
                Pin::new(&mut client).read_exact(&mut got).await.unwrap();
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
    .expect("the interoperating multi-record exchange timed out");
    assert_eq!(
        client_got, down,
        "multi-record plaintext corrupted to the external peer"
    );
    assert_eq!(
        server_got, up,
        "multi-record plaintext corrupted from the external peer"
    );

    // Closure, the external peer first. Its `poll_shutdown` also shuts its
    // transport's write direction down, so this crate sees `close_notify`
    // immediately followed by transport end of file, and must still report a
    // clean end of stream rather than an unexpected end of transport.
    timeout(LIMIT, async {
        Pin::new(&mut client).shutdown().await.unwrap();

        let mut sink = [0u8; 64];
        let n = server
            .read(&mut sink)
            .await
            .expect("this crate saw a truncation, not a clean close");
        assert_eq!(n, 0, "this crate must observe end of stream");
        assert!(server.is_peer_closed());

        server.shutdown().await.unwrap();

        let n = Pin::new(&mut client)
            .read(&mut sink)
            .await
            .expect("the external peer saw a truncation, not a clean close");
        assert_eq!(n, 0, "the external peer must observe end of stream");
    })
    .await
    .expect("the interoperating closure timed out");
}
