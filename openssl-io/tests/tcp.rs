//! Confirmation that the same stream works over a real socket.
//!
//! The deterministic suite lives in `in_memory.rs`; this file exists to show
//! the stream is not quietly coupled to the in-memory transport, satisfying
//! spec SC-002's "at least two distinct transport types" with one that does
//! have an operating-system handle.

mod common;

use common::certs;
use compio::net::{TcpListener, TcpStream};
use compio_buf::BufResult;
use compio_io::{AsyncRead, AsyncWrite};
use openssl_io::compio::SslStream;

/// Drive two futures to completion together.
async fn join<A, B>(a: A, b: B) -> (A::Output, B::Output)
where
    A: Future,
    B: Future,
{
    use std::pin::pin;
    use std::task::Poll;

    let mut a = pin!(a);
    let mut b = pin!(b);
    let (mut ao, mut bo) = (None, None);

    std::future::poll_fn(move |cx| {
        if ao.is_none()
            && let Poll::Ready(v) = a.as_mut().poll(cx)
        {
            ao = Some(v);
        }
        if bo.is_none()
            && let Poll::Ready(v) = b.as_mut().poll(cx)
        {
            bo = Some(v);
        }
        if ao.is_some() && bo.is_some() {
            Poll::Ready((ao.take().unwrap(), bo.take().unwrap()))
        } else {
            Poll::Pending
        }
    })
    .await
}

use std::future::Future;

#[compio::test]
async fn handshake_and_round_trip_over_tcp() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let (c_ssl, s_ssl) = certs::engine_ssl_pair();

    let ((accepted, _peer), connected) = join(async { listener.accept().await.unwrap() }, async {
        TcpStream::connect(addr).await.unwrap()
    })
    .await;

    // A TcpStream splits into two independently usable halves without a lock,
    // which is exactly what the stream stores.
    let (sr, sw) = accepted.into_split();
    let (cr, cw) = connected.into_split();

    let mut server = SslStream::new(s_ssl, sr, sw).unwrap();
    let mut client = SslStream::new(c_ssl, cr, cw).unwrap();

    let (c, s) = join(client.connect(), server.accept()).await;
    c.expect("client handshake over tcp");
    s.expect("server handshake over tcp");

    // Both ends agree on what was negotiated.
    assert_eq!(client.version(), server.version());
    assert_eq!(client.cipher(), server.cipher());
    assert!(client.cipher().is_some());
    client.with_ssl(|ssl| assert!(ssl.current_cipher().is_some()));

    // Payload larger than one record, so it cannot ride in a single write.
    let payload: Vec<u8> = (0..70_000u32).map(|i| (i % 241) as u8).collect();

    let (_, got) = join(
        async {
            let mut sent = 0;
            while sent < payload.len() {
                let BufResult(n, _) = client.write(payload[sent..].to_vec()).await;
                sent += n.expect("write over tcp");
            }
            client.flush().await.expect("flush over tcp");
        },
        async {
            let mut got = Vec::new();
            while got.len() < payload.len() {
                let buf = Vec::with_capacity(16 * 1024);
                let BufResult(n, buf) = server.read(buf).await;
                let n = n.expect("read over tcp");
                assert!(n > 0, "unexpected eof at {} bytes", got.len());
                got.extend_from_slice(&buf[..n]);
            }
            got
        },
    )
    .await;

    assert_eq!(got, payload, "plaintext corrupted over tcp");

    let (c, _) = join(client.close(), async {
        let buf = Vec::with_capacity(64);
        let _ = server.read(buf).await;
    })
    .await;
    c.expect("close over tcp");
    assert!(server.is_peer_closed());
}
