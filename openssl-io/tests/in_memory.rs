//! End-to-end tests over the deterministic in-memory transport.
//!
//! These are the primary suite: every condition that matters — fragmented
//! records, short writes, stalled writes, truncation — is reproducible here,
//! whereas over real TCP it would be timing-dependent. `tcp.rs` then confirms
//! the same stream works over a real socket.

mod common;

use std::time::Duration;

use common::certs;
use common::memory::{Faults, MemoryReadHalf, MemoryWriteHalf, duplex};
use compio_buf::BufResult;
use compio_io::{AsyncRead, AsyncWrite};
use openssl_io::{Error, SslStream};

type Stream = SslStream<MemoryReadHalf, MemoryWriteHalf>;

/// Build a connected, handshaken client/server pair over memory.
async fn connected() -> (Stream, Stream) {
    let (c_ssl, s_ssl) = certs::engine_ssl_pair();
    let (c_tp, s_tp) = duplex();
    let (cr, cw) = c_tp.into_halves();
    let (sr, sw) = s_tp.into_halves();

    let mut client = SslStream::new(c_ssl, cr, cw).unwrap();
    let mut server = SslStream::new(s_ssl, sr, sw).unwrap();

    // Both handshakes must be driven concurrently; each waits on the other.
    let (c, s) = futures_join(client.connect(), server.accept()).await;
    c.expect("client handshake");
    s.expect("server handshake");
    (client, server)
}

/// Minimal join for two futures, avoiding a dependency just for tests.
async fn futures_join<A, B>(a: A, b: B) -> (A::Output, B::Output)
where
    A: Future,
    B: Future,
{
    use std::pin::pin;
    use std::task::Poll;

    let mut a = pin!(a);
    let mut b = pin!(b);
    let mut ao = None;
    let mut bo = None;

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

/// Drive both futures but return as soon as `a` resolves.
///
/// Needed when one side is expected to fail: the peer would otherwise wait
/// forever for bytes that are never coming.
async fn drive_until<A, B>(a: A, b: B) -> A::Output
where
    A: Future,
    B: Future,
{
    use std::pin::pin;
    use std::task::Poll;

    let mut a = pin!(a);
    let mut b = pin!(b);
    let mut bo = None;

    std::future::poll_fn(move |cx| {
        if bo.is_none()
            && let Poll::Ready(v) = b.as_mut().poll(cx)
        {
            bo = Some(v);
        }
        a.as_mut().poll(cx)
    })
    .await
}

/// Read exactly `len` bytes of plaintext.
async fn read_exact(s: &mut Stream, len: usize) -> Vec<u8> {
    let mut got = Vec::new();
    while got.len() < len {
        let buf = Vec::with_capacity(8192);
        let BufResult(n, buf) = s.read(buf).await;
        let n = n.expect("read failed");
        assert!(n > 0, "unexpected end of stream at {} of {len}", got.len());
        got.extend_from_slice(&buf[..n]);
    }
    got
}

/// Write all of `data`, resubmitting whatever a partial write leaves behind.
async fn write_all(s: &mut Stream, data: &[u8]) {
    let mut sent = 0;
    while sent < data.len() {
        let BufResult(n, _) = s.write(data[sent..].to_vec()).await;
        let n = n.expect("write failed");
        assert!(n > 0, "write reported zero for a non-empty buffer");
        sent += n;
    }
}

#[compio::test]
async fn handshake_completes_over_a_transport_with_no_handle() {
    let (client, server) = connected().await;
    assert_eq!(client.version(), server.version());
    assert!(client.cipher().is_some());
    client.with_ssl(|ssl| assert!(ssl.current_cipher().is_some()));
}

#[compio::test]
async fn round_trips_in_both_directions() {
    let (mut client, mut server) = connected().await;

    let (_, r) = futures_join(
        write_all(&mut client, b"client says hello"),
        read_exact(&mut server, 17),
    )
    .await;
    assert_eq!(&r, b"client says hello");

    let (_, r) = futures_join(
        write_all(&mut server, b"server replies!!!"),
        read_exact(&mut client, 17),
    )
    .await;
    assert_eq!(&r, b"server replies!!!");
}

#[compio::test]
async fn round_trips_a_payload_spanning_many_records() {
    let (mut client, mut server) = connected().await;
    let payload: Vec<u8> = (0..120_000u32).map(|i| (i % 251) as u8).collect();

    let (_, got) = futures_join(
        write_all(&mut client, &payload),
        read_exact(&mut server, payload.len()),
    )
    .await;
    assert_eq!(got, payload);
}

/// A read buffer smaller than the available plaintext must leave the remainder
/// for the next read rather than discarding it.
#[compio::test]
async fn small_read_buffer_leaves_the_remainder() {
    let (mut client, mut server) = connected().await;

    let (_, first) = futures_join(write_all(&mut client, b"0123456789"), async {
        let buf = Vec::with_capacity(4);
        let BufResult(n, buf) = server.read(buf).await;
        assert_eq!(n.unwrap(), 4);
        buf
    })
    .await;
    assert_eq!(&first, b"0123");

    let rest = read_exact(&mut server, 6).await;
    assert_eq!(&rest, b"456789");
}

/// A single `SSL_write_ex` never takes more than one record.
#[compio::test]
async fn oversized_write_reports_a_partial_count() {
    let (mut client, mut server) = connected().await;
    let payload = vec![0x5Au8; 100_000];

    let (n, _) = futures_join(
        async {
            let BufResult(n, _) = client.write(payload.clone()).await;
            n.unwrap()
        },
        read_exact(&mut server, 16384),
    )
    .await;
    assert!(
        n > 0 && n < payload.len(),
        "expected partial write, got {n}"
    );
}

/// Short transport writes must be looped internally, so the plaintext count the
/// caller sees still corresponds to bytes actually handed over.
#[compio::test]
async fn survives_short_transport_writes() {
    let (c_ssl, s_ssl) = certs::engine_ssl_pair();
    let (c_tp, s_tp) = duplex();
    c_tp.set_faults(Faults {
        max_write: Some(7),
        ..Default::default()
    });
    let (cr, cw) = c_tp.into_halves();
    let (sr, sw) = s_tp.into_halves();

    let mut client = SslStream::new(c_ssl, cr, cw).unwrap();
    let mut server = SslStream::new(s_ssl, sr, sw).unwrap();
    let (c, s) = futures_join(client.connect(), server.accept()).await;
    c.unwrap();
    s.unwrap();

    let payload = vec![0xA5u8; 5000];
    let (_, got) = futures_join(
        write_all(&mut client, &payload),
        read_exact(&mut server, payload.len()),
    )
    .await;
    assert_eq!(got, payload);
}

/// Records delivered a few bytes at a time must not look like end-of-stream.
#[compio::test]
async fn survives_fragmented_delivery() {
    let (c_ssl, s_ssl) = certs::engine_ssl_pair();
    let (c_tp, s_tp) = duplex();
    s_tp.set_faults(Faults {
        max_read: Some(5),
        ..Default::default()
    });
    let (cr, cw) = c_tp.into_halves();
    let (sr, sw) = s_tp.into_halves();

    let mut client = SslStream::new(c_ssl, cr, cw).unwrap();
    let mut server = SslStream::new(s_ssl, sr, sw).unwrap();
    let (c, s) = futures_join(client.connect(), server.accept()).await;
    c.unwrap();
    s.unwrap();

    let payload = vec![0x3Cu8; 4000];
    let (_, got) = futures_join(
        write_all(&mut client, &payload),
        read_exact(&mut server, payload.len()),
    )
    .await;
    assert_eq!(got, payload);
}

#[compio::test]
async fn empty_buffers_are_no_ops() {
    let (mut client, _server) = connected().await;

    let BufResult(n, _) = client.write(Vec::new()).await;
    assert_eq!(n.unwrap(), 0);

    let BufResult(n, _) = client.read(Vec::with_capacity(0)).await;
    assert_eq!(n.unwrap(), 0);
}

#[compio::test]
async fn clean_close_reads_as_end_of_stream_repeatedly() {
    let (mut client, mut server) = connected().await;

    let (c, _) = futures_join(client.close(), async {
        // Give the server a chance to observe the close_notify.
        let buf = Vec::with_capacity(64);
        server.read(buf).await
    })
    .await;
    c.unwrap();

    // Every subsequent read reports a clean zero, never an error.
    for _ in 0..2 {
        let buf = Vec::with_capacity(64);
        let BufResult(n, _) = server.read(buf).await;
        assert_eq!(n.unwrap(), 0);
    }
    assert!(server.is_peer_closed());
}

#[compio::test]
async fn double_close_succeeds() {
    let (mut client, mut server) = connected().await;
    let (c, _) = futures_join(client.close(), async {
        let buf = Vec::with_capacity(64);
        let _ = server.read(buf).await;
    })
    .await;
    c.unwrap();
    client.close().await.expect("second close should succeed");
}

#[compio::test]
async fn write_after_close_is_reported_as_closed() {
    let (mut client, mut server) = connected().await;
    let (c, _) = futures_join(client.close(), async {
        let buf = Vec::with_capacity(64);
        let _ = server.read(buf).await;
    })
    .await;
    c.unwrap();

    let BufResult(res, _) = client.write(b"too late".to_vec()).await;
    let err = res.expect_err("write after close must fail");
    let classified = err
        .get_ref()
        .and_then(|e| e.downcast_ref::<Error>())
        .expect("classified error");
    assert!(matches!(classified, Error::Closed), "got {classified:?}");
}

/// `AsyncWrite::shutdown` is what generic helpers reach for, so it must send
/// `close_notify` rather than merely dropping the transport.
#[compio::test]
async fn trait_shutdown_performs_a_tls_close() {
    let (mut client, mut server) = connected().await;

    let (c, _) = futures_join(client.shutdown(), async {
        let buf = Vec::with_capacity(64);
        let _ = server.read(buf).await;
    })
    .await;
    c.unwrap();

    // The peer saw an orderly end, not a truncation.
    let buf = Vec::with_capacity(64);
    let BufResult(n, _) = server.read(buf).await;
    assert_eq!(n.unwrap(), 0);
    assert!(server.is_peer_closed());
}

/// A transport that dies without `close_notify` is a truncation, which must be
/// distinguishable from an orderly close.
#[compio::test]
async fn truncation_is_distinct_from_clean_end_of_stream() {
    let (c_ssl, s_ssl) = certs::engine_ssl_pair();
    let (c_tp, s_tp) = duplex();
    let (cr, cw) = c_tp.into_halves();
    let (sr, sw) = s_tp.into_halves();

    let mut client = SslStream::new(c_ssl, cr, cw).unwrap();
    let mut server = SslStream::new(s_ssl, sr, sw).unwrap();
    let (c, s) = futures_join(client.connect(), server.accept()).await;
    c.unwrap();
    s.unwrap();

    // Client vanishes: transport EOF with no close_notify.
    let (_cr, cw) = match client.into_inner() {
        Ok(halves) => halves,
        Err(_) => panic!("idle stream should yield halves"),
    };
    cw.close();

    let buf = Vec::with_capacity(64);
    let BufResult(res, _) = server.read(buf).await;
    let err = res.expect_err("truncation must not read as a clean close");
    let classified = err
        .get_ref()
        .and_then(|e| e.downcast_ref::<Error>())
        .expect("classified error");
    assert!(
        matches!(classified, Error::UnexpectedEof),
        "got {classified:?}"
    );
}

#[compio::test]
async fn untrusted_certificate_fails_verification() {
    let (c_ssl, s_ssl) = certs::untrusted_ssl_pair();
    let (c_tp, s_tp) = duplex();
    let (cr, cw) = c_tp.into_halves();
    let (sr, sw) = s_tp.into_halves();

    let mut client = SslStream::new(c_ssl, cr, cw).unwrap();
    let mut server = SslStream::new(s_ssl, sr, sw).unwrap();

    let c = drive_until(client.connect(), server.accept()).await;
    let err = c.expect_err("handshake against an untrusted cert must fail");
    assert!(
        matches!(err, Error::Verification { .. }),
        "expected Verification, got {err:?}"
    );
}

#[compio::test]
async fn transport_failure_is_classified_as_transport() {
    let (c_ssl, s_ssl) = certs::engine_ssl_pair();
    let (c_tp, s_tp) = duplex();
    // Keep a handle to the client's fault switch; the halves share it, so it
    // can be flipped after the handshake has already succeeded.
    let c_faults = c_tp.faults();
    let (cr, cw) = c_tp.into_halves();
    let (sr, sw) = s_tp.into_halves();

    let mut client = SslStream::new(c_ssl, cr, cw).unwrap();
    let mut server = SslStream::new(s_ssl, sr, sw).unwrap();
    let (c, s) = futures_join(client.connect(), server.accept()).await;
    c.unwrap();
    s.unwrap();

    // Arm a hard read failure, then force the client to go to the transport.
    c_faults.borrow_mut().read_error = Some(std::io::ErrorKind::ConnectionReset);

    let buf = Vec::with_capacity(64);
    let BufResult(res, _) = client.read(buf).await;
    let err = res.expect_err("a failing transport must surface as an error");
    let classified = err
        .get_ref()
        .and_then(|e| e.downcast_ref::<Error>())
        .expect("classified error");
    assert!(
        matches!(classified, Error::Transport(_)),
        "expected Transport, got {classified:?}"
    );
}

#[compio::test]
async fn into_inner_refuses_while_an_operation_is_in_flight() {
    let (mut client, _server) = connected().await;

    // Start a read that cannot complete, then abandon it. The stream keeps the
    // in-flight transport operation, so recovery must be refused.
    let pending = compio::time::timeout(Duration::from_millis(20), async {
        let buf = Vec::with_capacity(64);
        client.read(buf).await
    })
    .await;
    assert!(pending.is_err(), "read should not have completed");

    match client.into_inner() {
        Err((stream, _)) => {
            // The stream comes back intact and is still usable.
            assert!(stream.cipher().is_some());
        }
        Ok(_) => panic!("into_inner must refuse while an operation is in flight"),
    }
}

/// Abandoning a read must leave the session usable, which is the entire point
/// of keeping in-flight operations in the stream rather than in the future.
#[compio::test]
async fn abandoned_read_leaves_the_session_usable() {
    let (mut client, mut server) = connected().await;

    let timed_out = compio::time::timeout(Duration::from_millis(20), async {
        let buf = Vec::with_capacity(64);
        client.read(buf).await
    })
    .await;
    assert!(timed_out.is_err(), "read should have timed out");

    // The session still works in both directions afterwards.
    let (_, got) = futures_join(write_all(&mut server, b"still here"), async {
        read_exact(&mut client, 10).await
    })
    .await;
    assert_eq!(&got, b"still here");
}

#[compio::test]
async fn into_inner_recovers_the_transport_when_idle() {
    let (client, _server) = connected().await;
    let (_r, w) = match client.into_inner() {
        Ok(halves) => halves,
        Err(_) => panic!("idle stream should yield halves"),
    };
    // The recovered half is usable directly.
    w.close();
}

#[compio::test]
async fn dropping_without_close_neither_panics_nor_blocks() {
    let (client, _server) = connected().await;
    drop(client);
}
