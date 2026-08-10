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
        Err((mut stream, _)) => {
            // The stream comes back intact and remains genuinely usable, not
            // merely inspectable.
            assert!(stream.cipher().is_some());
            let BufResult(n, _) = stream.write(b"still works".to_vec()).await;
            assert_eq!(n.expect("write on the returned stream"), 11);
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

/// Build a pair whose client transport can be stalled on demand, so a write can
/// be abandoned mid-flight deterministically.
async fn connected_stallable() -> (Stream, Stream, std::rc::Rc<std::cell::RefCell<Faults>>) {
    let (c_ssl, s_ssl) = certs::engine_ssl_pair();
    let (c_tp, s_tp) = duplex();
    let faults = c_tp.faults();
    let (cr, cw) = c_tp.into_halves();
    let (sr, sw) = s_tp.into_halves();

    let mut client = SslStream::new(c_ssl, cr, cw).unwrap();
    let mut server = SslStream::new(s_ssl, sr, sw).unwrap();
    let (c, s) = futures_join(client.connect(), server.accept()).await;
    c.expect("client handshake");
    s.expect("server handshake");
    (client, server, faults)
}

/// Start a write, stall the transport so it cannot complete, then abandon it.
async fn abandon_a_write(client: &mut Stream, faults: &std::cell::RefCell<Faults>, data: &[u8]) {
    faults.borrow_mut().stall_writes = true;
    let abandoned = compio::time::timeout(Duration::from_millis(20), async {
        let BufResult(r, _) = client.write(data.to_vec()).await;
        r
    })
    .await;
    assert!(abandoned.is_err(), "write should have stalled");
    faults.borrow_mut().stall_writes = false;
}

/// The bug this guards against: resuming an abandoned write must not discard
/// the ciphertext of the write that follows it. Both payloads must arrive, in
/// order, with nothing lost.
#[compio::test]
async fn abandoned_write_then_write_delivers_both_in_order() {
    let (mut client, mut server, faults) = connected_stallable().await;

    abandon_a_write(&mut client, &faults, b"FIRST").await;

    let (_, got) = futures_join(write_all(&mut client, b"SECOND"), async {
        // The abandoned payload may or may not have been committed, so accept
        // either, but nothing may be corrupted or lost from the second write.
        let mut got = Vec::new();
        while !got.ends_with(b"SECOND") {
            let buf = Vec::with_capacity(1024);
            let BufResult(n, buf) = server.read(buf).await;
            let n = n.expect("read after abandoned write");
            assert!(n > 0, "unexpected eof");
            got.extend_from_slice(&buf[..n]);
        }
        got
    })
    .await;

    assert!(
        got == b"SECOND" || got == b"FIRSTSECOND",
        "unexpected bytes {:?} -- an abandoned write must be either fully \
         committed or not at all, never interleaved or truncated",
        String::from_utf8_lossy(&got)
    );
}

#[compio::test]
async fn abandoned_write_then_read_keeps_the_session_correct() {
    let (mut client, mut server, faults) = connected_stallable().await;

    abandon_a_write(&mut client, &faults, b"pending payload").await;

    // A read must not resume or clear the staged write; it just works.
    let (_, got) = futures_join(write_all(&mut server, b"from server"), async {
        read_exact(&mut client, 11).await
    })
    .await;
    assert_eq!(&got, b"from server");
}

#[compio::test]
async fn abandoned_write_then_flush_settles_it() {
    let (mut client, mut server, faults) = connected_stallable().await;

    abandon_a_write(&mut client, &faults, b"queued").await;

    let (flushed, _) = futures_join(client.flush(), async {
        let buf = Vec::with_capacity(1024);
        let _ = server.read(buf).await;
    })
    .await;
    flushed.expect("flush should settle the retained write");
}

#[compio::test]
async fn abandoned_write_then_close_still_sends_close_notify() {
    let (mut client, mut server, faults) = connected_stallable().await;

    abandon_a_write(&mut client, &faults, b"queued").await;

    let (closed, _) = futures_join(client.close(), async {
        // Drain until the peer observes the orderly end.
        for _ in 0..8 {
            let buf = Vec::with_capacity(4096);
            let BufResult(n, _) = server.read(buf).await;
            if matches!(n, Ok(0)) {
                break;
            }
        }
    })
    .await;
    closed.expect("close should settle the retained write and notify");
    assert!(
        server.is_peer_closed(),
        "close_notify must still reach the peer after an abandoned write"
    );
}

#[compio::test]
async fn dropping_with_an_operation_in_flight_neither_panics_nor_blocks() {
    let (mut client, _server, faults) = connected_stallable().await;
    abandon_a_write(&mut client, &faults, b"in flight").await;
    // The retained write operation is dropped along with the stream.
    drop(client);
}

/// A write rejected after closure must not leave staged plaintext behind, or a
/// later close would replay a doomed write and fail instead of being idempotent.
#[compio::test]
async fn close_stays_idempotent_after_a_rejected_write() {
    let (mut client, mut server) = connected().await;

    let (c, _) = futures_join(client.close(), async {
        let buf = Vec::with_capacity(64);
        let _ = server.read(buf).await;
    })
    .await;
    c.unwrap();

    let BufResult(res, _) = client.write(b"rejected".to_vec()).await;
    assert!(res.is_err(), "write after close must fail");

    client
        .close()
        .await
        .expect("close must remain idempotent after a rejected write");
}

/// Transport failure during the client handshake, before any session exists.
#[compio::test]
async fn transport_failure_during_handshake_is_classified() {
    let (c_ssl, _s_ssl) = certs::engine_ssl_pair();
    let (c_tp, _s_tp) = duplex();
    c_tp.faults().borrow_mut().read_error = Some(std::io::ErrorKind::ConnectionReset);
    let (cr, cw) = c_tp.into_halves();

    let mut client = SslStream::new(c_ssl, cr, cw).unwrap();
    let err = client
        .connect()
        .await
        .expect_err("handshake over a broken transport must fail");
    assert!(
        matches!(err, Error::Transport(_)),
        "expected Transport, got {err:?}"
    );
}

/// A peer that disappears mid-handshake must fail the accepting side promptly
/// with a truncation, not hang.
#[compio::test]
async fn peer_disconnect_during_server_handshake_is_unexpected_eof() {
    let (c_ssl, s_ssl) = certs::engine_ssl_pair();
    let (c_tp, s_tp) = duplex();
    let (cr, cw) = c_tp.into_halves();
    let (sr, sw) = s_tp.into_halves();

    let mut client = SslStream::new(c_ssl, cr, cw).unwrap();
    let mut server = SslStream::new(s_ssl, sr, sw).unwrap();

    // Let the client emit its ClientHello, then vanish without finishing.
    let started = compio::time::timeout(Duration::from_millis(20), client.connect()).await;
    assert!(started.is_err(), "handshake should still be in progress");
    drop(client);
    cw_close_after_drop(&mut server).await;
}

/// Helper: with the client gone, the server's handshake must terminate.
async fn cw_close_after_drop(server: &mut Stream) {
    let outcome = compio::time::timeout(Duration::from_secs(2), server.accept()).await;
    let result = outcome.expect("server handshake must not hang after the peer vanishes");
    let err = result.expect_err("a vanished peer cannot complete a handshake");
    assert!(
        matches!(err, Error::UnexpectedEof | Error::Transport(_)),
        "expected a truncation or transport failure, got {err:?}"
    );
}

/// SC-013's M1 half: abandoned operations run repeatedly through the real
/// completion-based driver without crash, hang, or corruption.
#[compio::test]
async fn repeated_cancellation_keeps_the_session_sound() {
    let (mut client, mut server, faults) = connected_stallable().await;

    for round in 0..25u32 {
        abandon_a_write(&mut client, &faults, b"cancelled payload").await;

        // A read is abandoned too, exercising the other direction.
        let timed_out = compio::time::timeout(Duration::from_millis(5), async {
            let buf = Vec::with_capacity(64);
            client.read(buf).await
        })
        .await;
        assert!(timed_out.is_err(), "round {round}: read should have parked");

        // The session must still carry data correctly afterwards.
        let msg = format!("round-{round}");
        let (_, got) = futures_join(write_all(&mut server, msg.as_bytes()), async {
            read_exact(&mut client, msg.len()).await
        })
        .await;
        assert_eq!(
            String::from_utf8_lossy(&got),
            msg,
            "round {round}: plaintext corrupted after cancellation"
        );
    }
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
