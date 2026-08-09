//! Tests for the in-memory transport itself, with no TLS involved.
//!
//! If the fault hooks do not behave as advertised here, every later test that
//! relies on them is worthless, so they are verified in isolation first.

mod common;

use std::time::Duration;

use common::memory::{Faults, duplex};
use compio_io::{AsyncRead, AsyncWrite};

#[compio::test]
async fn round_trips_bytes_in_both_directions() {
    let (mut a, mut b) = duplex();

    let compio_buf::BufResult(n, _) = a.write(b"ping".to_vec()).await;
    assert_eq!(n.unwrap(), 4);

    let buf = Vec::with_capacity(16);
    let compio_buf::BufResult(n, buf) = b.read(buf).await;
    assert_eq!(n.unwrap(), 4);
    assert_eq!(&buf, b"ping");

    let compio_buf::BufResult(n, _) = b.write(b"pong".to_vec()).await;
    assert_eq!(n.unwrap(), 4);

    let buf = Vec::with_capacity(16);
    let compio_buf::BufResult(n, buf) = a.read(buf).await;
    assert_eq!(n.unwrap(), 4);
    assert_eq!(&buf, b"pong");
}

#[compio::test]
async fn max_read_fragments_delivery() {
    let (mut a, mut b) = duplex();
    b.set_faults(Faults {
        max_read: Some(3),
        ..Default::default()
    });

    let compio_buf::BufResult(n, _) = a.write(b"abcdefghij".to_vec()).await;
    assert_eq!(n.unwrap(), 10);

    // Reader is capped at three bytes per call regardless of what is buffered.
    let mut got = Vec::new();
    while got.len() < 10 {
        let buf = Vec::with_capacity(64);
        let compio_buf::BufResult(n, buf) = b.read(buf).await;
        let n = n.unwrap();
        assert!(n > 0 && n <= 3, "expected a capped read, got {n}");
        got.extend_from_slice(&buf[..n]);
    }
    assert_eq!(&got, b"abcdefghij");
}

#[compio::test]
async fn max_write_produces_short_writes() {
    let (mut a, mut b) = duplex();
    a.set_faults(Faults {
        max_write: Some(4),
        ..Default::default()
    });

    let compio_buf::BufResult(n, _) = a.write(vec![7u8; 100]).await;
    assert_eq!(n.unwrap(), 4, "writer should accept only its cap");

    let buf = Vec::with_capacity(100);
    let compio_buf::BufResult(n, _) = b.read(buf).await;
    assert_eq!(n.unwrap(), 4);
}

#[compio::test]
async fn close_write_yields_clean_end_of_stream_after_draining() {
    let (mut a, mut b) = duplex();

    let compio_buf::BufResult(n, _) = a.write(b"tail".to_vec()).await;
    assert_eq!(n.unwrap(), 4);
    a.close_write();

    // Buffered bytes arrive first...
    let buf = Vec::with_capacity(16);
    let compio_buf::BufResult(n, buf) = b.read(buf).await;
    assert_eq!(n.unwrap(), 4);
    assert_eq!(&buf, b"tail");

    // ...then end-of-stream, repeatedly and without error.
    for _ in 0..2 {
        let buf = Vec::with_capacity(16);
        let compio_buf::BufResult(n, _) = b.read(buf).await;
        assert_eq!(n.unwrap(), 0);
    }
}

#[compio::test]
async fn injected_errors_surface_once() {
    let (mut a, mut b) = duplex();
    b.set_faults(Faults {
        read_error: Some(std::io::ErrorKind::ConnectionReset),
        ..Default::default()
    });

    let buf = Vec::with_capacity(16);
    let compio_buf::BufResult(r, _) = b.read(buf).await;
    assert_eq!(r.unwrap_err().kind(), std::io::ErrorKind::ConnectionReset);

    // The fault is one-shot, so normal operation resumes.
    let compio_buf::BufResult(n, _) = a.write(b"ok".to_vec()).await;
    assert_eq!(n.unwrap(), 2);
    let buf = Vec::with_capacity(16);
    let compio_buf::BufResult(n, _) = b.read(buf).await;
    assert_eq!(n.unwrap(), 2);
}

/// A stalled write must stay pending rather than reporting zero progress.
#[compio::test]
async fn stalled_writes_never_complete() {
    let (mut a, _b) = duplex();
    a.set_faults(Faults {
        stall_writes: true,
        ..Default::default()
    });

    let write = a.write(vec![1u8; 16]);
    let timeout = compio::time::timeout(Duration::from_millis(50), write).await;
    assert!(timeout.is_err(), "stalled write should not have completed");
}

#[compio::test]
async fn reads_park_until_data_arrives() {
    let (mut a, mut b) = duplex();

    // No data yet: the read must park, not spin or return zero.
    let buf = Vec::with_capacity(8);
    let early = compio::time::timeout(Duration::from_millis(20), b.read(buf)).await;
    assert!(early.is_err(), "read should have parked with no data");

    let compio_buf::BufResult(n, _) = a.write(b"late".to_vec()).await;
    assert_eq!(n.unwrap(), 4);

    let buf = Vec::with_capacity(8);
    let compio_buf::BufResult(n, buf) = b.read(buf).await;
    assert_eq!(n.unwrap(), 4);
    assert_eq!(&buf, b"late");
}
