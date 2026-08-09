//! Counts write syscalls on the async OpenSSL write path.
//!
//! OpenSSL splits a write into <=16 KiB TLS records and issues one `BIO_write` per
//! record, which becomes one `write(2)` per record on the socket. These tests make
//! that visible by counting `poll_write` calls on the underlying stream, and show
//! that a `BufWriter` collapses them into a handful of large writes.
//!
//! This is the mechanism behind the throughput difference measured by
//! `benches/write_throughput.rs`.

use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufWriter, ReadBuf};
use tokio::net::{TcpListener, TcpStream};

use crate::utils::{
    create_openssl_acceptor_builder, create_openssl_connector_builder, ssl_gen::mk_self_signed_cert,
};

const PAYLOAD: usize = 1 << 20;
const RECORD_SIZE: usize = 16 << 10;
const BUFWRITER_CAPACITY: usize = 1 << 20;

/// Wraps a stream and counts `poll_write` calls, each of which is one `write(2)`.
struct CountingStream<S> {
    inner: S,
    writes: Arc<AtomicUsize>,
}

impl<S> CountingStream<S> {
    fn new(inner: S) -> (Self, Arc<AtomicUsize>) {
        let writes = Arc::new(AtomicUsize::new(0));
        (
            Self {
                inner,
                writes: writes.clone(),
            },
            writes,
        )
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for CountingStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for CountingStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let res = Pin::new(&mut self.inner).poll_write(cx, buf);
        // Only a completed write reached the kernel; Pending did not.
        if res.is_ready() {
            self.writes.fetch_add(1, Ordering::Relaxed);
        }
        res
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Sends `PAYLOAD` bytes over TLS and returns the number of write syscalls it took,
/// excluding the handshake.
async fn count_writes(buffered: bool) -> usize {
    let listener = TcpListener::bind("localhost:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let (cert, key) = mk_self_signed_cert(vec!["localhost".to_string()]).unwrap();
    let acceptor = create_openssl_acceptor_builder(&cert, &key).build();

    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        tcp.set_nodelay(true).unwrap();
        let ssl = openssl::ssl::Ssl::new(acceptor.context()).unwrap();
        let mut server = openssl_ktls::TokioSslStream::new(tcp, ssl).unwrap();
        server.accept().await.unwrap();

        let mut remaining = PAYLOAD;
        let mut buf = vec![0_u8; 64 << 10];
        while remaining > 0 {
            let n = server.read(&mut buf).await.unwrap();
            assert_ne!(n, 0, "server hit EOF with {remaining} bytes outstanding");
            remaining -= n;
        }
    });

    let tcp = TcpStream::connect(addr).await.unwrap();
    tcp.set_nodelay(true).unwrap();
    let (counting, writes) = CountingStream::new(tcp);

    let ssl = create_openssl_connector_builder(&cert)
        .build()
        .configure()
        .unwrap()
        .into_ssl("localhost")
        .unwrap();

    let payload = vec![0x5a_u8; PAYLOAD];

    if buffered {
        let mut client = tokio_openssl::SslStream::new(
            ssl,
            BufWriter::with_capacity(BUFWRITER_CAPACITY, counting),
        )
        .unwrap();
        Pin::new(&mut client).connect().await.unwrap();
        // Exclude handshake writes.
        writes.store(0, Ordering::Relaxed);
        client.write_all(&payload).await.unwrap();
        client.flush().await.unwrap();
    } else {
        let mut client = tokio_openssl::SslStream::new(ssl, counting).unwrap();
        Pin::new(&mut client).connect().await.unwrap();
        writes.store(0, Ordering::Relaxed);
        client.write_all(&payload).await.unwrap();
        client.flush().await.unwrap();
    }

    server.await.unwrap();
    writes.load(Ordering::Relaxed)
}

#[tokio::test]
async fn unbuffered_writes_once_per_tls_record() {
    let writes = count_writes(false).await;
    let records = PAYLOAD / RECORD_SIZE;
    println!("unbuffered: {writes} write syscalls for {records} records ({PAYLOAD} bytes)");

    // One write syscall per TLS record. Allow slack for WouldBlock retries and for
    // OpenSSL choosing a smaller split_send_fragment.
    assert!(
        writes >= records,
        "expected at least {records} writes (one per record), got {writes}"
    );
}

#[tokio::test]
async fn bufwriter_coalesces_records_into_few_writes() {
    let buffered = count_writes(true).await;
    let unbuffered = count_writes(false).await;
    println!("buffered: {buffered} write syscalls vs unbuffered: {unbuffered}");

    // PAYLOAD fits in one BufWriter buffer, so it should take a small number of
    // large writes rather than one per record.
    assert!(
        buffered * 8 < unbuffered,
        "expected buffered writes ({buffered}) to be far below unbuffered ({unbuffered})"
    );
}
