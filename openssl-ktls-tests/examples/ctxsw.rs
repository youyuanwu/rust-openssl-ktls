//! Explains *why* the unbuffered TLS write path causes ~one context switch per record.
//!
//! `benches/write_throughput.rs` shows the cost; this attributes it. For an 8 MiB
//! transfer it counts, on both tokio schedulers:
//!
//! - `writes` — `poll_write` calls that reached the kernel, i.e. `write(2)` syscalls
//! - `writer-blocked` — `Pending` from the writer, i.e. a full socket send buffer
//! - `reader-waits` — `Pending` from the drain task, i.e. it emptied the socket and parked
//! - `ctxsw` — OS context switches summed across every thread of the process
//!
//! The `unbuf/uncon` row wraps the write in [`tokio::task::unconstrained`], which
//! disables tokio's 128-operation coop budget. Any remaining `writer-blocked` there is a
//! genuinely full send buffer rather than a scheduler-forced yield.
//!
//! Run with `cargo run --release --example ctxsw`. See `docs/Benchmarks.md`.

use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};

use openssl::ssl::Ssl;
use openssl_ktls_tests::utils::{
    create_openssl_acceptor_builder, create_openssl_connector_builder, ssl_gen::mk_self_signed_cert,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufWriter, ReadBuf};
use tokio::net::{TcpListener, TcpStream};

const PAYLOAD: usize = 8 << 20;
const ITERS: usize = 20;
const BUFWRITER_CAPACITY: usize = 1 << 20;
const DRAIN_BUFFER: usize = 256 << 10;

#[derive(Default)]
struct Counts {
    writes: AtomicUsize,
    write_pending: AtomicUsize,
    read_pending: AtomicUsize,
}

struct Counting<S> {
    inner: S,
    c: Arc<Counts>,
}

impl<S: AsyncRead + Unpin> AsyncRead for Counting<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let res = Pin::new(&mut self.inner).poll_read(cx, buf);
        if res.is_pending() {
            self.c.read_pending.fetch_add(1, Ordering::Relaxed);
        }
        res
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Counting<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let res = Pin::new(&mut self.inner).poll_write(cx, buf);
        match res {
            Poll::Ready(_) => self.c.writes.fetch_add(1, Ordering::Relaxed),
            Poll::Pending => self.c.write_pending.fetch_add(1, Ordering::Relaxed),
        };
        res
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Sum of voluntary + involuntary context switches across every thread of this process.
fn ctx_switches() -> u64 {
    let mut total = 0;
    for entry in std::fs::read_dir("/proc/self/task").unwrap() {
        let status = match std::fs::read_to_string(entry.unwrap().path().join("status")) {
            Ok(s) => s,
            Err(_) => continue,
        };
        for line in status.lines() {
            if line.starts_with("voluntary_ctxt_switches:")
                || line.starts_with("nonvoluntary_ctxt_switches:")
            {
                total += line
                    .split_whitespace()
                    .nth(1)
                    .unwrap()
                    .parse::<u64>()
                    .unwrap();
            }
        }
    }
    total
}

async fn run(buffered: bool, unconstrained: bool) -> (Arc<Counts>, u64, f64) {
    let listener = TcpListener::bind("localhost:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (cert, key) = mk_self_signed_cert(vec!["localhost".to_string()]).unwrap();
    let acceptor = create_openssl_acceptor_builder(&cert, &key).build();
    let c = Arc::new(Counts::default());

    let server_c = c.clone();
    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        tcp.set_nodelay(true).unwrap();
        let ssl = Ssl::new(acceptor.context()).unwrap();
        let mut s = openssl_ktls::TokioSslStream::new(tcp, ssl).unwrap();
        s.accept().await.unwrap();
        // Drain raw ciphertext from a duplicate of the socket, counting how often the
        // reader finds the socket empty and has to wait.
        let raw = s.get_ref().try_clone().unwrap();
        raw.set_nonblocking(true).unwrap();
        let mut raw = Counting {
            inner: TcpStream::from_std(raw).unwrap(),
            c: server_c,
        };
        let mut buf = vec![0u8; DRAIN_BUFFER];
        while let Ok(n) = raw.read(&mut buf).await {
            if n == 0 {
                break;
            }
        }
        drop(s);
    });

    let tcp = TcpStream::connect(addr).await.unwrap();
    tcp.set_nodelay(true).unwrap();
    let ssl = create_openssl_connector_builder(&cert)
        .build()
        .configure()
        .unwrap()
        .into_ssl("localhost")
        .unwrap();

    let mut client: Box<dyn AsyncWrite + Send + Unpin> = if buffered {
        let s = BufWriter::with_capacity(
            BUFWRITER_CAPACITY,
            Counting {
                inner: tcp,
                c: c.clone(),
            },
        );
        let mut cl = tokio_openssl::SslStream::new(ssl, s).unwrap();
        Pin::new(&mut cl).connect().await.unwrap();
        Box::new(cl)
    } else {
        let s = Counting {
            inner: tcp,
            c: c.clone(),
        };
        let mut cl = tokio_openssl::SslStream::new(ssl, s).unwrap();
        Pin::new(&mut cl).connect().await.unwrap();
        Box::new(cl)
    };

    let payload = vec![0x5a_u8; PAYLOAD];
    // Warm up, then reset so the handshake is excluded.
    client.write_all(&payload).await.unwrap();
    client.flush().await.unwrap();
    c.writes.store(0, Ordering::Relaxed);
    c.write_pending.store(0, Ordering::Relaxed);
    c.read_pending.store(0, Ordering::Relaxed);

    let before = ctx_switches();
    let t0 = std::time::Instant::now();
    for _ in 0..ITERS {
        if unconstrained {
            // Disables tokio's 128-op coop budget, so a Pending from the writer can only
            // mean a genuinely full socket buffer.
            tokio::task::unconstrained(client.write_all(&payload))
                .await
                .unwrap();
            tokio::task::unconstrained(client.flush()).await.unwrap();
        } else {
            client.write_all(&payload).await.unwrap();
            client.flush().await.unwrap();
        }
    }
    let elapsed = t0.elapsed();
    let switches = ctx_switches() - before;

    let mibs = (PAYLOAD * ITERS) as f64 / (1 << 20) as f64 / elapsed.as_secs_f64();
    drop(client);
    let _ = server.await;
    (c, switches, mibs)
}

fn main() {
    for flavor in ["current_thread", "multi_thread"] {
        for (buffered, unconstrained) in [(false, false), (true, false), (false, true)] {
            let rt = if flavor == "current_thread" {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap()
            } else {
                tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(2)
                    .enable_all()
                    .build()
                    .unwrap()
            };
            let (c, switches, mibs) = rt.block_on(run(buffered, unconstrained));
            let per = |v: usize| v as f64 / ITERS as f64;
            println!(
                "{flavor:<15} {:<11} writes/xfer {:>7.1}  writer-blocked {:>7.1}  \
                 reader-waits {:>7.1}  ctxsw/xfer {:>8.1}  {:>7.0} MiB/s",
                match (buffered, unconstrained) {
                    (true, _) => "buffered",
                    (false, true) => "unbuf/uncon",
                    (false, false) => "unbuffered",
                },
                per(c.writes.load(Ordering::Relaxed)),
                per(c.write_pending.load(Ordering::Relaxed)),
                per(c.read_pending.load(Ordering::Relaxed)),
                switches as f64 / ITERS as f64,
                mibs,
            );
        }
    }
}
