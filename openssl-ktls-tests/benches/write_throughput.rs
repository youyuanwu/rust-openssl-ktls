//! Write-throughput benchmarks for the async OpenSSL write paths.
//!
//! OpenSSL splits a write into `max_send_fragment` (<=16 KiB) TLS records and issues
//! one `BIO_write` per record, so a large `SSL_write` becomes one `write(2)` syscall
//! per record. These benchmarks measure what that costs and how much KTLS or
//! userspace coalescing recovers.
//!
//! Run with `cargo bench --bench write_throughput`. See `docs/Benchmarks.md`.

use std::pin::Pin;
use std::sync::Arc;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use openssl::ssl::Ssl;
use openssl_ktls_tests::utils::{
    create_openssl_acceptor_builder, create_openssl_connector_builder,
    create_openssl_connector_with_ktls, ssl_gen::mk_self_signed_cert,
};
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt, BufWriter};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

/// Payload sizes spanning sub-record, exactly-one-record, and many-record writes.
const PAYLOAD_SIZES: &[usize] = &[1 << 10, 16 << 10, 64 << 10, 1 << 20, 8 << 20];

/// Must exceed the 16 KiB TLS record size, otherwise `BufWriter` passes each record
/// straight through and no coalescing happens.
const BUFWRITER_CAPACITY: usize = 1 << 20;

const DRAIN_BUFFER: usize = 256 << 10;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Variant {
    /// `openssl-ktls` with `SSL_OP_ENABLE_KTLS`: the kernel frames records, one `sendmsg`.
    Ktls,
    /// `openssl-ktls` without KTLS: OpenSSL's native socket BIO, one `write` per record.
    SocketBio,
    /// `tokio-openssl`: rust-openssl's custom BIO calling `poll_write` per record.
    CustomBio,
    /// `tokio-openssl` over a `BufWriter`: records coalesced into one `write` per flush.
    CustomBioBuffered,
    /// `tokio-rustls` using the OpenSSL-backed rustls crypto provider.
    RustlsOpenSsl,
}

impl Variant {
    const ALL: [Variant; 5] = [
        Variant::Ktls,
        Variant::SocketBio,
        Variant::CustomBio,
        Variant::CustomBioBuffered,
        Variant::RustlsOpenSsl,
    ];

    fn name(self) -> &'static str {
        match self {
            Variant::Ktls => "openssl_ktls_ktls",
            Variant::SocketBio => "openssl_ktls_socket_bio",
            Variant::CustomBio => "tokio_openssl_custom_bio",
            Variant::CustomBioBuffered => "tokio_openssl_bufwriter",
            Variant::RustlsOpenSsl => "rustls_openssl",
        }
    }
}

/// Which tokio scheduler drives the writer and the drain task.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Flavor {
    /// Writer and drain share one thread, so a reader wakeup is a task switch rather
    /// than a cross-core wakeup.
    CurrentThread,
    /// Writer and drain can land on separate cores, as in the original measurements.
    MultiThread,
}

impl Flavor {
    const ALL: [Flavor; 2] = [Flavor::CurrentThread, Flavor::MultiThread];

    fn name(self) -> &'static str {
        match self {
            Flavor::CurrentThread => "current_thread",
            Flavor::MultiThread => "multi_thread",
        }
    }

    fn build(self) -> tokio::runtime::Runtime {
        match self {
            Flavor::CurrentThread => tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("bench runtime"),
            Flavor::MultiThread => tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .expect("bench runtime"),
        }
    }
}

/// An established TLS connection whose client half is the thing under measurement.
struct Peer {
    client: Box<dyn AsyncWrite + Send + Unpin>,
    /// Kept alive so the accepted connection is not torn down mid-benchmark.
    _server: openssl_ktls::TokioSslStream,
    drain: tokio::task::JoinHandle<()>,
}

impl Drop for Peer {
    fn drop(&mut self) {
        self.drain.abort();
    }
}

/// Drains raw ciphertext from a duplicate of the server's socket.
///
/// The server completes the handshake but never decrypts application data. That keeps
/// the peer's AES-GCM cost out of the critical path so the measurement reflects the
/// sender's write path rather than the receiver's throughput.
fn spawn_raw_drain(server: &openssl_ktls::TokioSslStream) -> tokio::task::JoinHandle<()> {
    let raw = server
        .get_ref()
        .try_clone()
        .expect("duplicate server socket");
    raw.set_nonblocking(true).expect("set nonblocking");
    let mut raw = TcpStream::from_std(raw).expect("register duplicated socket");

    tokio::spawn(async move {
        let mut buf = vec![0_u8; DRAIN_BUFFER];
        loop {
            match raw.read(&mut buf).await {
                Ok(0) => break,
                // A dead drain would make every subsequent write larger than the socket
                // buffers block forever inside the timed closure, so fail loudly.
                Err(e) => panic!("benchmark drain failed: {e}"),
                Ok(_) => {}
            }
        }
    })
}

/// Establishes a loopback TLS connection for `variant`.
///
/// Returns `None` when the variant is unavailable on this host, which currently only
/// happens for [`Variant::Ktls`] if the kernel `tls` module is not loaded.
async fn connect(
    variant: Variant,
    cert: &openssl::x509::X509,
    key: &openssl::pkey::PKey<openssl::pkey::Private>,
) -> Option<Peer> {
    let listener = TcpListener::bind("localhost:0")
        .await
        .expect("bind loopback listener");
    let addr = listener.local_addr().expect("listener address");

    // The same plain (non-KTLS) server is used for every variant so the peer is a
    // constant across the matrix.
    let acceptor = create_openssl_acceptor_builder(cert, key).build();

    let server_fut = async {
        let (tcp, _) = listener.accept().await.expect("accept");
        tcp.set_nodelay(true).expect("server nodelay");
        let ssl = Ssl::new(acceptor.context()).expect("server ssl");
        let mut server = openssl_ktls::TokioSslStream::new(tcp, ssl).expect("server stream");
        server.accept().await.expect("server handshake");
        server
    };

    let client_fut = async {
        let tcp = TcpStream::connect(addr).await.expect("client connect");
        tcp.set_nodelay(true).expect("client nodelay");
        build_client(variant, cert, tcp).await
    };

    let (server, client) = tokio::join!(server_fut, client_fut);
    let client = client?;
    let drain = spawn_raw_drain(&server);

    Some(Peer {
        client,
        _server: server,
        drain,
    })
}

async fn build_client(
    variant: Variant,
    cert: &openssl::x509::X509,
    tcp: TcpStream,
) -> Option<Box<dyn AsyncWrite + Send + Unpin>> {
    match variant {
        Variant::Ktls | Variant::SocketBio => {
            let connector = if variant == Variant::Ktls {
                create_openssl_connector_with_ktls(cert)
            } else {
                create_openssl_connector_builder(cert).build()
            };
            let ssl = connector
                .configure()
                .expect("client config")
                .into_ssl("localhost")
                .expect("client ssl");

            let client = openssl_ktls::TokioSslStream::new(tcp, ssl).expect("client stream");
            client.connect().await.expect("client handshake");

            if variant == Variant::Ktls && !client.ktls_send_enabled() {
                return None;
            }
            Some(Box::new(client))
        }
        Variant::CustomBio | Variant::CustomBioBuffered => {
            let ssl = create_openssl_connector_builder(cert)
                .build()
                .configure()
                .expect("client config")
                .into_ssl("localhost")
                .expect("client ssl");

            if variant == Variant::CustomBio {
                let mut client = tokio_openssl::SslStream::new(ssl, tcp).expect("client stream");
                Pin::new(&mut client)
                    .connect()
                    .await
                    .expect("client handshake");
                Some(Box::new(client))
            } else {
                let buffered = BufWriter::with_capacity(BUFWRITER_CAPACITY, tcp);
                let mut client =
                    tokio_openssl::SslStream::new(ssl, buffered).expect("client stream");
                Pin::new(&mut client)
                    .connect()
                    .await
                    .expect("client handshake");
                Some(Box::new(client))
            }
        }
        Variant::RustlsOpenSsl => {
            let mut roots = RootCertStore::empty();
            roots
                .add(CertificateDer::from(
                    cert.to_der().expect("certificate DER"),
                ))
                .expect("trusted certificate");

            let config =
                ClientConfig::builder_with_provider(Arc::new(rustls_openssl::default_provider()))
                    .with_safe_default_protocol_versions()
                    .expect("protocol versions")
                    .with_root_certificates(roots)
                    .with_no_client_auth();
            let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
            let server_name = ServerName::try_from("localhost").expect("server name");
            let client = connector
                .connect(server_name, tcp)
                .await
                .expect("client handshake");
            Some(Box::new(client))
        }
    }
}

fn bench_write_throughput(c: &mut Criterion) {
    let (cert, key) = mk_self_signed_cert(vec!["localhost".to_string()]).expect("self signed cert");

    let mut group = c.benchmark_group("tls_write");

    for flavor in Flavor::ALL {
        // A `TcpStream` is bound to the reactor that registered it, so every flavor gets
        // its own runtime and its own connections.
        let rt = flavor.build();

        for variant in Variant::ALL {
            let peer = match rt.block_on(connect(variant, &cert, &key)) {
                Some(peer) => Arc::new(Mutex::new(peer)),
                None => {
                    eprintln!(
                        "skipping {}_{}: KTLS send not enabled (is the kernel `tls` module loaded?)",
                        variant.name(),
                        flavor.name()
                    );
                    continue;
                }
            };
            let bench_name = format!("{}_{}", variant.name(), flavor.name());

            for &size in PAYLOAD_SIZES {
                let payload = Arc::new(vec![0x5a_u8; size]);
                group.throughput(Throughput::Bytes(size as u64));
                group.bench_with_input(BenchmarkId::new(&bench_name, size), &size, |b, _| {
                    b.to_async(&rt).iter(|| {
                        let peer = peer.clone();
                        let payload = payload.clone();
                        async move {
                            let mut peer = peer.lock().await;
                            assert!(
                                !peer.drain.is_finished(),
                                "drain task stopped; the write below would block forever"
                            );
                            peer.client.write_all(&payload).await.expect("write");
                            // Required for the BufWriter variant; a no-op for the others.
                            peer.client.flush().await.expect("flush");
                        }
                    });
                });
            }
        }
    }

    group.finish();
}

criterion_group!(benches, bench_write_throughput);
criterion_main!(benches);
