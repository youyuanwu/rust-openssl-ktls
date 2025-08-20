use openssl::ssl::SslAcceptor;
use openssl_ktls::async_mode::AsyncThread;
use rand::Rng;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    task::JoinSet,
};
use tokio_util::sync::CancellationToken;

use crate::{
    SSL_TEST_SEMAPHORE,
    utils::{HELLO, TestMode, create_openssl_acceptor_builder, create_openssl_connector_with_ktls},
};

async fn async_stream_test_internal(test_mode: TestMode) {
    let l = tokio::net::TcpListener::bind("localhost:0").await.unwrap();
    let l_addr = l.local_addr().unwrap();

    let (cert, key_pair) =
        crate::utils::ssl_gen::mk_self_signed_cert(vec!["localhost".to_string()]).unwrap();

    let ssl_acpt_builder = create_openssl_acceptor_builder(&cert, &key_pair, test_mode);

    let ssl_acpt = ssl_acpt_builder.build();

    let ssl_con = create_openssl_connector_with_ktls(&cert, test_mode)
        .configure()
        .unwrap();

    // Server task
    let server_task = tokio::spawn(async move {
        println!("accept server tcp");
        let (tcp_stream, _) = l.accept().await.unwrap();

        // Create SSL from the acceptor context for AsyncBIOSocketStream
        let ssl_ctx = ssl_acpt.context();
        let ssl = openssl::ssl::Ssl::new(ssl_ctx).unwrap();

        println!("creating async bio socket stream for server");
        let mut ssl_s = openssl_ktls::TokioSslStream::new(tcp_stream, ssl).unwrap();

        println!("accept server ssl");
        ssl_s.accept().await.unwrap();

        // Check KTLS on server side
        let receive_enabled = ssl_s.ktls_recv_enabled();
        let send_enabled = ssl_s.ktls_send_enabled();
        println!("Server KTLS send enabled: {send_enabled}, recv enabled: {receive_enabled}");

        println!("server read");
        let mut buf = [0_u8; 100];
        let len = ssl_s.read(&mut buf).await.unwrap();
        assert_eq!(len, HELLO.len());
        assert_eq!(&buf[0..len], HELLO.as_bytes());

        // Write back 2 hellos
        println!("server write");
        ssl_s.write_all(HELLO.as_bytes()).await.unwrap();
        println!("server write2");
        ssl_s.write_all(HELLO.as_bytes()).await.unwrap();
        ssl_s.shutdown().await.unwrap();
    });

    // Give server time to start
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Client task
    let client_task = tokio::spawn(async move {
        println!("client tcp conn");
        let tcp_stream = tokio::net::TcpStream::connect(l_addr).await.unwrap();

        let ssl = ssl_con.into_ssl("localhost").unwrap();

        println!("creating async bio socket stream for client");
        let mut ssl_s = openssl_ktls::TokioSslStream::new(tcp_stream, ssl).unwrap();

        println!("client ssl conn");
        ssl_s.connect().await.unwrap();

        // Debug: Check all BIOs in the chain
        println!("checking KTLS on client side");
        let receive_enabled = ssl_s.ktls_recv_enabled();
        let send_enabled = ssl_s.ktls_send_enabled();
        println!("Client KTLS send enabled: {send_enabled}, recv enabled: {receive_enabled}");

        let async_status = openssl_ktls::async_mode::get_async_status(ssl_s.ssl());
        println!("Client async status: {async_status:?}");

        println!("client ssl write");
        let len = ssl_s.write(HELLO.as_bytes()).await.unwrap();
        assert_eq!(len, HELLO.len());

        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        let mut data = Vec::new();
        loop {
            let mut buf = [0_u8; 100];
            let len = ssl_s.read(&mut buf).await.unwrap();
            if len == 0 {
                break;
            }
            data.extend_from_slice(&buf[..len]);
        }
        assert_eq!(
            data.len(),
            2 * HELLO.len(),
            "data: {:?}",
            String::from_utf8_lossy(&data)
        );
    });

    // Wait for both tasks to complete
    let (server_result, client_result) = tokio::join!(server_task, client_task);
    server_result.unwrap();
    client_result.unwrap();

    println!("Async KTLS test completed successfully!");
}

#[tokio::test]
async fn async_stream_test_ktls() {
    // Acquire semaphore to serialize async mode tests (prevents OpenSSL async/engine conflicts)
    let _permit = SSL_TEST_SEMAPHORE.acquire().await.unwrap();
    async_stream_test_internal(TestMode::Ktls).await;
}

#[tokio::test]
async fn async_stream_test_none() {
    // Acquire semaphore to serialize async mode tests (prevents OpenSSL async/engine conflicts)
    let _permit = SSL_TEST_SEMAPHORE.acquire().await.unwrap();
    async_stream_test_internal(TestMode::None).await;
}

#[tokio::test(flavor = "current_thread")]
async fn async_stream_test_async_with_engine() {
    // Acquire semaphore to serialize async mode tests (prevents OpenSSL async/engine conflicts)
    let _permit = SSL_TEST_SEMAPHORE.acquire().await.unwrap();

    println!("Is async capable: {}", AsyncThread::is_capable());
    let _async_thread = AsyncThread::default();

    // Create and register custom async engine
    // This demonstrates how a custom OpenSSL engine can integrate with
    // the async callback system we've implemented
    println!("Creating custom async engine for test...");
    use crate::exp::custom_engine::AsyncEngine;
    let engine = AsyncEngine::new().expect("Failed to create custom async engine");
    assert!(engine.register(), "Failed to register custom async engine");
    async_stream_test_internal(TestMode::Async).await;
    drop(engine);
}

#[tokio::test(flavor = "current_thread")]
async fn async_stream_test_async_no_engine() {
    // Acquire semaphore to serialize async mode tests (prevents OpenSSL async/engine conflicts)
    let _permit = SSL_TEST_SEMAPHORE.acquire().await.unwrap();

    async_stream_test_internal(TestMode::Async).await;
}

async fn graceful_shutdown(stream: &mut openssl_ktls::TokioSslStream) {
    // Perform a graceful shutdown
    match stream.ssl_shutdown().await.unwrap() {
        openssl::ssl::ShutdownResult::Sent => {
            // wait for peer to receive
            let received = stream.ssl_shutdown().await.unwrap();
            assert_eq!(received, openssl::ssl::ShutdownResult::Received);
        }
        openssl::ssl::ShutdownResult::Received => {
            // peer already shutdown.
        }
    }
}

const SERVER_BUFFER_SIZE: usize = 256;
const CLIENT_PAYLOAD_SIZE: usize = 1024 * 32;

async fn echo_server(l: tokio::net::TcpListener, ssl_acpt: SslAcceptor, token: CancellationToken) {
    loop {
        let stream = tokio::select! {
            _ = token.cancelled() => {
                println!("Echo server cancelled");
                return;
            }
            stream = l.accept() => {
                match stream {
                    Ok((stream, _)) => stream,
                    Err(e) => {
                        eprintln!("Failed to accept TCP connection: {e}");
                        continue;
                    }
                }
            }
        };
        let ssl_ctx = ssl_acpt.context();
        let ssl = openssl::ssl::Ssl::new(ssl_ctx).unwrap();
        // process request in another task
        tokio::spawn(async move {
            let mut ssl_stream = openssl_ktls::TokioSslStream::new(stream, ssl).unwrap();

            if let Err(e) = ssl_stream.accept().await {
                eprintln!("Failed to accept SSL stream: {e}");
                return;
            }

            let mut buf = [0_u8; SERVER_BUFFER_SIZE];

            // Read data from the client and echo it back
            loop {
                let n = ssl_stream.read(&mut buf).await.unwrap();
                if n == 0 {
                    break; // EOF
                }
                ssl_stream.write_all(&buf[..n]).await.unwrap();
            }
            graceful_shutdown(&mut ssl_stream).await;
        });
    }
}

async fn echo_client(
    l_addr: std::net::SocketAddr,
    ssl_con: &openssl::ssl::SslConnector,
    payload: &[u8],
    domain: &str,
) -> Result<(), openssl_ktls::error::Error> {
    let ssl = ssl_con.configure().unwrap().into_ssl(domain).unwrap();
    let client = tokio::net::TcpStream::connect(l_addr).await.unwrap();
    let mut ssl_stream = openssl_ktls::TokioSslStream::new(client, ssl).unwrap();

    ssl_stream.connect().await?;

    ssl_stream
        .write_all(payload)
        .await
        .map_err(openssl_ktls::error::Error::from_io)?;
    let mut buf = vec![0_u8; payload.len()];
    let n = ssl_stream
        .read_exact(&mut buf)
        .await
        .map_err(openssl_ktls::error::Error::from_io)?;
    assert_eq!(n, payload.len());
    assert_eq!(&buf[..n], payload);
    graceful_shutdown(&mut ssl_stream).await;
    Ok(())
}

fn generate_random_payload() -> Vec<u8> {
    let mut rng = rand::rng();
    (0..CLIENT_PAYLOAD_SIZE).map(|_| rng.random()).collect()
}

async fn longhaul_client(l_addr: std::net::SocketAddr, ssl_con: &openssl::ssl::SslConnector) {
    let ssl = ssl_con.configure().unwrap().into_ssl("localhost").unwrap();
    let client = tokio::net::TcpStream::connect(l_addr).await.unwrap();
    let mut ssl_stream = openssl_ktls::TokioSslStream::new(client, ssl).unwrap();

    ssl_stream.connect().await.unwrap();

    // generate random payload of random length
    let (payload, send_chunks, receive_chunks_len) = {
        let payload = generate_random_payload();
        let mut rng = rand::rng();
        // make the payload into vec of chunks of random length
        let mut send_chunks = Vec::new();
        let mut offset = 0;
        while offset < payload.len() {
            let chunk_len = rng.random_range(1..=payload.len() - offset);
            send_chunks.push(payload[offset..offset + chunk_len].to_vec());
            offset += chunk_len;
        }
        assert_eq!(offset, payload.len());

        // use receive chunk lengths the same as send chunk lengths.
        let mut receive_chunks_len = send_chunks.iter().map(|c| c.len()).collect::<Vec<_>>();
        use rand::prelude::SliceRandom;
        receive_chunks_len.shuffle(&mut rng);
        assert_eq!(payload.len(), receive_chunks_len.iter().sum::<usize>());

        (payload, send_chunks, receive_chunks_len)
    };

    // split the read and write stream using tokio
    let (mut read_half, mut write_half) = tokio::io::split(ssl_stream);

    let w_h = tokio::spawn(async move {
        for chunk in send_chunks {
            write_half.write_all(&chunk).await.unwrap();
        }
        write_half
    });

    // read the data back with random buf len.
    let mut result_buf = Vec::new();
    for chunk_len in receive_chunks_len {
        let mut buf = vec![0_u8; chunk_len];
        let n = read_half.read_exact(&mut buf).await.unwrap();
        if n == 0 {
            break; // EOF
        }
        result_buf.extend_from_slice(&buf[..n]);
    }
    let write_half = w_h.await.unwrap();

    // check the result is the same as payload
    assert_eq!(result_buf, payload);

    // Merge the streams back together
    let mut ssl_stream = read_half.unsplit(write_half);

    // Now you can use the reunited stream for additional operations
    graceful_shutdown(&mut ssl_stream).await;
}

async fn echo_test(test_mode: TestMode) {
    let l = tokio::net::TcpListener::bind("localhost:0").await.unwrap();
    let (cert, key_pair) =
        crate::utils::ssl_gen::mk_self_signed_cert(vec!["localhost".to_string()]).unwrap();
    let ssl_acpt = create_openssl_acceptor_builder(&cert, &key_pair, test_mode).build();

    let l_addr = l.local_addr().unwrap();

    let token = CancellationToken::new();

    // Start the echo server
    let h_svr = tokio::spawn(echo_server(l, ssl_acpt, token.clone()));

    // Allow some time for the server to start
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    let ssl_con = create_openssl_connector_with_ktls(&cert, test_mode);

    // Client test
    {
        echo_client(l_addr, &ssl_con, HELLO.as_bytes(), "localhost")
            .await
            .unwrap();
    }
    // Client test with bad hostname
    {
        let err = echo_client(l_addr, &ssl_con, b"dummy", "localhost_bad")
            .await
            .unwrap_err();
        assert_eq!(err.code(), openssl::ssl::ErrorCode::SSL);
        assert_eq!(err.ssl_error().unwrap().errors().len(), 1); // bad hostname.
    }
    // send big payload
    {
        let payload = generate_random_payload();
        echo_client(l_addr, &ssl_con, &payload, "localhost")
            .await
            .unwrap();
    }

    // run random test
    let num_client = 10;
    let mut set = JoinSet::new();
    for _ in 0..num_client {
        let ssl_con = ssl_con.clone();
        set.spawn({
            async move {
                longhaul_client(l_addr, &ssl_con).await;
            }
        });
    }
    set.join_all().await;

    token.cancel();
    h_svr.await.unwrap();
}

#[tokio::test]
async fn echo_test_ktls() {
    // Acquire semaphore to serialize async mode tests (prevents OpenSSL async/engine conflicts)
    let _permit = SSL_TEST_SEMAPHORE.acquire().await.unwrap();
    echo_test(TestMode::Ktls).await;
}

#[tokio::test]
async fn echo_test_none() {
    // Acquire semaphore to serialize async mode tests (prevents OpenSSL async/engine conflicts)
    let _permit = SSL_TEST_SEMAPHORE.acquire().await.unwrap();
    echo_test(TestMode::None).await;
}

#[tokio::test]
async fn echo_test_async() {
    // Acquire semaphore to serialize async mode tests (prevents OpenSSL async/engine conflicts)
    let _permit = SSL_TEST_SEMAPHORE.acquire().await.unwrap();

    println!("Is async capable: {}", AsyncThread::is_capable());
    let _async_thread = AsyncThread::default();
    echo_test(TestMode::Async).await;
}

#[tokio::test]
#[ignore = "only one engine test should run. Engine drop is not working."]
async fn echo_test_async_with_engine() {
    // Acquire semaphore to serialize async mode tests (prevents OpenSSL async/engine conflicts)
    let _permit = SSL_TEST_SEMAPHORE.acquire().await.unwrap();

    use crate::exp::custom_engine::AsyncEngine;
    let engine = AsyncEngine::new().expect("Failed to create custom async engine");
    assert!(engine.register(), "Failed to register custom async engine");
    echo_test(TestMode::Async).await;
    drop(engine);
}
