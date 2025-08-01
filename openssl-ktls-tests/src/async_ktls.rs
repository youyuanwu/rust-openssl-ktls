use openssl_ktls::option::SSL_OP_ENABLE_KTLS;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::utils::{HELLO, create_openssl_acceptor_builder, create_openssl_connector_with_ktls};

#[tokio::test]
async fn async_ktls_test() {
    let l = tokio::net::TcpListener::bind("localhost:0").await.unwrap();
    let l_addr = l.local_addr().unwrap();

    let (cert, key_pair) =
        crate::utils::ssl_gen::mk_self_signed_cert(vec!["localhost".to_string()]).unwrap();

    let mut ssl_acpt_builder = create_openssl_acceptor_builder(&cert, &key_pair);

    // Set ktls
    ssl_acpt_builder.set_options(SSL_OP_ENABLE_KTLS);

    let ssl_acpt = ssl_acpt_builder.build();

    let ssl_con = create_openssl_connector_with_ktls(&cert)
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
