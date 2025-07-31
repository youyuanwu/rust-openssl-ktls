use std::{io, mem, os::fd::AsRawFd};

use libc::{SOL_TCP, SOL_TLS, TCP_ULP, TLS_RX, TLS_TX, tls12_crypto_info_aes_gcm_128};
use openssl_ktls::kbio::ffi::SSL_OP_ENABLE_KTLS;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::utils::{HELLO, create_openssl_acceptor_builder, create_openssl_connector_with_ktls};

#[allow(dead_code)]
unsafe fn set_sock(
    socket: &std::net::TcpStream,
    tx: &tls12_crypto_info_aes_gcm_128,
    rx: &tls12_crypto_info_aes_gcm_128,
) -> io::Result<()> {
    const INFO_SIZE: usize = mem::size_of::<tls12_crypto_info_aes_gcm_128>();

    let socket = socket.as_raw_fd();

    if unsafe { libc::setsockopt(socket, SOL_TCP, TCP_ULP, c"tls".as_ptr() as _, 4) } < 0 {
        return Err(io::Error::last_os_error());
    }

    if unsafe {
        libc::setsockopt(
            socket,
            SOL_TLS,
            TLS_TX as _,
            tx as *const _ as _,
            INFO_SIZE as _,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }

    if unsafe {
        libc::setsockopt(
            socket,
            SOL_TLS,
            TLS_RX as _,
            rx as *const _ as _,
            INFO_SIZE as _,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }

    Ok(())
}

#[tokio::test]
async fn async_ktls_test() {
    let l = tokio::net::TcpListener::bind("localhost:0").await.unwrap();
    let l_addr = l.local_addr().unwrap();

    let (cert, key_pair) =
        crate::utils::ssl_gen::mk_self_signed_cert(vec!["localhost".to_string()]).unwrap();

    let ssl_acpt_builder = create_openssl_acceptor_builder(&cert, &key_pair);

    // Set ktls and KTLS-compatible ciphers for TLS 1.2
    let ptr = ssl_acpt_builder.as_ptr();
    unsafe {
        openssl_sys::SSL_CTX_set_options(ptr, SSL_OP_ENABLE_KTLS);
        // Use TLS 1.2 with KTLS-compatible cipher suite
        let cipher_list = std::ffi::CString::new("ECDHE-RSA-AES128-GCM-SHA256").unwrap();
        openssl_sys::SSL_CTX_set_cipher_list(ptr, cipher_list.as_ptr());
    };

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
        let mut ssl_s = openssl_ktls::kbio::create_async_bio_socket_stream(tcp_stream, ssl)
            .await
            .unwrap();

        println!("accept server ssl");
        ssl_s.accept().await.unwrap();

        // Check KTLS on server side
        println!("checking KTLS on server side");
        let send_enabled = {
            use foreign_types_shared::ForeignTypeRef;
            let wbio = unsafe { openssl_sys::SSL_get_wbio(ssl_s.ssl().as_ptr()) };
            println!("Server wbio ptr: {wbio:?}");
            println!(
                "Server cipher: {:?}",
                ssl_s.ssl().current_cipher().map(|c| c.name())
            );
            println!("Server version: {:?}", ssl_s.ssl().version_str());

            unsafe { openssl_ktls::kbio::ffi::BIO_get_ktls_send(wbio) }
        };
        println!("Server KTLS send enabled: {send_enabled}");

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
        let mut ssl_s = openssl_ktls::kbio::create_async_bio_socket_stream(tcp_stream, ssl)
            .await
            .unwrap();

        println!("client ssl conn");
        ssl_s.connect().await.unwrap();

        // Debug: Check all BIOs in the chain
        println!("checking KTLS on client side");
        let client_send = {
            use foreign_types_shared::ForeignTypeRef;
            let rbio = unsafe { openssl_sys::SSL_get_rbio(ssl_s.ssl().as_ptr()) };
            println!("Client rbio ptr: {rbio:?}");
            println!(
                "Client cipher: {:?}",
                ssl_s.ssl().current_cipher().map(|c| c.name())
            );
            println!("Client version: {:?}", ssl_s.ssl().version_str());

            unsafe { openssl_ktls::kbio::ffi::BIO_get_ktls_send(rbio) }
        };
        println!("KTLS send enabled on client: {client_send}");

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
