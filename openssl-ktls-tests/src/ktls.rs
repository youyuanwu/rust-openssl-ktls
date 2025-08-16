use std::io::{Read, Write};

use openssl_ktls::option::SSL_OP_ENABLE_KTLS;

use crate::utils::{HELLO, create_openssl_acceptor_builder, create_openssl_connector_with_ktls};

#[test]
fn ktls_test() {
    let l = std::net::TcpListener::bind("localhost:0").unwrap();
    let l_addr = l.local_addr().unwrap();

    let (cert, key_pair) =
        crate::utils::ssl_gen::mk_self_signed_cert(vec!["localhost".to_string()]).unwrap();

    let mut ssl_acpt_builder = create_openssl_acceptor_builder(&cert, &key_pair);

    // Set ktls and KTLS-compatible ciphers for TLS 1.2
    ssl_acpt_builder.set_options(SSL_OP_ENABLE_KTLS);

    let ssl_acpt = ssl_acpt_builder.build();

    let ssl_con = create_openssl_connector_with_ktls(&cert)
        .configure()
        .unwrap();

    let svr = std::thread::spawn(move || {
        println!("accept server tcp");
        let (s, _) = l.accept().unwrap();

        // Create SSL from the acceptor context for BIOSocketStream
        let ssl_ctx = ssl_acpt.context();
        let ssl = openssl::ssl::Ssl::new(ssl_ctx).unwrap();

        println!("accept server ssl");
        let mut ssl_s = openssl_ktls::SslStream::new(s, ssl);
        ssl_s.accept().unwrap();

        // check ktls on server side
        let server_send = ssl_s.ktls_send_enabled();
        let server_recv = ssl_s.ktls_recv_enabled();
        println!("KTLS server send: {server_send}, recv: {server_recv}");

        println!("server read");
        let mut buf = [0_u8; 100];
        let len = ssl_s.read(buf.as_mut_slice()).unwrap();
        assert_eq!(len, HELLO.len());
        assert_eq!(&buf[0..len], HELLO.as_bytes());

        // write back 2 hellos
        println!("server write");
        ssl_s.write_all(HELLO.as_bytes()).unwrap();
        println!("server write2");
        ssl_s.write_all(HELLO.as_bytes()).unwrap();
        ssl_s.shutdown().unwrap();
    });

    {
        println!("client tcp conn");
        let stream = std::net::TcpStream::connect(l_addr).unwrap();

        let ctx = ssl_con.into_ssl("localhost").unwrap();

        // KTLS is already configured in the connector, no need for additional setup

        let mut ssl_s = openssl_ktls::SslStream::new(stream, ctx);
        println!("client ssl conn");
        ssl_s.connect().unwrap();

        // Check KTLS on client side
        let client_send = ssl_s.ktls_send_enabled();
        let client_recv = ssl_s.ktls_recv_enabled();
        println!("KTLS client send: {client_send}, recv: {client_recv}");

        println!("client ssl write");
        let len = ssl_s.write(HELLO.as_bytes()).unwrap();
        assert_eq!(len, HELLO.len());

        std::thread::sleep(std::time::Duration::from_secs(5));
        let mut data = Vec::new();
        loop {
            let mut buf = [0_u8; 100];
            let len = ssl_s.read(buf.as_mut_slice()).unwrap();
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
        ssl_s.shutdown().unwrap();
    }

    svr.join().unwrap();
}
