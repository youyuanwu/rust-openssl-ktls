use std::{
    io::{self, Read, Write},
    mem,
    os::fd::AsRawFd,
};

use libc::{SOL_TCP, SOL_TLS, TCP_ULP, TLS_RX, TLS_TX, tls12_crypto_info_aes_gcm_128};
use openssl_ktls::kbio::ffi::SSL_OP_ENABLE_KTLS;

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

#[test]
fn ktls_test() {
    let l = std::net::TcpListener::bind("localhost:0").unwrap();
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

    let svr = std::thread::spawn(move || {
        println!("accept server tcp");
        let (s, _) = l.accept().unwrap();

        // Create SSL from the acceptor context for BIOSocketStream
        let ssl_ctx = ssl_acpt.context();
        let ssl = openssl::ssl::Ssl::new(ssl_ctx).unwrap();

        println!("accept server ssl");
        let mut ssl_s = unsafe { openssl_ktls::BIOSocketStream::new(s.as_raw_fd(), ssl) };
        ssl_s.accept().unwrap();

        // check ktls on server side
        use foreign_types_shared::ForeignTypeRef;
        let rbio = unsafe { openssl_sys::SSL_get_wbio(ssl_s.ssl().as_ptr()) };
        println!("Server rbio ptr: {rbio:?}");
        println!(
            "Server cipher: {:?}",
            ssl_s.ssl().current_cipher().map(|c| c.name())
        );
        println!("Server version: {:?}", ssl_s.ssl().version_str());

        let send_enabled = unsafe { openssl_ktls::kbio::ffi::BIO_get_ktls_send(rbio) };
        println!("Server KTLS send enabled: {send_enabled}");

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

    std::thread::sleep(std::time::Duration::from_secs(1));

    {
        println!("client tcp conn");
        let stream = std::net::TcpStream::connect(l_addr).unwrap();

        let ctx = ssl_con.into_ssl("localhost").unwrap();

        // KTLS is already configured in the connector, no need for additional setup

        let mut ssl_s = unsafe { openssl_ktls::BIOSocketStream::new(stream.as_raw_fd(), ctx) };
        println!("client ssl conn");
        ssl_s.connect().unwrap();

        // Debug: Check all BIOs in the chain
        use foreign_types_shared::ForeignTypeRef;
        let rbio = unsafe { openssl_sys::SSL_get_rbio(ssl_s.ssl().as_ptr()) };
        println!("rbio ptr: {rbio:?}");
        println!(
            "Client cipher: {:?}",
            ssl_s.ssl().current_cipher().map(|c| c.name())
        );
        println!("Client version: {:?}", ssl_s.ssl().version_str());

        // Also check the first BIO (Rust BIO)
        let client_send = unsafe { openssl_ktls::kbio::ffi::BIO_get_ktls_send(rbio) };
        println!("KTLS send enabled on client: {client_send}");

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
    }

    svr.join().unwrap();
}
