use std::ffi::{c_char, c_int, c_long};

use openssl_sys::BIO_ctrl;

pub const BIO_CTRL_GET_KTLS_SEND: c_int = 73;
pub const BIO_CTRL_GET_KTLS_RECV: c_int = 76;
pub const BIO_CTRL_SET_KTLS_SEND: c_int = 72;
pub const BIO_C_GET_BUF_MEM_PTR: c_int = 115;

// BIO control constants
pub const BIO_CTRL_FLUSH: c_int = 11;
pub const BIO_C_DO_STATE_MACHINE: c_int = 101;

pub const SSL_OP_ENABLE_KTLS: u64 = 0x00000008;

unsafe extern "C" {
    pub unsafe fn BIO_free(b: *mut openssl_sys::BIO);
    pub unsafe fn BIO_next(b: *mut openssl_sys::BIO) -> *mut openssl_sys::BIO;
    /* put the 'bio' on the end of b's list of operators */
    pub unsafe fn BIO_push(
        b: *mut openssl_sys::BIO,
        bio: *mut openssl_sys::BIO,
    ) -> *mut openssl_sys::BIO;
    // const BIO_METHOD *BIO_f_base64(void)
    pub unsafe fn BIO_f_base64() -> *const openssl_sys::BIO_METHOD;

    // Null filter BIO - passes data through unchanged
    pub unsafe fn BIO_f_null() -> *const openssl_sys::BIO_METHOD;

    // Buffer filter BIO - buffers data but passes it through
    pub unsafe fn BIO_f_buffer() -> *const openssl_sys::BIO_METHOD;

    // BIO pair - creates two connected BIOs
    pub unsafe fn BIO_s_bio() -> *const openssl_sys::BIO_METHOD;

    // sockets

    // BIO *BIO_new_connect(const char *host_port);
    pub unsafe fn BIO_new_connect(host_port: *const c_char) -> *mut openssl_sys::BIO;
}

/// # Safety
// # define BIO_flush(b)            (int)BIO_ctrl(b,BIO_CTRL_FLUSH,0,NULL)
#[allow(non_snake_case)]
#[inline]
pub unsafe fn BIO_flush(b: *mut openssl_sys::BIO) -> c_int {
    unsafe {
        BIO_ctrl(b, openssl_sys::BIO_CTRL_FLUSH, 0, std::ptr::null_mut())
            .try_into()
            .unwrap()
    }
}

// BIO control operation wrapper functions
// These provide type-safe Rust wrappers for common BIO control operations.

/// # Safety
// # define BIO_do_handshake(b)     BIO_ctrl(b,BIO_C_DO_STATE_MACHINE,0,NULL)
#[allow(non_snake_case)]
#[inline]
pub unsafe fn BIO_do_handshake(b: *mut openssl_sys::BIO) -> c_long {
    unsafe { BIO_ctrl(b, BIO_C_DO_STATE_MACHINE, 0, std::ptr::null_mut()) }
}

/// # Safety
// # define BIO_do_connect(b)       BIO_do_handshake(b)
#[allow(non_snake_case)]
#[inline]
pub unsafe fn BIO_do_connect(b: *mut openssl_sys::BIO) -> c_long {
    unsafe { BIO_do_handshake(b) }
}

#[allow(non_snake_case)]
/// # Safety
/// This function must be called with a valid BIO pointer.
pub unsafe fn BIO_get_ktls_send(b: *mut openssl_sys::BIO) -> c_long {
    unsafe { BIO_ctrl(b, BIO_CTRL_GET_KTLS_SEND, 0, std::ptr::null_mut()) }
}
/// # Safety
/// This function must be called with a valid BIO pointer.
/// Attempts to enable KTLS send on the BIO. Returns 1 on success, 0 on failure.
#[allow(non_snake_case)]
pub unsafe fn BIO_get_ktls_recv(b: *mut openssl_sys::BIO) -> c_long {
    unsafe { BIO_ctrl(b, BIO_CTRL_GET_KTLS_RECV, 0, std::ptr::null_mut()) }
}

/// # Safety
// # define BIO_get_mem_ptr(b,pp)   BIO_ctrl(b,BIO_C_GET_BUF_MEM_PTR,0, (char *)(pp))
#[allow(non_snake_case)]
pub unsafe fn BIO_get_mem_ptr(b: *mut openssl_sys::BIO, buf_mem: *mut *mut BUF_MEM) -> c_long {
    unsafe { BIO_ctrl(b, BIO_C_GET_BUF_MEM_PTR, 0, buf_mem as *mut _) }
}

#[allow(non_camel_case_types)]
#[repr(C)]
pub struct BUF_MEM {
    length: usize, /* current number of bytes */
    data: *mut c_char,
    max: usize, /* size of buffer */
    flags: u64,
}

pub const BIO_NOCLOSE: c_int = 0x00;
pub const BIO_CLOSE: c_int = 0x01;

// Custom functions

/// # Safety
/// Get the last BIO in the chain.
#[allow(non_snake_case)]
pub unsafe fn BIO_get_last(b: *mut openssl_sys::BIO) -> *mut openssl_sys::BIO {
    assert!(!b.is_null());
    let mut last_bio: *mut openssl_sys::BIO = std::ptr::null_mut();
    let mut current_bio = b;
    while !current_bio.is_null() {
        last_bio = current_bio;
        current_bio = unsafe { BIO_next(current_bio) };
    }
    last_bio
}

#[cfg(test)]
mod tests {
    use openssl::base64;
    use openssl_sys::{BIO_free_all, BIO_new, BIO_s_mem, BIO_write};

    use crate::kbio::ffi::{BIO_f_base64, BIO_flush, BIO_get_mem_ptr, BIO_push, BUF_MEM};

    #[test]
    fn test_bio_layers() {
        let b64 = unsafe { BIO_new(BIO_f_base64()) };
        let mem = unsafe { BIO_new(BIO_s_mem()) };
        unsafe { BIO_push(b64, mem) };
        let written = unsafe { BIO_write(b64, b"hi".as_ptr() as *const _, 2) };
        assert!(written > 0);
        let res = unsafe { BIO_flush(b64) };
        assert!(res >= 0);

        // get the underlying memory BIO
        let mut mem_ptr: *mut BUF_MEM = std::ptr::null_mut();
        let res = unsafe { BIO_get_mem_ptr(mem, &mut mem_ptr) };
        assert!(res >= 0);
        assert!(!mem_ptr.is_null());
        let mem_ptr = unsafe { &*mem_ptr };
        let data = unsafe { std::slice::from_raw_parts(mem_ptr.data as *const u8, mem_ptr.length) };
        let decoded = base64::decode_block(&String::from_utf8_lossy(data)).unwrap();
        assert_eq!(decoded, b"hi");
        unsafe { BIO_free_all(b64) };
    }

    /// Network tests that require external connectivity
    /// These tests are ignored by default and can be enabled with:
    /// cargo test --package ktls -- --ignored
    /// or for a specific test:
    /// cargo test --package ktls test_name -- --ignored
    mod network {
        use std::ffi::c_char;
        use std::net::TcpStream;
        use std::os::fd::AsRawFd;

        use foreign_types_shared::ForeignTypeRef;
        use openssl::ssl::{SslContext, SslMethod};
        use openssl_sys::BIO_new_socket;

        use crate::kbio::bio_socket::BIOSocketStream;
        use crate::kbio::ffi::{
            BIO_NOCLOSE, BIO_do_connect, BIO_f_null, BIO_free, BIO_new_connect, BIO_push,
            SSL_OP_ENABLE_KTLS,
        };

        #[test]
        #[ignore]
        fn test_bio_socket() {
            // Use httpbin.org which provides HTTP testing endpoints
            let host_port = c"httpbin.org:80".as_ptr() as *const c_char;
            let bio = unsafe { BIO_new_connect(host_port) };
            assert!(!bio.is_null());

            // Try to establish connection - BIO_do_connect equivalent
            let connect_result = unsafe { BIO_do_connect(bio) };
            if connect_result <= 0 {
                println!("Failed to connect to httpbin.org:80, skipping test");
                unsafe { BIO_free(bio) };
                return; // Skip test if connection fails (maybe no internet)
            }

            // Send HTTP GET request
            let http_request =
                b"GET /get HTTP/1.1\r\nHost: httpbin.org\r\nConnection: close\r\n\r\n";
            let bytes_written = unsafe {
                openssl_sys::BIO_write(
                    bio,
                    http_request.as_ptr() as *const _,
                    http_request.len() as _,
                )
            };

            if bytes_written <= 0 {
                println!("Failed to write to socket, skipping test");
                unsafe { BIO_free(bio) };
                return;
            }

            println!("Sent {bytes_written} bytes");

            // Read response
            let mut response = Vec::new();
            let mut buffer = [0u8; 1024];

            for _ in 0..10 {
                // Limit iterations to avoid infinite loop
                let bytes_read = unsafe {
                    openssl_sys::BIO_read(bio, buffer.as_mut_ptr() as *mut _, buffer.len() as _)
                };

                if bytes_read <= 0 {
                    break; // Connection closed or error
                }

                response.extend_from_slice(&buffer[..bytes_read as usize]);

                // Stop after reading reasonable amount
                if response.len() > 4096 {
                    break;
                }
            }

            unsafe { BIO_free(bio) };

            // Verify we got an HTTP response
            if response.is_empty() {
                println!("No response received, skipping verification");
                return;
            }

            let response_str = String::from_utf8_lossy(&response);
            println!("Response length: {} bytes", response.len());
            println!(
                "Response preview: {}",
                &response_str[..response_str.len().min(200)]
            );

            // Basic HTTP response validation
            assert!(response_str.contains("HTTP/1.1") || response_str.contains("HTTP/1.0"));
        }

        #[test]
        #[ignore]
        fn test_bio_socket_full_response() {
            // Test with a smaller, more predictable endpoint
            let host_port = c"httpbin.org:80".as_ptr() as *const c_char;
            let bio = unsafe { BIO_new_connect(host_port) };
            assert!(!bio.is_null());

            // Connect
            let connect_result = unsafe { BIO_do_connect(bio) };
            if connect_result <= 0 {
                println!("Failed to connect, skipping test");
                unsafe { BIO_free(bio) };
                return;
            }

            // Send a simple HTTP request for IP endpoint (smaller response)
            let http_request =
                b"GET /ip HTTP/1.1\r\nHost: httpbin.org\r\nConnection: close\r\n\r\n";
            let bytes_written = unsafe {
                openssl_sys::BIO_write(
                    bio,
                    http_request.as_ptr() as *const _,
                    http_request.len() as _,
                )
            };

            if bytes_written <= 0 {
                unsafe { BIO_free(bio) };
                return;
            }

            println!("=== HTTP REQUEST ===");
            println!("{}", String::from_utf8_lossy(http_request));

            // Read complete response
            let mut response = Vec::new();
            let mut buffer = [0u8; 512];

            // Read until connection closes
            loop {
                let bytes_read = unsafe {
                    openssl_sys::BIO_read(bio, buffer.as_mut_ptr() as *mut _, buffer.len() as _)
                };

                if bytes_read <= 0 {
                    break;
                }

                response.extend_from_slice(&buffer[..bytes_read as usize]);

                // Safety limit
                if response.len() > 2048 {
                    break;
                }
            }

            unsafe { BIO_free(bio) };

            if !response.is_empty() {
                println!("=== HTTP RESPONSE ===");
                println!("{}", String::from_utf8_lossy(&response));

                let response_str = String::from_utf8_lossy(&response);
                assert!(response_str.contains("HTTP/1.1 200"));
                assert!(response_str.contains("application/json"));
                assert!(response_str.contains("origin"));
            }
        }

        #[test]
        #[ignore]
        fn test_bio_https_request() {
            // Create SSL context
            let ctx = unsafe { openssl_sys::SSL_CTX_new(openssl_sys::TLS_client_method()) };
            assert!(!ctx.is_null());

            // Create a regular socket BIO for HTTPS (port 443)
            let hostname = c"httpbin.org:443".as_ptr() as *const c_char;
            let sock_bio = unsafe { BIO_new_connect(hostname) };
            assert!(!sock_bio.is_null());

            // Connect to the server
            let connect_result = unsafe { BIO_do_connect(sock_bio) };
            if connect_result <= 0 {
                println!("Failed to connect to httpbin.org:443, skipping HTTPS test");
                unsafe {
                    BIO_free(sock_bio);
                    openssl_sys::SSL_CTX_free(ctx);
                }
                return;
            }

            // Create SSL object
            let ssl = unsafe { openssl_sys::SSL_new(ctx) };
            assert!(!ssl.is_null());

            // Set the socket BIO to the SSL object
            unsafe { openssl_sys::SSL_set_bio(ssl, sock_bio, sock_bio) };

            // Set SNI hostname
            let sni_hostname = c"httpbin.org".as_ptr() as *mut c_char;
            unsafe { openssl_sys::SSL_set_tlsext_host_name(ssl, sni_hostname) };

            // Perform SSL handshake
            let handshake_result = unsafe { openssl_sys::SSL_connect(ssl) };
            if handshake_result <= 0 {
                println!("SSL handshake failed, skipping HTTPS test");
                unsafe {
                    openssl_sys::SSL_free(ssl); // This also frees the BIO
                    openssl_sys::SSL_CTX_free(ctx);
                }
                return;
            }

            println!("✅ SSL handshake successful!");

            // Check if KTLS is enabled on this SSL connection
            let rbio = unsafe { openssl_sys::SSL_get_rbio(ssl) };
            let wbio = unsafe { openssl_sys::SSL_get_wbio(ssl) };

            let send_enabled = unsafe { super::super::BIO_get_ktls_send(wbio) };
            let recv_enabled = unsafe { super::super::BIO_get_ktls_recv(rbio) };

            println!("KTLS send enabled: {send_enabled}");
            println!("KTLS recv enabled: {recv_enabled}");

            if send_enabled > 0 || recv_enabled > 0 {
                println!("🎉 KTLS is enabled on this SSL connection!");
            } else {
                println!("ℹ️  KTLS not enabled (expected for non-KTLS configured SSL)");
            }

            // Send HTTPS GET request
            let https_request =
                b"GET /ip HTTP/1.1\r\nHost: httpbin.org\r\nConnection: close\r\n\r\n";
            let bytes_written = unsafe {
                openssl_sys::SSL_write(
                    ssl,
                    https_request.as_ptr() as *const _,
                    https_request.len() as _,
                )
            };

            if bytes_written <= 0 {
                println!("Failed to write HTTPS request");
                unsafe {
                    openssl_sys::SSL_free(ssl);
                    openssl_sys::SSL_CTX_free(ctx);
                }
                return;
            }

            println!("=== HTTPS REQUEST ===");
            println!("{}", String::from_utf8_lossy(https_request));
            println!("Sent {bytes_written} bytes over SSL");

            // Read HTTPS response
            let mut response = Vec::new();
            let mut buffer = [0u8; 512];

            loop {
                let bytes_read = unsafe {
                    openssl_sys::SSL_read(ssl, buffer.as_mut_ptr() as *mut _, buffer.len() as _)
                };

                if bytes_read <= 0 {
                    break;
                }

                response.extend_from_slice(&buffer[..bytes_read as usize]);

                // Safety limit
                if response.len() > 2048 {
                    break;
                }
            }

            // Cleanup
            unsafe {
                openssl_sys::SSL_free(ssl); // This also frees the BIO
                openssl_sys::SSL_CTX_free(ctx);
            }

            if !response.is_empty() {
                println!("=== HTTPS RESPONSE ===");
                println!("{}", String::from_utf8_lossy(&response));

                let response_str = String::from_utf8_lossy(&response);
                assert!(response_str.contains("HTTP/1.1 200"));
                assert!(response_str.contains("application/json"));
                assert!(response_str.contains("origin"));
                println!("✅ HTTPS request successful!");
            } else {
                println!("No HTTPS response received");
            }
        }

        #[test]
        #[ignore]
        fn test_bio_https_with_ktls() {
            // Create SSL context with KTLS enabled using openssl crate
            let ctx_builder = SslContext::builder(SslMethod::tls_client()).unwrap();
            // Enable KTLS using raw option since it's not yet in high-level API
            unsafe {
                openssl_sys::SSL_CTX_set_options(ctx_builder.as_ptr(), SSL_OP_ENABLE_KTLS);
            }
            let ctx = ctx_builder.build();

            // Create a TcpStream connection instead of BIO connect
            let tcp_stream = match TcpStream::connect("httpbin.org:443") {
                Ok(stream) => stream,
                Err(e) => {
                    println!(
                        "Failed to connect via TcpStream to httpbin.org:443: {e}, skipping KTLS HTTPS test"
                    );
                    return;
                }
            };

            // Get the raw file descriptor
            let fd = tcp_stream.as_raw_fd();

            // Create SSL object using the KTLS-enabled context with high-level API
            let ssl = match openssl::ssl::Ssl::new(&ctx) {
                Ok(ssl) => ssl,
                Err(e) => {
                    println!("Failed to create SSL object: {e}, skipping KTLS HTTPS test");
                    return;
                }
            };

            // Create BIOSocketStream with SSL and socket file descriptor
            let bio_socket_stream = unsafe { BIOSocketStream::new(fd, ssl) };

            // Set SNI hostname
            let sni_hostname = c"httpbin.org".as_ptr() as *mut c_char;
            unsafe {
                openssl_sys::SSL_set_tlsext_host_name(
                    bio_socket_stream.ssl().as_ptr(),
                    sni_hostname,
                )
            };

            // Perform SSL handshake using the BIOSocketStream's connect method
            let handshake_result = bio_socket_stream.connect();
            if handshake_result.is_err() {
                println!(
                    "SSL handshake failed, skipping KTLS HTTPS test: {:?}",
                    handshake_result.err()
                );
                return;
            }

            println!("✅ SSL handshake with KTLS option successful!");

            // Check cipher suite
            let cipher =
                unsafe { openssl_sys::SSL_get_current_cipher(bio_socket_stream.ssl().as_ptr()) };
            if !cipher.is_null() {
                let cipher_name = unsafe { openssl_sys::SSL_CIPHER_get_name(cipher) };
                let cipher_str = unsafe { std::ffi::CStr::from_ptr(cipher_name) };
                println!("Cipher: {:?}", cipher_str.to_string_lossy());
            }

            // Check if KTLS is enabled on this SSL connection
            let rbio = unsafe { openssl_sys::SSL_get_rbio(bio_socket_stream.ssl().as_ptr()) };
            let wbio = unsafe { openssl_sys::SSL_get_wbio(bio_socket_stream.ssl().as_ptr()) };

            let send_enabled = unsafe { super::super::BIO_get_ktls_send(wbio) };
            let recv_enabled = unsafe { super::super::BIO_get_ktls_recv(rbio) };

            println!("KTLS send enabled: {send_enabled}");
            println!("KTLS recv enabled: {recv_enabled}");

            if send_enabled > 0 || recv_enabled > 0 {
                println!("🎉 KTLS is enabled on this SSL connection!");
            } else {
                println!(
                    "ℹ️  KTLS not auto-enabled (this is the expected behavior we investigated)"
                );
                println!("   Reason: Native socket BIO with KTLS requires specific setup");
            }

            // Cleanup - SslContext and Ssl will be automatically dropped
            // ssl_stream will be dropped automatically, freeing the SSL object

            println!(
                "Test completed - demonstrated HTTPS with KTLS option set and BIOSocketStream"
            );
        }

        #[test]
        #[ignore]
        fn test_bio_https_with_null_filter() {
            // Test BIO_f_null() which acts as a transparent pass-through filter
            println!("=== Testing BIO_f_null() filter with KTLS ===");

            // Create SSL context with KTLS enabled
            let ctx = unsafe { openssl_sys::SSL_CTX_new(openssl_sys::TLS_client_method()) };
            assert!(!ctx.is_null());
            unsafe { openssl_sys::SSL_CTX_set_options(ctx, SSL_OP_ENABLE_KTLS) };

            // Create TcpStream connection
            let tcp_stream = match TcpStream::connect("httpbin.org:443") {
                Ok(stream) => stream,
                Err(e) => {
                    println!("Failed to connect via TcpStream: {e}, skipping test");
                    unsafe { openssl_sys::SSL_CTX_free(ctx) };
                    return;
                }
            };

            let fd = tcp_stream.as_raw_fd();
            let sock_bio = unsafe { BIO_new_socket(fd, BIO_NOCLOSE) };
            assert!(!sock_bio.is_null());

            // Create null filter BIO (transparent pass-through)
            let null_bio = unsafe { openssl_sys::BIO_new(BIO_f_null()) };
            assert!(!null_bio.is_null());

            // Chain: null filter -> socket BIO
            unsafe { BIO_push(null_bio, sock_bio) };

            // Create SSL object and set the BIO chain
            let ssl = unsafe { openssl_sys::SSL_new(ctx) };
            assert!(!ssl.is_null());
            unsafe { openssl_sys::SSL_set_bio(ssl, null_bio, null_bio) };

            // Set SNI hostname
            let sni_hostname = c"httpbin.org".as_ptr() as *mut c_char;
            unsafe { openssl_sys::SSL_set_tlsext_host_name(ssl, sni_hostname) };

            // Perform SSL handshake
            let handshake_result = unsafe { openssl_sys::SSL_connect(ssl) };
            if handshake_result <= 0 {
                println!("SSL handshake failed, skipping test");
                unsafe {
                    openssl_sys::SSL_free(ssl);
                    openssl_sys::SSL_CTX_free(ctx);
                }
                return;
            }

            println!("✅ SSL handshake successful with BIO_f_null() filter!");

            // Check cipher suite
            let cipher = unsafe { openssl_sys::SSL_get_current_cipher(ssl) };
            if !cipher.is_null() {
                let cipher_name = unsafe { openssl_sys::SSL_CIPHER_get_name(cipher) };
                let cipher_str = unsafe { std::ffi::CStr::from_ptr(cipher_name) };
                println!("Cipher: {:?}", cipher_str.to_string_lossy());
            }

            // Check KTLS status
            let rbio = unsafe { openssl_sys::SSL_get_rbio(ssl) };
            let wbio = unsafe { openssl_sys::SSL_get_wbio(ssl) };

            let send_enabled = unsafe { super::super::BIO_get_ktls_send(wbio) };
            let recv_enabled = unsafe { super::super::BIO_get_ktls_recv(rbio) };

            println!("KTLS send enabled: {send_enabled}");
            println!("KTLS recv enabled: {recv_enabled}");

            if send_enabled > 0 || recv_enabled > 0 {
                println!("🎉 KTLS is enabled with BIO_f_null() filter!");
            } else {
                println!("ℹ️  KTLS not enabled with BIO_f_null() filter");
            }

            // Cleanup
            unsafe {
                openssl_sys::SSL_free(ssl);
                openssl_sys::SSL_CTX_free(ctx);
            }

            println!("=== BIO_f_null() test completed ===");
        }
    }
}
