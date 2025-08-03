use std::os::fd::AsRawFd;

use foreign_types_shared::ForeignType;

use crate::ffi::BIO_NOCLOSE;

pub struct SslStream {
    _tcp: std::net::TcpStream,
    ssl: openssl::ssl::Ssl,
}
impl SslStream {
    /// Create a new SslStream from a tcp stream and SSL object.
    pub fn new(tcp: std::net::TcpStream, ssl: openssl::ssl::Ssl) -> Self {
        let sock_bio = unsafe { openssl_sys::BIO_new_socket(tcp.as_raw_fd(), BIO_NOCLOSE) };
        assert!(!sock_bio.is_null(), "Failed to create socket BIO");
        unsafe {
            openssl_sys::SSL_set_bio(ssl.as_ptr(), sock_bio, sock_bio);
        }
        SslStream { _tcp: tcp, ssl }
    }

    /// Synchronous connect method (kept for backward compatibility)
    pub fn connect(&self) -> Result<(), crate::error::Error> {
        let result = unsafe { openssl_sys::SSL_connect(self.ssl.as_ptr()) };
        if result <= 0 {
            Err(crate::error::Error::make(result, self.ssl()))
        } else {
            Ok(())
        }
    }

    pub fn accept(&self) -> Result<(), crate::error::Error> {
        let result = unsafe { openssl_sys::SSL_accept(self.ssl.as_ptr()) };
        if result <= 0 {
            Err(crate::error::Error::make(result, self.ssl()))
        } else {
            Ok(())
        }
    }

    pub fn ssl(&self) -> &openssl::ssl::Ssl {
        &self.ssl
    }

    pub fn shutdown(&self) -> Result<(), crate::error::Error> {
        let result = unsafe { openssl_sys::SSL_shutdown(self.ssl.as_ptr()) };
        if result < 0 {
            Err(crate::error::Error::make(result, self.ssl()))
        } else {
            Ok(())
        }
    }

    pub fn ktls_send_enabled(&self) -> bool {
        unsafe {
            let wbio = openssl_sys::SSL_get_wbio(self.ssl.as_ptr());
            crate::ffi::BIO_get_ktls_send(wbio) != 0
        }
    }

    pub fn ktls_recv_enabled(&self) -> bool {
        unsafe {
            let rbio = openssl_sys::SSL_get_rbio(self.ssl.as_ptr());
            crate::ffi::BIO_get_ktls_recv(rbio) != 0
        }
    }
}

impl std::io::Read for SslStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        unsafe {
            let len = openssl_sys::SSL_read(
                self.ssl.as_ptr(),
                buf.as_mut_ptr() as *mut _,
                buf.len().try_into().unwrap(),
            );
            if len < 0 {
                Err(std::io::Error::other(crate::error::Error::make(
                    len,
                    self.ssl(),
                )))
            } else {
                Ok(len as usize)
            }
        }
    }
}

impl std::io::Write for SslStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        unsafe {
            let len = openssl_sys::SSL_write(
                self.ssl.as_ptr(),
                buf.as_ptr() as *const _,
                buf.len().try_into().unwrap(),
            );
            if len < 0 {
                Err(std::io::Error::other(crate::error::Error::make(
                    len,
                    self.ssl(),
                )))
            } else {
                Ok(len as usize)
            }
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Drop for SslStream {
    fn drop(&mut self) {
        // The BIO is automatically freed when SSL_free is called on the SSL object,
        // so we don't need to manually free the BIO here. The SSL object will be
        // dropped automatically via its Drop implementation.
        //
        // Note: We used SSL_set_bio(ssl, bio, bio) which means both read and write
        // BIOs point to the same BIO object, and SSL takes ownership of it.
    }
}
