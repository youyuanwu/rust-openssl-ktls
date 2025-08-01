use std::os::fd::AsRawFd;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::bio::ffi::BIO_NOCLOSE;
use foreign_types_shared::ForeignType;

/// Async version of SslStream that integrates with Tokio runtime
pub struct SslStream {
    async_fd: AsyncFd<std::net::TcpStream>, // Use TcpStream as a wrapper for the raw fd
    ssl: openssl::ssl::Ssl,
}

impl SslStream {
    /// Create a new SslStream from a raw file descriptor and SSL object.
    pub fn new(tcp_stream: tokio::net::TcpStream, ssl: openssl::ssl::Ssl) -> std::io::Result<Self> {
        // Convert to std tcp stream so that tokio has no track of the tcp,
        // and we will register with tokio using AsyncFd again.
        let std_tcp = tcp_stream.into_std().unwrap();
        let sock_bio = unsafe { openssl_sys::BIO_new_socket(std_tcp.as_raw_fd(), BIO_NOCLOSE) };
        assert!(!sock_bio.is_null(), "Failed to create socket BIO");
        unsafe {
            openssl_sys::SSL_set_bio(ssl.as_ptr(), sock_bio, sock_bio);
        }

        // Create a AsyncFd for tcp stream
        let async_fd = AsyncFd::new(std_tcp)?;

        Ok(SslStream { ssl, async_fd })
    }

    /// Async SSL connect
    pub async fn connect(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        use std::future::poll_fn;

        poll_fn(|cx| self.poll_connect(cx)).await
    }

    /// Poll-based connect for async compatibility
    /// Returns Poll::Pending if the operation would block and needs to be retried
    /// Returns Poll::Ready(Ok(())) if the handshake completed successfully
    /// Returns Poll::Ready(Err(_)) if there was an error
    pub fn poll_connect(
        &self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Box<dyn std::error::Error + Send + Sync>>> {
        loop {
            let handshake_result = unsafe { openssl_sys::SSL_connect(self.ssl.as_ptr()) };

            if handshake_result > 0 {
                // Handshake completed successfully
                return Poll::Ready(Ok(()));
            }

            // Check what kind of error occurred
            let ssl_error =
                unsafe { openssl_sys::SSL_get_error(self.ssl.as_ptr(), handshake_result) };

            match ssl_error {
                openssl_sys::SSL_ERROR_WANT_READ => {
                    // SSL wants to read more data, wait for socket to become readable
                    match self.async_fd.poll_read_ready(cx) {
                        Poll::Ready(Ok(mut guard)) => {
                            guard.clear_ready();
                            continue; // Try SSL_connect again
                        }
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(Box::new(e))),
                        Poll::Pending => return Poll::Pending,
                    }
                }
                openssl_sys::SSL_ERROR_WANT_WRITE => {
                    // SSL wants to write more data, wait for socket to become writable
                    match self.async_fd.poll_write_ready(cx) {
                        Poll::Ready(Ok(mut guard)) => {
                            guard.clear_ready();
                            continue; // Try SSL_connect again
                        }
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(Box::new(e))),
                        Poll::Pending => return Poll::Pending,
                    }
                }
                _ => {
                    // Real error occurred
                    return Poll::Ready(Err(Box::new(openssl::error::ErrorStack::get())));
                }
            }
        }
    }

    /// Async SSL accept
    pub async fn accept(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        use std::future::poll_fn;

        poll_fn(|cx| self.poll_accept(cx)).await
    }

    /// Poll-based accept for async compatibility
    pub fn poll_accept(
        &self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Box<dyn std::error::Error + Send + Sync>>> {
        loop {
            let handshake_result = unsafe { openssl_sys::SSL_accept(self.ssl.as_ptr()) };

            if handshake_result > 0 {
                return Poll::Ready(Ok(()));
            }

            let ssl_error =
                unsafe { openssl_sys::SSL_get_error(self.ssl.as_ptr(), handshake_result) };

            match ssl_error {
                openssl_sys::SSL_ERROR_WANT_READ => {
                    match self.async_fd.poll_read_ready(cx) {
                        Poll::Ready(Ok(mut guard)) => {
                            guard.clear_ready();
                            continue; // Try SSL_accept again
                        }
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(Box::new(e))),
                        Poll::Pending => return Poll::Pending,
                    }
                }
                openssl_sys::SSL_ERROR_WANT_WRITE => {
                    match self.async_fd.poll_write_ready(cx) {
                        Poll::Ready(Ok(mut guard)) => {
                            guard.clear_ready();
                            continue; // Try SSL_accept again
                        }
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(Box::new(e))),
                        Poll::Pending => return Poll::Pending,
                    }
                }
                _ => return Poll::Ready(Err(Box::new(openssl::error::ErrorStack::get()))),
            }
        }
    }

    /// Async SSL shutdown
    pub async fn ssl_shutdown(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        use std::future::poll_fn;

        poll_fn(|cx| self.poll_ssl_shutdown(cx)).await
    }

    /// Poll-based shutdown for async compatibility
    pub fn poll_ssl_shutdown(
        &self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Box<dyn std::error::Error + Send + Sync>>> {
        loop {
            let result = unsafe { openssl_sys::SSL_shutdown(self.ssl.as_ptr()) };

            if result == 1 {
                // Clean shutdown completed
                return Poll::Ready(Ok(()));
            } else if result == 0 {
                // First phase of shutdown completed, need to wait for peer's close_notify
                // For simplicity, we'll consider this complete
                return Poll::Ready(Ok(()));
            }

            let ssl_error = unsafe { openssl_sys::SSL_get_error(self.ssl.as_ptr(), result) };

            match ssl_error {
                openssl_sys::SSL_ERROR_WANT_READ => {
                    match self.async_fd.poll_read_ready(cx) {
                        Poll::Ready(Ok(mut guard)) => {
                            guard.clear_ready();
                            continue; // Try SSL_shutdown again
                        }
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(Box::new(e))),
                        Poll::Pending => return Poll::Pending,
                    }
                }
                openssl_sys::SSL_ERROR_WANT_WRITE => {
                    match self.async_fd.poll_write_ready(cx) {
                        Poll::Ready(Ok(mut guard)) => {
                            guard.clear_ready();
                            continue; // Try SSL_shutdown again
                        }
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(Box::new(e))),
                        Poll::Pending => return Poll::Pending,
                    }
                }
                _ => return Poll::Ready(Err(Box::new(openssl::error::ErrorStack::get()))),
            }
        }
    }

    pub fn ssl(&self) -> &openssl::ssl::Ssl {
        &self.ssl
    }

    pub fn ktls_send_enabled(&self) -> bool {
        unsafe {
            let wbio = openssl_sys::SSL_get_wbio(self.ssl.as_ptr());
            crate::bio::ffi::BIO_get_ktls_send(wbio) != 0
        }
    }

    pub fn ktls_recv_enabled(&self) -> bool {
        unsafe {
            let rbio = openssl_sys::SSL_get_rbio(self.ssl.as_ptr());
            crate::bio::ffi::BIO_get_ktls_recv(rbio) != 0
        }
    }
}

impl AsyncRead for SslStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let unfilled = unsafe { buf.unfilled_mut() };

        if unfilled.is_empty() {
            return Poll::Ready(Ok(()));
        }

        loop {
            unsafe {
                let len = openssl_sys::SSL_read(
                    self.ssl.as_ptr(),
                    unfilled.as_mut_ptr() as *mut _,
                    unfilled.len().try_into().unwrap_or(i32::MAX),
                );

                if len > 0 {
                    buf.advance(len as usize);
                    return Poll::Ready(Ok(()));
                } else {
                    let ssl_error = openssl_sys::SSL_get_error(self.ssl.as_ptr(), len);
                    match ssl_error {
                        openssl_sys::SSL_ERROR_WANT_READ => {
                            match self.async_fd.poll_read_ready(cx) {
                                Poll::Ready(Ok(mut guard)) => {
                                    guard.clear_ready();
                                    continue; // Try SSL_read again
                                }
                                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                                Poll::Pending => return Poll::Pending,
                            }
                        }
                        openssl_sys::SSL_ERROR_WANT_WRITE => {
                            match self.async_fd.poll_write_ready(cx) {
                                Poll::Ready(Ok(mut guard)) => {
                                    guard.clear_ready();
                                    continue; // Try SSL_read again
                                }
                                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                                Poll::Pending => return Poll::Pending,
                            }
                        }
                        openssl_sys::SSL_ERROR_ZERO_RETURN => {
                            // Clean shutdown
                            return Poll::Ready(Ok(()));
                        }
                        _ => return Poll::Ready(Err(std::io::Error::last_os_error())),
                    }
                }
            }
        }
    }
}

impl AsyncWrite for SslStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        loop {
            unsafe {
                let len = openssl_sys::SSL_write(
                    self.ssl.as_ptr(),
                    buf.as_ptr() as *const _,
                    buf.len().try_into().unwrap_or(i32::MAX),
                );

                if len > 0 {
                    return Poll::Ready(Ok(len as usize));
                } else {
                    let ssl_error = openssl_sys::SSL_get_error(self.ssl.as_ptr(), len);
                    match ssl_error {
                        openssl_sys::SSL_ERROR_WANT_READ => {
                            match self.async_fd.poll_read_ready(cx) {
                                Poll::Ready(Ok(mut guard)) => {
                                    guard.clear_ready();
                                    continue; // Try SSL_write again
                                }
                                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                                Poll::Pending => return Poll::Pending,
                            }
                        }
                        openssl_sys::SSL_ERROR_WANT_WRITE => {
                            match self.async_fd.poll_write_ready(cx) {
                                Poll::Ready(Ok(mut guard)) => {
                                    guard.clear_ready();
                                    continue; // Try SSL_write again
                                }
                                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                                Poll::Pending => return Poll::Pending,
                            }
                        }
                        _ => return Poll::Ready(Err(std::io::Error::last_os_error())),
                    }
                }
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        // SSL doesn't have a specific flush operation, so we just return ready
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        match self.poll_ssl_shutdown(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(std::io::Error::other(e))),
            Poll::Pending => Poll::Pending,
        }
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
