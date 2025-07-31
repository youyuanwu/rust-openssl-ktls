use std::os::fd::RawFd;
use std::pin::Pin;
use std::task::{Context, Poll};

use openssl_sys::BIO;
use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::kbio::ffi::BIO_NOCLOSE;
use foreign_types_shared::ForeignType;

// Send-safe wrapper for BIO pointer
#[allow(dead_code)]
struct SendBio(*mut BIO);
unsafe impl Send for SendBio {}
unsafe impl Sync for SendBio {}

/// Async version of BIOSocketStream that integrates with Tokio runtime
pub struct AsyncBIOSocketStream {
    ssl: openssl::ssl::Ssl,
    _bio: SendBio,
    async_fd: AsyncFd<std::fs::File>, // Use File as a wrapper for the raw fd
}

// Safety: The BIO pointer is owned by the SSL object and properly managed by OpenSSL.
// The SSL object itself is Send + Sync, and we never access the BIO pointer directly
// from multiple threads simultaneously.
unsafe impl Send for AsyncBIOSocketStream {}
unsafe impl Sync for AsyncBIOSocketStream {}

impl AsyncBIOSocketStream {
    /// Create a new AsyncBIOSocketStream from a raw file descriptor and SSL object.
    ///
    /// # Safety
    ///
    /// The caller must ensure that:
    /// - `fd` is a valid file descriptor for a non-blocking socket
    /// - The file descriptor remains valid for the lifetime of this object
    /// - The SSL object is properly configured and compatible with socket operations
    /// - The underlying socket is set to non-blocking mode
    pub unsafe fn new(fd: RawFd, ssl: openssl::ssl::Ssl) -> std::io::Result<Self> {
        let sock_bio = unsafe { openssl_sys::BIO_new_socket(fd, BIO_NOCLOSE) };
        assert!(!sock_bio.is_null(), "Failed to create socket BIO");
        unsafe {
            openssl_sys::SSL_set_bio(ssl.as_ptr(), sock_bio, sock_bio);
        }

        // Create a File from the raw fd for AsyncFd
        use std::os::fd::FromRawFd;
        let file = unsafe { std::fs::File::from_raw_fd(fd) };
        let async_fd = AsyncFd::new(file)?;

        Ok(AsyncBIOSocketStream {
            _bio: SendBio(sock_bio),
            ssl,
            async_fd,
        })
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
}

impl AsyncRead for AsyncBIOSocketStream {
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

impl AsyncWrite for AsyncBIOSocketStream {
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

impl Drop for AsyncBIOSocketStream {
    fn drop(&mut self) {
        // The BIO is automatically freed when SSL_free is called on the SSL object,
        // so we don't need to manually free the BIO here. The SSL object will be
        // dropped automatically via its Drop implementation.
        //
        // Note: We used SSL_set_bio(ssl, bio, bio) which means both read and write
        // BIOs point to the same BIO object, and SSL takes ownership of it.
    }
}

/// Helper function to create an async BIO socket stream with proper setup
pub async fn create_async_bio_socket_stream(
    tcp_stream: tokio::net::TcpStream,
    ssl: openssl::ssl::Ssl,
) -> Result<AsyncBIOSocketStream, std::io::Error> {
    use std::os::fd::AsRawFd;

    // Convert tokio TcpStream to std TcpStream
    let std_stream = tcp_stream.into_std()?;

    // Set to non-blocking mode (required for async operations)
    std_stream.set_nonblocking(true)?;

    // Get file descriptor
    let fd = std_stream.as_raw_fd();

    // Create the async BIO socket stream
    let bio_stream = unsafe { AsyncBIOSocketStream::new(fd, ssl)? };

    // Keep the std_stream alive by forgetting it (BIO will manage the fd)
    std::mem::forget(std_stream);

    Ok(bio_stream)
}
