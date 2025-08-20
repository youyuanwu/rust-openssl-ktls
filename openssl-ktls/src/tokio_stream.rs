use std::os::fd::AsRawFd;
use std::pin::Pin;
use std::task::{Context, Poll};

use openssl::ssl::ShutdownResult;
use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::error::Error;
use crate::ffi::BIO_NOCLOSE;
use foreign_types_shared::ForeignType;

/// RAII guard for managing waker pointers passed to SSL async callbacks
/// Automatically cleans up the waker when dropped, unless explicitly released
struct WakerGuard {
    waker_ptr: Option<*mut std::ffi::c_void>,
}

impl WakerGuard {
    /// Create a new guard with a waker pointer
    fn new(waker_ptr: *mut std::ffi::c_void) -> Self {
        Self {
            waker_ptr: Some(waker_ptr),
        }
    }

    /// Release the waker pointer for callback consumption
    /// This should be called when SSL_ERROR_WANT_ASYNC is returned
    fn release(mut self) {
        self.waker_ptr = None;
        // Guard will be dropped but won't clean up the waker since it's None
    }
}

impl Drop for WakerGuard {
    fn drop(&mut self) {
        if let Some(ptr) = self.waker_ptr.take() {
            if !ptr.is_null() {
                unsafe {
                    // Convert back to Box and drop it
                    let _ = Box::from_raw(ptr as *mut std::task::Waker);
                }
            }
        }
    }
}

/// Async version of SslStream that integrates with Tokio runtime
#[derive(Debug)]
pub struct SslStream {
    async_fd: AsyncFd<std::net::TcpStream>, // Use TcpStream as a wrapper for the raw fd
    ssl: openssl::ssl::Ssl,
}

enum ReactResult {
    Final(Poll<Result<(), Error>>),
    Retry,
    Async, // New variant for async operations
}

fn react_to_ssl_call(
    ssl_result: i32,
    ssl: &openssl::ssl::Ssl,
    async_fd: &AsyncFd<std::net::TcpStream>,
    cx: &mut Context<'_>,
) -> ReactResult {
    // Check what kind of error occurred
    let ssl_error = unsafe { openssl_sys::SSL_get_error(ssl.as_ptr(), ssl_result) };

    match ssl_error {
        openssl_sys::SSL_ERROR_WANT_READ => {
            // SSL wants to read more data, wait for socket to become readable
            match async_fd.poll_read_ready(cx) {
                Poll::Ready(Ok(mut guard)) => {
                    guard.clear_ready();
                    ReactResult::Retry
                }
                Poll::Ready(Err(e)) => ReactResult::Final(Poll::Ready(Err(Error::from_io(e)))),
                Poll::Pending => ReactResult::Final(Poll::Pending),
            }
        }
        openssl_sys::SSL_ERROR_WANT_WRITE => {
            // SSL wants to write more data, wait for socket to become writable
            match async_fd.poll_write_ready(cx) {
                Poll::Ready(Ok(mut guard)) => {
                    guard.clear_ready();
                    ReactResult::Retry
                }
                Poll::Ready(Err(e)) => ReactResult::Final(Poll::Ready(Err(Error::from_io(e)))),
                Poll::Pending => ReactResult::Final(Poll::Pending),
            }
        }
        crate::ffi::SSL_ERROR_WANT_ASYNC => {
            println!("🔧 SSL want async");
            // SSL operation is running asynchronously, the callback will wake us
            ReactResult::Async
        }
        openssl_sys::SSL_ERROR_ZERO_RETURN => {
            // SSL connection closed cleanly
            ReactResult::Final(Poll::Ready(Ok(())))
        }
        _ => {
            // Real error occurred
            ReactResult::Final(Poll::Ready(Err(Error::make(ssl_result, ssl))))
        }
    }
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

        // If async mode is enabled, set up the callback function once
        let is_async_enabled = Self::is_async_mode_enabled(&ssl);

        if is_async_enabled {
            unsafe {
                let ret = crate::ffi::SSL_set_async_callback(
                    ssl.as_ptr(),
                    Some(crate::async_mode::raw_ssl_async_callback_fn),
                );
                if ret != 1 {
                    return Err(std::io::Error::other("Failed to set async callback"));
                }
            }
        }

        // Create a AsyncFd for tcp stream
        let async_fd = AsyncFd::new(std_tcp)?;

        Ok(SslStream { ssl, async_fd })
    }

    /// Get ref to the inner stream.
    pub fn get_ref(&self) -> &std::net::TcpStream {
        self.async_fd.get_ref()
    }

    /// Check if async mode is enabled on the SSL object
    pub fn is_async_mode_enabled(ssl: &openssl::ssl::Ssl) -> bool {
        {
            let mode = unsafe { crate::ffi::SSL_get_mode(ssl.as_ptr()) };
            (mode & crate::ffi::SSL_MODE_ASYNC) != 0
        }
    }

    /// Update async callback argument with current waker (only if async mode is enabled)
    /// Returns a WakerGuard if async mode is enabled, None otherwise
    fn update_async_callback_arg(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Result<Option<WakerGuard>, Error> {
        if Self::is_async_mode_enabled(&self.ssl) {
            unsafe {
                // Clone the waker to ensure it remains valid after this call returns
                let waker = cx.waker().clone();
                // Box the waker to put it on the heap with a stable address
                let waker_box = Box::new(waker);
                // Convert to raw pointer immediately
                let waker_ptr = Box::into_raw(waker_box) as *mut std::ffi::c_void;

                let ret = crate::ffi::SSL_set_async_callback_arg(self.ssl.as_ptr(), waker_ptr);
                if ret != 1 {
                    // If setting the callback arg failed, we need to clean up the raw pointer
                    let _ = Box::from_raw(waker_ptr as *mut std::task::Waker);
                    return Err(Error::from_io(std::io::Error::other(
                        "Failed to set async callback arg",
                    )));
                }

                Ok(Some(WakerGuard::new(waker_ptr)))
            }
        } else {
            Ok(None)
        }
    }

    /// Async SSL connect
    pub async fn connect(&mut self) -> Result<(), Error> {
        use std::future::poll_fn;

        poll_fn(|cx| self.poll_connect(cx)).await
    }

    /// Poll-based connect for async compatibility
    /// Returns Poll::Pending if the operation would block and needs to be retried
    /// Returns Poll::Ready(Ok(())) if the handshake completed successfully
    /// Returns Poll::Ready(Err(_)) if there was an error
    pub fn poll_connect(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), crate::error::Error>> {
        // Update async callback arg with current waker if async mode is enabled
        let _waker_guard = match self.update_async_callback_arg(cx) {
            Ok(guard) => guard,
            Err(e) => return Poll::Ready(Err(e)),
        };

        loop {
            let handshake_result = unsafe { openssl_sys::SSL_connect(self.ssl.as_ptr()) };

            if handshake_result > 0 {
                // Handshake completed successfully
                // Guard will auto-cleanup waker since operation succeeded without async
                return Poll::Ready(Ok(()));
            }

            match react_to_ssl_call(handshake_result, &self.ssl, &self.async_fd, cx) {
                ReactResult::Final(result) => {
                    // Guard will auto-cleanup waker since this is a final result
                    return result;
                }
                ReactResult::Retry => continue, // Retry the SSL_connect
                ReactResult::Async => {
                    // Release the guard so the callback can consume the waker
                    if let Some(guard) = _waker_guard {
                        guard.release();
                    }
                    return Poll::Pending; // Async operation in progress, wait for callback
                }
            }
        }
    }

    /// Async SSL accept
    pub async fn accept(&mut self) -> Result<(), Error> {
        use std::future::poll_fn;

        poll_fn(|cx| self.poll_accept(cx)).await
    }

    /// Poll-based accept for async compatibility
    pub fn poll_accept(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        // Update async callback arg with current waker if async mode is enabled
        let _waker_guard = match self.update_async_callback_arg(cx) {
            Ok(guard) => guard,
            Err(e) => return Poll::Ready(Err(e)),
        };

        loop {
            let accept_result = unsafe { openssl_sys::SSL_accept(self.ssl.as_ptr()) };

            if accept_result > 0 {
                // Guard will auto-cleanup waker since operation succeeded without async
                return Poll::Ready(Ok(()));
            }
            match react_to_ssl_call(accept_result, &self.ssl, &self.async_fd, cx) {
                ReactResult::Final(result) => {
                    // Guard will auto-cleanup waker since this is a final result
                    return result;
                }
                ReactResult::Retry => continue, // Retry the SSL_accept
                ReactResult::Async => {
                    // Release the guard so the callback can consume the waker
                    if let Some(guard) = _waker_guard {
                        guard.release();
                    }
                    return Poll::Pending; // Async operation in progress
                }
            }
        }
    }

    /// Async SSL shutdown
    pub async fn ssl_shutdown(&mut self) -> Result<openssl::ssl::ShutdownResult, Error> {
        use std::future::poll_fn;

        poll_fn(|cx| self.poll_ssl_shutdown(cx)).await
    }

    /// Poll-based shutdown for async compatibility
    pub fn poll_ssl_shutdown(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<openssl::ssl::ShutdownResult, Error>> {
        // Update async callback arg with current waker if async mode is enabled
        let _waker_guard = match self.update_async_callback_arg(cx) {
            Ok(guard) => guard,
            Err(e) => return Poll::Ready(Err(e)),
        };

        loop {
            let result = unsafe { openssl_sys::SSL_shutdown(self.ssl.as_ptr()) };

            match result {
                1 => {
                    // Clean shutdown completed
                    // Guard will auto-cleanup waker since operation completed without async
                    return Poll::Ready(Ok(openssl::ssl::ShutdownResult::Received));
                }
                0 => {
                    // First phase of shutdown completed, need to wait for peer's close_notify
                    // For simplicity, we'll consider this complete
                    // Guard will auto-cleanup waker since operation completed without async
                    return Poll::Ready(Ok(ShutdownResult::Sent));
                }
                i => {
                    match react_to_ssl_call(i, &self.ssl, &self.async_fd, cx) {
                        ReactResult::Final(result) => {
                            // Guard will auto-cleanup waker since this is a final result
                            return result
                                .map(|res| res.map(|_| openssl::ssl::ShutdownResult::Sent));
                        }
                        ReactResult::Retry => continue, // Retry the SSL_shutdown
                        ReactResult::Async => {
                            // Release the guard so the callback can consume the waker
                            if let Some(guard) = _waker_guard {
                                guard.release();
                            }
                            return Poll::Pending; // Async operation in progress
                        }
                    }
                }
            }
        }
    }

    pub fn ssl(&self) -> &openssl::ssl::Ssl {
        &self.ssl
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

impl AsyncRead for SslStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        // Update async callback arg with current waker if async mode is enabled
        let _waker_guard = match self.as_mut().get_mut().update_async_callback_arg(cx) {
            Ok(guard) => guard,
            Err(e) => return Poll::Ready(Err(std::io::Error::other(e))),
        };

        let unfilled = unsafe { buf.unfilled_mut() };

        if unfilled.is_empty() {
            return Poll::Ready(Ok(()));
        }

        // Get references we need for the loop
        let this = self.get_mut();
        let ssl_ptr = this.ssl.as_ptr();
        let ssl = &this.ssl;
        let async_fd = &this.async_fd;

        loop {
            let mut readbytes = 0;
            let ret = unsafe {
                openssl_sys::SSL_read_ex(
                    ssl_ptr,
                    unfilled.as_mut_ptr() as *mut _,
                    unfilled.len(),
                    &mut readbytes,
                )
            };

            if ret > 0 {
                // FIXED: Initialize the bytes first, then advance
                unsafe { buf.assume_init(readbytes) }; // Mark bytes as initialized
                buf.advance(readbytes); // Then advance the filled pointer
                // Guard will auto-cleanup waker since operation succeeded without async
                return Poll::Ready(Ok(()));
            }

            match react_to_ssl_call(ret, ssl, async_fd, cx) {
                ReactResult::Final(result) => {
                    // Guard will auto-cleanup waker since this is a final result
                    return result.map(|res| {
                        res.map_err(|arg0: Error| match arg0.into_io_error() {
                            Ok(io_e) => io_e,
                            Err(other) => std::io::Error::other(other),
                        })
                    });
                }
                ReactResult::Retry => continue, // Retry the SSL_read
                ReactResult::Async => {
                    // Release the guard so the callback can consume the waker
                    if let Some(guard) = _waker_guard {
                        guard.release();
                    }
                    return Poll::Pending; // Async operation in progress
                }
            }
        }
    }
}

impl AsyncWrite for SslStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        // Update async callback arg with current waker if async mode is enabled
        let _waker_guard = match self.as_mut().get_mut().update_async_callback_arg(cx) {
            Ok(guard) => guard,
            Err(e) => return Poll::Ready(Err(std::io::Error::other(e))),
        };

        // Get references we need for the loop
        let this = self.get_mut();
        let ssl_ptr = this.ssl.as_ptr();
        let ssl = &this.ssl;
        let async_fd = &this.async_fd;

        loop {
            let mut written = 0;

            let ret = unsafe {
                openssl_sys::SSL_write_ex(
                    ssl_ptr,
                    buf.as_ptr() as *const _,
                    buf.len(),
                    &mut written,
                )
            };

            if ret > 0 {
                // Guard will auto-cleanup waker since operation succeeded without async
                return Poll::Ready(Ok(written));
            } else {
                match react_to_ssl_call(ret, ssl, async_fd, cx) {
                    ReactResult::Final(result) => {
                        // Guard will auto-cleanup waker since this is a final result
                        return result.map(|res| {
                            res.map_err(|arg0: Error| match arg0.into_io_error() {
                                Ok(io_e) => io_e,
                                Err(other) => std::io::Error::other(other),
                            })
                            .map(|_| 0)
                        });
                    }
                    ReactResult::Retry => continue, // Retry the SSL_write
                    ReactResult::Async => {
                        // Release the guard so the callback can consume the waker
                        if let Some(guard) = _waker_guard {
                            guard.release();
                        }
                        return Poll::Pending; // Async operation in progress
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
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        match self.poll_ssl_shutdown(cx) {
            Poll::Ready(Ok(_)) => Poll::Ready(Ok(())),
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
        //
        // No need to clean up wakers since they're now managed entirely by the callback
    }
}
