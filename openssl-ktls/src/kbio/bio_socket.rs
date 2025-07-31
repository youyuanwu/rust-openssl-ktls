use std::os::fd::RawFd;

use openssl_sys::BIO;

use crate::kbio::ffi::BIO_NOCLOSE;
use foreign_types_shared::ForeignType;

pub struct BIOSocketStream {
    ssl: openssl::ssl::Ssl,
    _bio: *mut BIO,
}
impl BIOSocketStream {
    /// Create a new BIOSocketStream from a raw file descriptor and SSL object.
    ///
    /// # Safety
    ///
    /// The caller must ensure that:
    /// - `fd` is a valid file descriptor
    /// - The file descriptor remains valid for the lifetime of this object
    /// - The SSL object is properly configured and compatible with socket operations
    pub unsafe fn new(fd: RawFd, ssl: openssl::ssl::Ssl) -> Self {
        let sock_bio = unsafe { openssl_sys::BIO_new_socket(fd, BIO_NOCLOSE) };
        assert!(!sock_bio.is_null(), "Failed to create socket BIO");
        unsafe {
            openssl_sys::SSL_set_bio(ssl.as_ptr(), sock_bio, sock_bio);
        }
        BIOSocketStream {
            _bio: sock_bio,
            ssl,
        }
    }

    /// Synchronous connect method (kept for backward compatibility)
    pub fn connect(&self) -> Result<(), openssl::error::ErrorStack> {
        let handshake_result = unsafe { openssl_sys::SSL_connect(self.ssl.as_ptr()) };
        if handshake_result <= 0 {
            Err(openssl::error::ErrorStack::get())
        } else {
            Ok(())
        }
    }

    pub fn accept(&self) -> Result<(), openssl::error::ErrorStack> {
        let handshake_result = unsafe { openssl_sys::SSL_accept(self.ssl.as_ptr()) };
        if handshake_result <= 0 {
            Err(openssl::error::ErrorStack::get())
        } else {
            Ok(())
        }
    }

    pub fn ssl(&self) -> &openssl::ssl::Ssl {
        &self.ssl
    }

    pub fn shutdown(&self) -> Result<(), openssl::error::ErrorStack> {
        let result = unsafe { openssl_sys::SSL_shutdown(self.ssl.as_ptr()) };
        if result < 0 {
            Err(openssl::error::ErrorStack::get())
        } else {
            Ok(())
        }
    }
}

impl std::io::Read for BIOSocketStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        unsafe {
            let len = openssl_sys::SSL_read(
                self.ssl.as_ptr(),
                buf.as_mut_ptr() as *mut _,
                buf.len().try_into().unwrap(),
            );
            if len < 0 {
                Err(std::io::Error::last_os_error())
            } else {
                Ok(len as usize)
            }
        }
    }
}

impl std::io::Write for BIOSocketStream {
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
                Err(std::io::Error::last_os_error())
            } else {
                Ok(len as usize)
            }
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Drop for BIOSocketStream {
    fn drop(&mut self) {
        // The BIO is automatically freed when SSL_free is called on the SSL object,
        // so we don't need to manually free the BIO here. The SSL object will be
        // dropped automatically via its Drop implementation.
        //
        // Note: We used SSL_set_bio(ssl, bio, bio) which means both read and write
        // BIOs point to the same BIO object, and SSL takes ownership of it.
    }
}
