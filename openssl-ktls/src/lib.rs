use std::os::fd::RawFd;

use openssl_sys::BIO_new_socket;

use crate::kbio::ffi::{BIO_NOCLOSE, BIO_free, BIO_get_ktls_recv, BIO_get_ktls_send};

pub mod kbio;
pub use kbio::BIOSocketStream;
pub use kbio::SslStream3;

pub struct BIOSocket {
    pub bio: *mut openssl_sys::BIO,
}

impl BIOSocket {
    pub fn new(fd: RawFd) -> Self {
        let bio = unsafe { BIO_new_socket(fd, BIO_NOCLOSE) };
        if bio.is_null() {
            panic!("Failed to create BIO from socket");
        }
        BIOSocket { bio }
    }

    pub fn get_ktls_send(&self) -> bool {
        unsafe { BIO_get_ktls_send(self.bio) != 0 }
    }

    pub fn get_ktls_recv(&self) -> bool {
        unsafe { BIO_get_ktls_recv(self.bio) != 0 }
    }
}

impl Drop for BIOSocket {
    fn drop(&mut self) {
        // TODO:: how to free this?
        unsafe { BIO_free(self.bio) };
    }
}

impl std::io::Read for BIOSocket {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let len = unsafe {
            openssl_sys::BIO_read(
                self.bio,
                buf.as_mut_ptr() as *mut _,
                buf.len().try_into().unwrap(),
            )
        };
        if len < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(len as usize)
        }
    }
}

impl std::io::Write for BIOSocket {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        let len = unsafe {
            openssl_sys::BIO_write(
                self.bio,
                buf.as_ptr() as *const _,
                buf.len().try_into().unwrap(),
            )
        };
        if len < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(len as usize)
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

pub type SslStream2 = openssl::ssl::SslStream<BIOSocket>;
