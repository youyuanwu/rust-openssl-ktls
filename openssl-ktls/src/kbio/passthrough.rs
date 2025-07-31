pub struct PassThroughBIO {
    next_bio: Option<*mut openssl_sys::BIO>,
}

impl PassThroughBIO {
    pub fn new(next_bio: *mut openssl_sys::BIO) -> Self {
        PassThroughBIO {
            next_bio: Some(next_bio),
        }
    }
}

// Read write operations will be passed through to the next BIO in the chain.

impl std::io::Read for PassThroughBIO {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        unsafe {
            let len = openssl_sys::BIO_read(
                self.next_bio.unwrap(),
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

impl std::io::Write for PassThroughBIO {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        unsafe {
            let len = openssl_sys::BIO_write(
                self.next_bio.unwrap(),
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
