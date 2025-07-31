use std::{
    ops::{Deref, DerefMut},
    os::fd::RawFd,
};

use openssl::error::ErrorStack;

use crate::kbio::{
    ffi::{BIO_NOCLOSE, BIO_push},
    passthrough::PassThroughBIO,
};

pub struct SslStream3(pub openssl::ssl::SslStream<PassThroughBIO>);

impl SslStream3 {
    pub fn new_socket(fd: RawFd, ssl: openssl::ssl::Ssl) -> Result<Self, ErrorStack> {
        let sock_bio = unsafe { openssl_sys::BIO_new_socket(fd, BIO_NOCLOSE) };
        let bio = PassThroughBIO::new(sock_bio);
        let s = openssl::ssl::SslStream::new(ssl, bio)?;
        // Hook up the stream rust bio with the pass through bio.
        use foreign_types_shared::ForeignTypeRef;
        let rs_rbio = unsafe { openssl_sys::SSL_get_rbio(s.ssl().as_ptr()) };
        {
            let rs_wbio = unsafe { openssl_sys::SSL_get_wbio(s.ssl().as_ptr()) };
            assert_eq!(rs_rbio, rs_wbio)
        }
        unsafe { BIO_push(rs_rbio, sock_bio) };
        //HACK: replace rs bio with sock bio
        // use foreign_types_shared::ForeignTypeRef;
        // unsafe { openssl_sys::SSL_set_bio(s.ssl().as_ptr(), sock_bio, sock_bio) };
        Ok(SslStream3(s))
    }
}

impl Deref for SslStream3 {
    type Target = openssl::ssl::SslStream<PassThroughBIO>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for SslStream3 {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
