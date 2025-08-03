use std::ffi::{c_int, c_long};

use openssl_sys::BIO_ctrl;

pub const BIO_CTRL_GET_KTLS_SEND: c_int = 73;
pub const BIO_CTRL_GET_KTLS_RECV: c_int = 76;

pub const SSL_OP_ENABLE_KTLS: u64 = 0x00000008;

// BIO control operation wrapper functions
// These provide type-safe Rust wrappers for common BIO control operations.

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

pub const BIO_NOCLOSE: c_int = 0x00;
// pub const BIO_CLOSE: c_int = 0x01;
