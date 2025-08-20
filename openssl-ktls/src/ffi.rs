#![allow(non_camel_case_types, non_snake_case)]

use std::ffi::{c_int, c_long};

use openssl_sys::BIO_ctrl;

pub const BIO_CTRL_GET_KTLS_SEND: c_int = 73;
pub const BIO_CTRL_GET_KTLS_RECV: c_int = 76;

pub const SSL_OP_ENABLE_KTLS: u64 = 0x00000008;

pub const SSL_MODE_ASYNC: i64 = 0x00000100;

/// Want asynchronous operation
pub const SSL_ERROR_WANT_ASYNC: c_int = 9;

// BIO control operation wrapper functions
// These provide type-safe Rust wrappers for common BIO control operations.

/// # Safety
/// This function must be called with a valid BIO pointer.
pub unsafe fn BIO_get_ktls_send(b: *mut openssl_sys::BIO) -> c_long {
    unsafe { BIO_ctrl(b, BIO_CTRL_GET_KTLS_SEND, 0, std::ptr::null_mut()) }
}
/// # Safety
/// This function must be called with a valid BIO pointer.
/// Attempts to enable KTLS send on the BIO. Returns 1 on success, 0 on failure.
pub unsafe fn BIO_get_ktls_recv(b: *mut openssl_sys::BIO) -> c_long {
    unsafe { BIO_ctrl(b, BIO_CTRL_GET_KTLS_RECV, 0, std::ptr::null_mut()) }
}

pub const BIO_NOCLOSE: c_int = 0x00;
// pub const BIO_CLOSE: c_int = 0x01;

// typedef int (*SSL_async_callback_fn)(SSL *s, void *arg);
pub type SSL_async_callback_fn =
    extern "C" fn(*mut openssl_sys::SSL, *mut std::ffi::c_void) -> c_int;

// async mode functions.
unsafe extern "C" {
    // int SSL_set_async_callback(SSL *s, SSL_async_callback_fn callback);
    pub fn SSL_set_async_callback(
        ssl: *mut openssl_sys::SSL,
        callback: Option<SSL_async_callback_fn>,
    ) -> c_int;

    //int SSL_set_async_callback_arg(SSL *s, void *arg);
    pub fn SSL_set_async_callback_arg(
        ssl: *mut openssl_sys::SSL,
        arg: *mut std::ffi::c_void,
    ) -> c_int;

    // __owur int SSL_get_async_status(SSL *s, int *status);
    pub fn SSL_get_async_status(ssl: *mut openssl_sys::SSL, status: *mut c_int) -> c_int;

    // long SSL_set_mode(SSL *s, long mode);
    pub fn SSL_set_mode(ssl: *mut openssl_sys::SSL, mode: c_long) -> c_long;

    // int ASYNC_init_thread(size_t max_size, size_t init_size);
    pub fn ASYNC_init_thread(max_size: usize, init_size: usize) -> c_int;
    // void ASYNC_cleanup_thread(void);
    pub fn ASYNC_cleanup_thread();
    // int ASYNC_is_capable(void);
    pub fn ASYNC_is_capable() -> c_int;

    // SSL_CTX *SSL_CTX_new_ex(OSSL_LIB_CTX *libctx, const char *propq, const SSL_METHOD *method);
    pub fn SSL_CTX_new_ex(
        libctx: *mut openssl_sys::OSSL_LIB_CTX,
        propq: *const std::ffi::c_char,
        method: *const openssl_sys::SSL_METHOD,
    ) -> *mut openssl_sys::SSL_CTX;

    // const SSL_METHOD *TLS_method(void);
    pub fn TLS_method() -> *const openssl_sys::SSL_METHOD;
}

// SSL_ctrl((ssl),SSL_CTRL_MODE,0,NULL)
/// # Safety
/// The `ssl` pointer must be a valid pointer to an initialized SSL object.
pub unsafe fn SSL_get_mode(ssl: *mut openssl_sys::SSL) -> c_long {
    unsafe { openssl_sys::SSL_ctrl(ssl, openssl_sys::SSL_CTRL_MODE, 0, std::ptr::null_mut()) }
}

// #define ASYNC_STATUS_UNSUPPORTED    0
// #define ASYNC_STATUS_ERR            1
// #define ASYNC_STATUS_OK             2
// #define ASYNC_STATUS_EAGAIN         3

pub const ASYNC_STATUS_UNSUPPORTED: c_int = 0;
pub const ASYNC_STATUS_ERR: c_int = 1;
pub const ASYNC_STATUS_OK: c_int = 2;
pub const ASYNC_STATUS_EAGAIN: c_int = 3;

/// Creates an SSL context with a specific library context
/// # Safety
/// The `libctx` pointer must be a valid pointer to an initialized OSSL_LIB_CTX object.
/// The returned SSL_CTX must be freed with SSL_CTX_free when no longer needed.
pub unsafe fn create_ssl_ctx_with_libctx(
    libctx: *mut openssl_sys::OSSL_LIB_CTX,
) -> *mut openssl_sys::SSL_CTX {
    let method = unsafe { TLS_method() };
    unsafe { SSL_CTX_new_ex(libctx, std::ptr::null(), method) }
}
