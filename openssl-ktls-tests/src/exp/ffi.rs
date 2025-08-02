use std::ffi::{c_char, c_long};

use openssl_sys::{BIO_ctrl, c_int};

pub const BIO_CTRL_SET_KTLS_SEND: c_int = 72;
pub const BIO_C_GET_BUF_MEM_PTR: c_int = 115;

// BIO control constants
pub const BIO_CTRL_FLUSH: c_int = 11;
pub const BIO_C_DO_STATE_MACHINE: c_int = 101;

unsafe extern "C" {
    pub unsafe fn BIO_free(b: *mut openssl_sys::BIO);
    pub unsafe fn BIO_next(b: *mut openssl_sys::BIO) -> *mut openssl_sys::BIO;
    /* put the 'bio' on the end of b's list of operators */
    pub unsafe fn BIO_push(
        b: *mut openssl_sys::BIO,
        bio: *mut openssl_sys::BIO,
    ) -> *mut openssl_sys::BIO;
    // const BIO_METHOD *BIO_f_base64(void)
    pub unsafe fn BIO_f_base64() -> *const openssl_sys::BIO_METHOD;

    // Null filter BIO - passes data through unchanged
    pub unsafe fn BIO_f_null() -> *const openssl_sys::BIO_METHOD;

    // Buffer filter BIO - buffers data but passes it through
    pub unsafe fn BIO_f_buffer() -> *const openssl_sys::BIO_METHOD;

    // BIO pair - creates two connected BIOs
    pub unsafe fn BIO_s_bio() -> *const openssl_sys::BIO_METHOD;

    // sockets

    // BIO *BIO_new_connect(const char *host_port);
    pub unsafe fn BIO_new_connect(host_port: *const c_char) -> *mut openssl_sys::BIO;
}

// Custom functions

/// # Safety
/// Get the last BIO in the chain.
#[allow(non_snake_case)]
pub unsafe fn BIO_get_last(b: *mut openssl_sys::BIO) -> *mut openssl_sys::BIO {
    assert!(!b.is_null());
    let mut last_bio: *mut openssl_sys::BIO = std::ptr::null_mut();
    let mut current_bio = b;
    while !current_bio.is_null() {
        last_bio = current_bio;
        current_bio = unsafe { BIO_next(current_bio) };
    }
    last_bio
}

/// # Safety
// # define BIO_get_mem_ptr(b,pp)   BIO_ctrl(b,BIO_C_GET_BUF_MEM_PTR,0, (char *)(pp))
#[allow(non_snake_case)]
pub unsafe fn BIO_get_mem_ptr(b: *mut openssl_sys::BIO, buf_mem: *mut *mut BUF_MEM) -> c_long {
    unsafe { BIO_ctrl(b, BIO_C_GET_BUF_MEM_PTR, 0, buf_mem as *mut _) }
}

#[allow(non_camel_case_types)]
#[repr(C)]
pub struct BUF_MEM {
    pub length: usize, /* current number of bytes */
    pub data: *mut c_char,
    max: usize, /* size of buffer */
    flags: u64,
}

/// # Safety
// # define BIO_do_handshake(b)     BIO_ctrl(b,BIO_C_DO_STATE_MACHINE,0,NULL)
#[allow(non_snake_case)]
#[inline]
pub unsafe fn BIO_do_handshake(b: *mut openssl_sys::BIO) -> c_long {
    unsafe { BIO_ctrl(b, BIO_C_DO_STATE_MACHINE, 0, std::ptr::null_mut()) }
}

/// # Safety
// # define BIO_do_connect(b)       BIO_do_handshake(b)
#[allow(non_snake_case)]
#[inline]
pub unsafe fn BIO_do_connect(b: *mut openssl_sys::BIO) -> c_long {
    unsafe { BIO_do_handshake(b) }
}

/// # Safety
// # define BIO_flush(b)            (int)BIO_ctrl(b,BIO_CTRL_FLUSH,0,NULL)
#[allow(non_snake_case)]
#[inline]
pub unsafe fn BIO_flush(b: *mut openssl_sys::BIO) -> c_int {
    unsafe {
        BIO_ctrl(b, openssl_sys::BIO_CTRL_FLUSH, 0, std::ptr::null_mut())
            .try_into()
            .unwrap()
    }
}
