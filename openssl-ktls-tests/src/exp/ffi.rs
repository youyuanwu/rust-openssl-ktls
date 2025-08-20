#![allow(non_camel_case_types, non_snake_case)]
use std::ffi::{c_char, c_long};

use openssl_sys::{BIO_ctrl, c_int};

// OpenSSL opaque type definitions for custom engines
#[repr(C)]
pub struct ENGINE {
    _private: [u8; 0],
}

#[repr(C)]
pub struct RSA_METHOD {
    _private: [u8; 0],
}

#[repr(C)]
pub struct ASYNC_WAIT_CTX {
    _private: [u8; 0],
}

#[repr(C)]
pub struct ASYNC_JOB {
    _private: [u8; 0],
}

#[repr(C)]
pub struct RSA {
    _private: [u8; 0],
}

// OSSL_ASYNC_FD is typically an int on Unix systems
pub type OSSL_ASYNC_FD = c_int;

pub const BIO_CTRL_SET_KTLS_SEND: c_int = 72;
pub const BIO_C_GET_BUF_MEM_PTR: c_int = 115;

// BIO control constants
pub const BIO_CTRL_FLUSH: c_int = 11;
pub const BIO_C_DO_STATE_MACHINE: c_int = 101;

// Engine flags
pub const ENGINE_FLAGS_MANUAL_CMD_CTRL: c_int = 0x0002;

// Async operation constants
// ASYNC constants
pub const ASYNC_PAUSE: c_int = 0;
pub const ASYNC_NO_JOBS: c_int = 1;
pub const ASYNC_ERR: c_int = -1;
pub const ASYNC_FINISH: c_int = 2; // Job completed successfully

// ASYNC_WAIT_CTX status constants
pub const ASYNC_STATUS_UNSUPPORTED: c_int = 0;
pub const ASYNC_STATUS_ERR: c_int = 1;
pub const ASYNC_STATUS_OK: c_int = 2;
pub const ASYNC_STATUS_EAGAIN: c_int = 3;

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

    // Engine and async functions for custom engines
    // ASYNC_JOB *ASYNC_get_current_job(void);
    pub fn ASYNC_get_current_job() -> *mut ASYNC_JOB;

    // int ASYNC_pause_job(void);
    pub fn ASYNC_pause_job() -> c_int;

    // ASYNC_WAIT_CTX *ASYNC_get_wait_ctx(ASYNC_JOB *job);
    pub fn ASYNC_get_wait_ctx(job: *mut ASYNC_JOB) -> *mut ASYNC_WAIT_CTX;

    // int ASYNC_start_job(ASYNC_JOB **job, ASYNC_WAIT_CTX *ctx, int *ret, int (*func)(void *), void *args, size_t size);
    pub fn ASYNC_start_job(
        job: *mut *mut ASYNC_JOB,
        ctx: *mut ASYNC_WAIT_CTX,
        ret: *mut c_int,
        func: extern "C" fn(*mut std::ffi::c_void) -> c_int,
        args: *mut std::ffi::c_void,
        size: usize,
    ) -> c_int;

    // int ASYNC_init_thread(size_t max_size, size_t init_size);
    pub fn ASYNC_init_thread(max_size: usize, init_size: usize) -> c_int;

    // void ASYNC_cleanup_thread(void);
    pub fn ASYNC_cleanup_thread();

    // ASYNC_WAIT_CTX *ASYNC_WAIT_CTX_new(void);
    pub fn ASYNC_WAIT_CTX_new() -> *mut ASYNC_WAIT_CTX;

    // void ASYNC_WAIT_CTX_free(ASYNC_WAIT_CTX *ctx);
    pub fn ASYNC_WAIT_CTX_free(ctx: *mut ASYNC_WAIT_CTX);

    // int ASYNC_wake(ASYNC_WAIT_CTX *ctx, const char *identifier);
    pub fn ASYNC_wake(ctx: *mut ASYNC_WAIT_CTX, identifier: *const std::os::raw::c_char) -> c_int;

    // int ASYNC_WAIT_CTX_set_status(ASYNC_WAIT_CTX *ctx, const void *key, int status);
    pub fn ASYNC_WAIT_CTX_set_status(
        ctx: *mut ASYNC_WAIT_CTX,
        key: *const std::os::raw::c_char,
        status: c_int,
    ) -> c_int;

    // ASYNC_WAIT_CTX callback functions
    pub fn ASYNC_WAIT_CTX_get_callback(
        ctx: *mut ASYNC_WAIT_CTX,
        callback: *mut Option<extern "C" fn(*mut std::ffi::c_void)>,
        callback_arg: *mut *mut std::ffi::c_void,
    ) -> c_int;

    // SSL callback functions for async operations
    pub fn SSL_get_async_callback(
        ssl: *mut openssl_sys::SSL,
    ) -> Option<extern "C" fn(*mut openssl_sys::SSL, *mut std::ffi::c_void) -> c_int>;
    pub fn SSL_get_async_callback_arg(ssl: *mut openssl_sys::SSL) -> *mut std::ffi::c_void;

    // Engine functions
    pub fn ENGINE_new() -> *mut ENGINE;
    pub fn ENGINE_free(engine: *mut ENGINE);
    pub fn ENGINE_set_id(engine: *mut ENGINE, id: *const std::os::raw::c_char) -> c_int;
    pub fn ENGINE_set_name(engine: *mut ENGINE, name: *const std::os::raw::c_char) -> c_int;
    pub fn ENGINE_set_init_function(
        engine: *mut ENGINE,
        init_f: Option<extern "C" fn(*mut ENGINE) -> c_int>,
    );
    pub fn ENGINE_set_finish_function(
        engine: *mut ENGINE,
        finish_f: Option<extern "C" fn(*mut ENGINE) -> c_int>,
    );
    pub fn ENGINE_set_destroy_function(
        engine: *mut ENGINE,
        destroy_f: Option<extern "C" fn(*mut ENGINE) -> c_int>,
    );
    pub fn ENGINE_set_RSA(engine: *mut ENGINE, rsa_meth: *const RSA_METHOD) -> c_int;
    pub fn ENGINE_set_flags(engine: *mut ENGINE, flags: c_int);
    pub fn ENGINE_add(engine: *mut ENGINE) -> c_int;
    pub fn ENGINE_remove(engine: *mut ENGINE) -> c_int;
    pub fn ENGINE_init(engine: *mut ENGINE) -> c_int;
    pub fn ENGINE_finish(engine: *mut ENGINE) -> c_int;
    pub fn ENGINE_set_default_RSA(engine: *mut ENGINE) -> c_int;

    // RSA method functions
    pub fn RSA_meth_new(name: *const std::os::raw::c_char, flags: c_int) -> *mut RSA_METHOD;
    pub fn RSA_meth_free(meth: *mut RSA_METHOD);
    pub fn RSA_meth_set_pub_enc(
        meth: *mut RSA_METHOD,
        pub_enc: Option<extern "C" fn(c_int, *const u8, *mut u8, *mut RSA, c_int) -> c_int>,
    ) -> c_int;
    pub fn RSA_meth_set_pub_dec(
        meth: *mut RSA_METHOD,
        pub_dec: Option<extern "C" fn(c_int, *const u8, *mut u8, *mut RSA, c_int) -> c_int>,
    ) -> c_int;
    pub fn RSA_meth_set_priv_enc(
        meth: *mut RSA_METHOD,
        priv_enc: Option<extern "C" fn(c_int, *const u8, *mut u8, *mut RSA, c_int) -> c_int>,
    ) -> c_int;
    pub fn RSA_meth_set_priv_dec(
        meth: *mut RSA_METHOD,
        priv_dec: Option<extern "C" fn(c_int, *const u8, *mut u8, *mut RSA, c_int) -> c_int>,
    ) -> c_int;
    pub fn RSA_meth_set_mod_exp(
        meth: *mut RSA_METHOD,
        mod_exp: Option<
            extern "C" fn(
                *mut openssl_sys::BIGNUM,
                *const openssl_sys::BIGNUM,
                *const openssl_sys::BIGNUM,
                *const openssl_sys::BIGNUM,
                *mut openssl_sys::BN_CTX,
                *mut openssl_sys::BN_MONT_CTX,
            ) -> c_int,
        >,
    ) -> c_int;
    pub fn RSA_meth_set_bn_mod_exp(
        meth: *mut RSA_METHOD,
        bn_mod_exp: Option<
            extern "C" fn(
                *mut openssl_sys::BIGNUM,
                *const openssl_sys::BIGNUM,
                *const openssl_sys::BIGNUM,
                *const openssl_sys::BIGNUM,
                *mut openssl_sys::BN_CTX,
                *mut openssl_sys::BN_MONT_CTX,
            ) -> c_int,
        >,
    ) -> c_int;
    pub fn RSA_meth_set_init(
        meth: *mut RSA_METHOD,
        init: Option<extern "C" fn(*mut RSA) -> c_int>,
    ) -> c_int;
    pub fn RSA_meth_set_finish(
        meth: *mut RSA_METHOD,
        finish: Option<extern "C" fn(*mut RSA) -> c_int>,
    ) -> c_int;

    // RSA method getters (from default implementation)
    pub fn RSA_PKCS1_OpenSSL() -> *const RSA_METHOD;
    pub fn RSA_meth_get_pub_enc(
        meth: *const RSA_METHOD,
    ) -> Option<extern "C" fn(c_int, *const u8, *mut u8, *mut RSA, c_int) -> c_int>;
    pub fn RSA_meth_get_pub_dec(
        meth: *const RSA_METHOD,
    ) -> Option<extern "C" fn(c_int, *const u8, *mut u8, *mut RSA, c_int) -> c_int>;
    pub fn RSA_meth_get_priv_enc(
        meth: *const RSA_METHOD,
    ) -> Option<extern "C" fn(c_int, *const u8, *mut u8, *mut RSA, c_int) -> c_int>;
    pub fn RSA_meth_get_priv_dec(
        meth: *const RSA_METHOD,
    ) -> Option<extern "C" fn(c_int, *const u8, *mut u8, *mut RSA, c_int) -> c_int>;
    pub fn RSA_meth_get_mod_exp(
        meth: *const RSA_METHOD,
    ) -> Option<
        extern "C" fn(
            *mut openssl_sys::BIGNUM,
            *const openssl_sys::BIGNUM,
            *const openssl_sys::BIGNUM,
            *const openssl_sys::BIGNUM,
            *mut openssl_sys::BN_CTX,
            *mut openssl_sys::BN_MONT_CTX,
        ) -> c_int,
    >;
    pub fn RSA_meth_get_bn_mod_exp(
        meth: *const RSA_METHOD,
    ) -> Option<
        extern "C" fn(
            *mut openssl_sys::BIGNUM,
            *const openssl_sys::BIGNUM,
            *const openssl_sys::BIGNUM,
            *const openssl_sys::BIGNUM,
            *mut openssl_sys::BN_CTX,
            *mut openssl_sys::BN_MONT_CTX,
        ) -> c_int,
    >;
    pub fn RSA_meth_get_init(meth: *const RSA_METHOD) -> Option<extern "C" fn(*mut RSA) -> c_int>;
    pub fn RSA_meth_get_finish(meth: *const RSA_METHOD)
    -> Option<extern "C" fn(*mut RSA) -> c_int>;

    // Error functions
    pub fn ERR_get_error() -> c_long;
    pub fn ERR_error_string(e: c_long, buf: *mut std::os::raw::c_char)
    -> *mut std::os::raw::c_char;

    // Provider API functions for OpenSSL 3.0+
    pub fn OSSL_PROVIDER_load(
        libctx: *mut openssl_sys::OSSL_LIB_CTX,
        name: *const std::os::raw::c_char,
    ) -> *mut crate::exp::custom_provider::OSSL_PROVIDER;

    pub fn OSSL_PROVIDER_unload(
        prov: *mut crate::exp::custom_provider::OSSL_PROVIDER,
    ) -> std::os::raw::c_int;

    pub fn OSSL_PROVIDER_available(
        libctx: *mut openssl_sys::OSSL_LIB_CTX,
        name: *const std::os::raw::c_char,
    ) -> std::os::raw::c_int;

    pub fn OSSL_PROVIDER_add_builtin(
        libctx: *mut openssl_sys::OSSL_LIB_CTX,
        name: *const std::os::raw::c_char,
        init_fn: unsafe extern "C" fn(
            *const crate::exp::custom_provider::OSSL_CORE_HANDLE,
            *const crate::exp::custom_provider::OSSL_DISPATCH,
            *mut *const crate::exp::custom_provider::OSSL_DISPATCH,
            *mut *mut std::ffi::c_void,
        ) -> std::os::raw::c_int,
    ) -> std::os::raw::c_int;

    pub fn OSSL_PROVIDER_get0_name(
        prov: *const crate::exp::custom_provider::OSSL_PROVIDER,
    ) -> *const std::os::raw::c_char;

    // Library context functions (if available)
    pub fn OSSL_LIB_CTX_new() -> *mut openssl_sys::OSSL_LIB_CTX;
    pub fn OSSL_LIB_CTX_free(libctx: *mut openssl_sys::OSSL_LIB_CTX);

    // Provider loading in specific library context
    pub fn OSSL_PROVIDER_load_ex(
        libctx: *mut openssl_sys::OSSL_LIB_CTX,
        name: *const std::os::raw::c_char,
        params: *const crate::exp::custom_provider::OSSL_PARAM,
    ) -> *mut crate::exp::custom_provider::OSSL_PROVIDER;

    // EVP default properties functions (OpenSSL 3.0+)
    pub fn EVP_set_default_properties(
        libctx: *mut openssl_sys::OSSL_LIB_CTX,
        propq: *const std::os::raw::c_char,
    ) -> c_int;

    pub fn EVP_get_default_properties(
        libctx: *mut openssl_sys::OSSL_LIB_CTX,
    ) -> *const std::os::raw::c_char;
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
