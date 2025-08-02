// Various bio experiments and tests.

use std::ffi::{c_char, c_int, c_long, c_void};

use openssl::error::ErrorStack;
use openssl_sys::{
    BIO, BIO_TYPE_NONE, BIO_get_data, BIO_meth_new, BIO_meth_set_create__fixed_rust,
    BIO_meth_set_ctrl__fixed_rust, BIO_meth_set_destroy__fixed_rust, BIO_meth_set_puts__fixed_rust,
    BIO_meth_set_read__fixed_rust, BIO_meth_set_write__fixed_rust, BIO_set_data, BIO_set_flags,
    BIO_set_init,
};

pub mod ffi;

pub trait Bio {
    fn read(&self, buf: &mut [u8]) -> Result<usize, std::io::Error>;
    fn write(&self, buf: &[u8]) -> Result<usize, std::io::Error>;
    fn puts(&self, buf: &[u8]) -> Result<(), std::io::Error>;
    fn ctrl(&self, cmd: c_int, arg: c_long) -> Result<c_long, std::io::Error>;
    fn create(&self) -> Result<(), std::io::Error>;
    fn destroy(&self) -> Result<(), std::io::Error>;
}

#[inline]
fn cvt(r: c_int) -> Result<c_int, ErrorStack> {
    if r <= 0 {
        Err(ErrorStack::get())
    } else {
        Ok(r)
    }
}

#[inline]
fn cvt_p<T>(r: *mut T) -> Result<*mut T, ErrorStack> {
    if r.is_null() {
        Err(ErrorStack::get())
    } else {
        Ok(r)
    }
}

/// The same as `slice::from_raw_parts`, except that `data` may be `NULL` if
/// `len` is 0.
unsafe fn from_raw_parts<'a, T>(data: *const T, len: usize) -> &'a [T] {
    if len == 0 {
        &[]
    } else {
        // Using this to implement the preferred API
        unsafe {
            #[allow(clippy::disallowed_methods)]
            std::slice::from_raw_parts(data, len)
        }
    }
}

/// The same as `slice::from_raw_parts_mut`, except that `data` may be `NULL`
/// if `len` is 0.
unsafe fn from_raw_parts_mut<'a, T>(data: *mut T, len: usize) -> &'a mut [T] {
    if len == 0 {
        &mut []
    } else {
        // Using this to implement the preferred API
        unsafe {
            #[allow(clippy::disallowed_methods)]
            std::slice::from_raw_parts_mut(data, len)
        }
    }
}

#[allow(bad_style, clippy::upper_case_acronyms)]
struct BIO_METHOD(*mut openssl_sys::BIO_METHOD);

unsafe extern "C" fn bwrite<B: Bio>(bio: *mut BIO, buf: *const c_char, len: c_int) -> c_int {
    let data = unsafe { get_data::<B>(bio) };
    match data.write(unsafe { from_raw_parts(buf as *const u8, len as usize) }) {
        Ok(n) => n as c_int,
        Err(_) => -1, // set last error?
    }
}
unsafe extern "C" fn bread<B: Bio>(bio: *mut BIO, buf: *mut c_char, len: c_int) -> c_int {
    let buff = unsafe { from_raw_parts_mut(buf as *mut u8, len as usize) };
    let data = unsafe { get_data::<B>(bio) };
    match data.read(buff) {
        Ok(n) => n as c_int,
        Err(_) => -1, // set last error?
    }
}
unsafe extern "C" fn bputs<B: Bio>(bio: *mut BIO, buf: *const c_char) -> c_int {
    // Convert C string to Rust slice
    let c_str = unsafe { std::ffi::CStr::from_ptr(buf) };
    let bytes = c_str.to_bytes(); // This excludes the null terminator

    let data = unsafe { get_data::<B>(bio) };
    match data.puts(bytes) {
        Ok(()) => 1,  // Success
        Err(_) => -1, // Error
    }
}
unsafe extern "C" fn ctrl<B: Bio>(
    bio: *mut BIO,
    cmd: c_int,
    num: c_long,
    _ptr: *mut c_void,
) -> c_long {
    let data = unsafe { get_data::<B>(bio) };
    data.ctrl(cmd, num).unwrap_or(-1)
}
unsafe extern "C" fn create(bio: *mut BIO) -> c_int {
    unsafe { BIO_set_init(bio, 0) };
    // unsafe { BIO_set_num(bio, 0) };
    unsafe { BIO_set_data(bio, std::ptr::null_mut()) };
    unsafe { BIO_set_flags(bio, 0) };
    1
}
unsafe extern "C" fn destroy<B: Bio>(bio: *mut BIO) -> c_int {
    if bio.is_null() {
        return 0;
    }

    let data = unsafe { BIO_get_data(bio) };
    assert!(!data.is_null());
    let _ = unsafe { Box::<dyn Bio>::from_raw(data as *mut B) };
    unsafe { BIO_set_data(bio, std::ptr::null_mut()) };
    unsafe { BIO_set_init(bio, 0) };
    1
}

unsafe fn get_data<'a, B: 'a>(bio: *mut BIO) -> &'a mut B {
    unsafe { &mut *(BIO_get_data(bio) as *mut _) }
}

#[allow(dead_code)]
fn bio_make_method<B: Bio>() -> Result<BIO_METHOD, ErrorStack> {
    unsafe {
        let ptr = cvt_p(BIO_meth_new(BIO_TYPE_NONE, c"rust".as_ptr() as *const _))?;
        let method = BIO_METHOD(ptr);
        cvt(BIO_meth_set_write__fixed_rust(method.0, Some(bwrite::<B>)))?;
        cvt(BIO_meth_set_read__fixed_rust(method.0, Some(bread::<B>)))?;
        cvt(BIO_meth_set_puts__fixed_rust(method.0, Some(bputs::<B>)))?;
        cvt(BIO_meth_set_ctrl__fixed_rust(method.0, Some(ctrl::<B>)))?;
        cvt(BIO_meth_set_create__fixed_rust(method.0, Some(create)))?;
        cvt(BIO_meth_set_destroy__fixed_rust(
            method.0,
            Some(destroy::<B>),
        ))?;
        Ok(method)
    }
}

#[cfg(test)]
mod tests;
