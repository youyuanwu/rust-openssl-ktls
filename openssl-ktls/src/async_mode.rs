use std::ffi::c_int;
use std::task::Waker;

use crate::ffi::SSL_get_async_status;

/// Raw SSL async callback function that wakes up the async task
pub extern "C" fn raw_ssl_async_callback_fn(
    _ssl: *mut openssl_sys::SSL,
    arg: *mut std::ffi::c_void,
) -> c_int {
    println!("🔧 Raw SSL async callback called");
    if !arg.is_null() {
        unsafe {
            // Safety: arg should be a pointer to a boxed Waker
            let waker_box = Box::from_raw(arg as *mut Waker);
            // Wake the task
            waker_box.wake();
            // Waker is consumed and cleaned up automatically
        }
    }
    1 // Return 1 to indicate success
}

pub fn get_async_status(ssl: &openssl::ssl::Ssl) -> AsyncStatus {
    use foreign_types_shared::ForeignType;
    let mut status = 0;
    unsafe {
        if SSL_get_async_status(ssl.as_ptr(), &mut status) == 1 {
            AsyncStatus::from(status)
        } else {
            AsyncStatus::UNKNOWN
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AsyncStatus {
    OK,
    EAGAIN,
    ERR,
    UNSUPPORTED,
    UNKNOWN,
}

impl From<c_int> for AsyncStatus {
    fn from(value: c_int) -> Self {
        match value {
            crate::ffi::ASYNC_STATUS_OK => Self::OK,
            crate::ffi::ASYNC_STATUS_EAGAIN => Self::EAGAIN,
            crate::ffi::ASYNC_STATUS_ERR => Self::ERR,
            crate::ffi::ASYNC_STATUS_UNSUPPORTED => Self::UNSUPPORTED,
            _ => Self::UNKNOWN,
        }
    }
}

pub struct AsyncThread {}

impl AsyncThread {
    pub fn init(max_size: usize, init_size: usize) -> Result<Self, AsyncStatus> {
        let ret = unsafe { crate::ffi::ASYNC_init_thread(max_size, init_size) };
        if ret == 1 {
            Ok(Self {})
        } else {
            Err(AsyncStatus::ERR)
        }
    }

    pub fn is_capable() -> bool {
        unsafe { crate::ffi::ASYNC_is_capable() == 1 }
    }
}

impl Default for AsyncThread {
    fn default() -> Self {
        Self::init(4, 4).unwrap()
    }
}

impl Drop for AsyncThread {
    fn drop(&mut self) {
        unsafe {
            crate::ffi::ASYNC_cleanup_thread();
        }
    }
}
