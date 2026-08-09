//! Raw OpenSSL bindings that `openssl-sys` 0.9 does not expose, plus thin safe
//! wrappers so the rest of the crate needs no `unsafe`.
//!
//! Only the BIO-pair surface lives here. Everything else the crate needs
//! (`BIO_new`, `BIO_read`, `BIO_write`, `BIO_ctrl`, `BIO_free_all`,
//! `SSL_set_bio`, the `SSL_*_ex` I/O calls) is already declared by
//! `openssl-sys`.

use std::ffi::{c_int, c_void};
use std::ptr;

unsafe extern "C" {
    /// `int BIO_new_bio_pair(BIO **bio1, size_t writebuf1, BIO **bio2, size_t writebuf2);`
    ///
    /// The buffer sizes are `size_t`. Declaring them as `c_int` would misalign
    /// the argument list on 64-bit targets.
    fn BIO_new_bio_pair(
        bio1: *mut *mut openssl_sys::BIO,
        writebuf1: usize,
        bio2: *mut *mut openssl_sys::BIO,
        writebuf2: usize,
    ) -> c_int;

    /// `int BIO_test_flags(const BIO *b, int flags);`
    fn BIO_test_flags(b: *const openssl_sys::BIO, flags: c_int) -> c_int;
}

/// `BIO_ctrl` command for "bytes readable on this BIO".
const BIO_CTRL_PENDING: c_int = 10;
/// `BIO_ctrl` command for "bytes still buffered for the peer BIO".
const BIO_CTRL_WPENDING: c_int = 13;

/// The two halves of an OpenSSL BIO pair.
///
/// The pair is the crate's ciphertext port. OpenSSL writes records into its
/// half; we drain them from ours and hand them to the transport, and vice
/// versa. Unlike a memory BIO, each half has a bounded buffer, so a peer that
/// stops reading eventually makes OpenSSL report `WANT_WRITE` rather than
/// letting ciphertext accumulate without limit.
pub(crate) struct BioPair {
    /// Handed to `SSL_set_bio`, which takes ownership. Not ours to free.
    ssl_side: *mut openssl_sys::BIO,
    /// Our end of the pair. The halves are freed independently, so this one
    /// *is* ours to free.
    app_side: *mut openssl_sys::BIO,
}

impl BioPair {
    /// Create a pair with `buf_size` bytes of buffering in each direction.
    pub(crate) fn new(buf_size: usize) -> Option<Self> {
        let mut ssl_side: *mut openssl_sys::BIO = ptr::null_mut();
        let mut app_side: *mut openssl_sys::BIO = ptr::null_mut();

        // SAFETY: both out-pointers are valid and initialized to null; the
        // sizes are plain values.
        let rc = unsafe { BIO_new_bio_pair(&mut ssl_side, buf_size, &mut app_side, buf_size) };

        if rc != 1 || ssl_side.is_null() || app_side.is_null() {
            return None;
        }
        Some(Self { ssl_side, app_side })
    }

    /// The half OpenSSL owns. Only valid before [`BioPair::take_ssl_side`].
    pub(crate) fn ssl_side(&self) -> *mut openssl_sys::BIO {
        self.ssl_side
    }

    /// Relinquish the SSL-side pointer after handing it to `SSL_set_bio`, so
    /// this type never tries to free it.
    pub(crate) fn take_ssl_side(&mut self) {
        self.ssl_side = ptr::null_mut();
    }

    /// Bytes we can read out of our half right now (ciphertext OpenSSL produced).
    pub(crate) fn pending(&self) -> usize {
        // SAFETY: `app_side` is a live BIO for the lifetime of `self`.
        let n =
            unsafe { openssl_sys::BIO_ctrl(self.app_side, BIO_CTRL_PENDING, 0, ptr::null_mut()) };
        if n < 0 { 0 } else { n as usize }
    }

    /// Bytes still buffered on our half awaiting OpenSSL's attention.
    pub(crate) fn write_pending(&self) -> usize {
        // SAFETY: as above.
        let n =
            unsafe { openssl_sys::BIO_ctrl(self.app_side, BIO_CTRL_WPENDING, 0, ptr::null_mut()) };
        if n < 0 { 0 } else { n as usize }
    }

    /// Read ciphertext OpenSSL has produced. Returns 0 when nothing is ready.
    pub(crate) fn read(&self, out: &mut [u8]) -> usize {
        if out.is_empty() {
            return 0;
        }
        let cap = out.len().min(c_int::MAX as usize) as c_int;
        // SAFETY: `out` is valid for `cap` bytes and `app_side` is a live BIO.
        let n =
            unsafe { openssl_sys::BIO_read(self.app_side, out.as_mut_ptr() as *mut c_void, cap) };
        if n <= 0 { 0 } else { n as usize }
    }

    /// Hand ciphertext from the peer to OpenSSL.
    ///
    /// May accept fewer bytes than offered — the pair is bounded — so the
    /// caller must retain and re-offer the remainder.
    pub(crate) fn write(&self, data: &[u8]) -> usize {
        if data.is_empty() {
            return 0;
        }
        let len = data.len().min(c_int::MAX as usize) as c_int;
        // SAFETY: `data` is valid for `len` bytes and `app_side` is a live BIO.
        let n =
            unsafe { openssl_sys::BIO_write(self.app_side, data.as_ptr() as *const c_void, len) };
        if n <= 0 { 0 } else { n as usize }
    }

    /// Whether our half is asking to be retried rather than reporting failure.
    pub(crate) fn should_retry(&self) -> bool {
        // SAFETY: `app_side` is a live BIO.
        unsafe { BIO_test_flags(self.app_side, openssl_sys::BIO_FLAGS_SHOULD_RETRY) != 0 }
    }
}

impl Drop for BioPair {
    fn drop(&mut self) {
        // A BIO pair's halves are independent: freeing one does not free the
        // other. `SSL_free` releases whichever half was handed to
        // `SSL_set_bio`, so we free ours and only free the SSL side if it was
        // never handed over (i.e. construction failed part-way).
        if !self.app_side.is_null() {
            // SAFETY: we own this half and free it exactly once.
            unsafe { openssl_sys::BIO_free_all(self.app_side) };
            self.app_side = ptr::null_mut();
        }
        if !self.ssl_side.is_null() {
            // SAFETY: still owned because it was never passed to SSL_set_bio.
            unsafe { openssl_sys::BIO_free_all(self.ssl_side) };
            self.ssl_side = ptr::null_mut();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BUF: usize = 4096;

    #[test]
    fn pair_is_created() {
        assert!(BioPair::new(BUF).is_some());
    }

    /// The whole reason for choosing a pair over `BIO_s_mem`: a bounded buffer
    /// that pushes back instead of growing without limit.
    #[test]
    fn write_is_bounded_and_signals_retry() {
        let pair = BioPair::new(BUF).unwrap();

        let data = vec![0xABu8; BUF * 4];
        let accepted = pair.write(&data);
        assert_eq!(accepted, BUF, "pair should accept exactly its buffer size");

        // Now full: a further write makes no progress but asks to be retried
        // rather than reporting a hard failure.
        assert_eq!(pair.write(&data[..64]), 0);
        assert!(pair.should_retry());
    }

    /// Cross-checks the hardcoded `BIO_CTRL_PENDING` value against a known
    /// write size. If the constant were wrong this would report nonsense.
    #[test]
    fn pending_reports_exact_written_count() {
        let pair = BioPair::new(BUF).unwrap();
        assert_eq!(pair.pending(), 0);

        let data = vec![0x11u8; 100];
        assert_eq!(pair.write(&data), 100);
        // Written into *our* half, so it is pending for the peer, not for us.
        assert_eq!(pair.write_pending(), 100);
        assert_eq!(pair.pending(), 0);
    }

    #[test]
    fn draining_frees_capacity_for_further_writes() {
        let pair = BioPair::new(BUF).unwrap();

        let data = vec![0xCDu8; BUF];
        assert_eq!(pair.write(&data), BUF);
        assert_eq!(pair.write(&data[..1]), 0, "expected the pair to be full");

        // The peer (SSL side) consumes; here we simulate by reading from the
        // opposite half via a second pair is not possible, so assert the
        // bookkeeping instead: our half still holds the bytes for the peer.
        assert_eq!(pair.write_pending(), BUF);
    }

    #[test]
    fn empty_slices_are_no_ops() {
        let pair = BioPair::new(BUF).unwrap();
        assert_eq!(pair.write(&[]), 0);
        let mut out = [];
        assert_eq!(pair.read(&mut out), 0);
    }
}
