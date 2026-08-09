//! An in-memory duplex transport implementing compio's I/O traits, with hooks
//! for injecting the failures a real socket makes hard to reproduce.
//!
//! Two things motivate it. First, spec SC-002 asks the stream to work over a
//! transport with no operating-system handle, which proves the design is
//! genuinely transport-agnostic. Second, conditions like "the peer accepts one
//! byte at a time", "the write direction stalls forever", and "the connection
//! dies without `close_notify`" are timing-dependent and flaky over loopback
//! TCP, but deterministic here.
//!
//! compio publishes no in-memory duplex type; its own tests define a private
//! one the same way.

#![allow(dead_code)]

use std::cell::RefCell;
use std::collections::VecDeque;
use std::io;
use std::rc::Rc;
use std::task::Waker;

use compio_buf::{BufResult, IoBuf, IoBufMut};
use compio_io::{AsyncRead, AsyncWrite};

/// How an endpoint should misbehave.
#[derive(Debug, Clone, Copy, Default)]
pub struct Faults {
    /// Deliver at most this many bytes per read, simulating fragmentation.
    pub max_read: Option<usize>,
    /// Accept at most this many bytes per write, simulating a short write.
    pub max_write: Option<usize>,
    /// Never accept writes; they stay pending forever.
    pub stall_writes: bool,
    /// Fail the next read with this error kind instead of returning data.
    pub read_error: Option<io::ErrorKind>,
    /// Fail the next write with this error kind.
    pub write_error: Option<io::ErrorKind>,
}

#[derive(Default)]
struct Channel {
    buf: VecDeque<u8>,
    /// The writer has gone away; readers see end-of-stream once drained.
    closed: bool,
    waker: Option<Waker>,
}

impl Channel {
    fn wake(&mut self) {
        if let Some(w) = self.waker.take() {
            w.wake();
        }
    }
}

/// One end of an in-memory duplex pair.
pub struct MemoryStream {
    /// Bytes this endpoint reads from.
    rx: Rc<RefCell<Channel>>,
    /// Bytes this endpoint writes into.
    tx: Rc<RefCell<Channel>>,
    faults: Rc<RefCell<Faults>>,
}

/// Create a connected pair of endpoints.
pub fn duplex() -> (MemoryStream, MemoryStream) {
    let a = Rc::new(RefCell::new(Channel::default()));
    let b = Rc::new(RefCell::new(Channel::default()));
    (
        MemoryStream {
            rx: a.clone(),
            tx: b.clone(),
            faults: Rc::new(RefCell::new(Faults::default())),
        },
        MemoryStream {
            rx: b,
            tx: a,
            faults: Rc::new(RefCell::new(Faults::default())),
        },
    )
}

impl MemoryStream {
    /// Handle for adjusting this endpoint's fault injection at any time,
    /// including from another task while an operation is outstanding.
    pub fn faults(&self) -> Rc<RefCell<Faults>> {
        self.faults.clone()
    }

    pub fn set_faults(&self, f: Faults) {
        *self.faults.borrow_mut() = f;
    }

    /// Drop the write side abruptly, as a reset would. Readers see whatever was
    /// already buffered and then end-of-stream — with no TLS `close_notify`,
    /// which is exactly the truncation case.
    pub fn close_write(&self) {
        let mut tx = self.tx.borrow_mut();
        tx.closed = true;
        tx.wake();
    }

    /// Split into the two halves the stream stores. Any `(R, W)` tuple is
    /// `Splittable`, so this is all a transport needs to provide.
    pub fn into_halves(self) -> (MemoryReadHalf, MemoryWriteHalf) {
        (
            MemoryReadHalf {
                rx: self.rx,
                faults: self.faults.clone(),
            },
            MemoryWriteHalf {
                tx: self.tx,
                faults: self.faults,
            },
        )
    }
}

/// Read half of a [`MemoryStream`].
pub struct MemoryReadHalf {
    rx: Rc<RefCell<Channel>>,
    faults: Rc<RefCell<Faults>>,
}

/// Write half of a [`MemoryStream`].
pub struct MemoryWriteHalf {
    tx: Rc<RefCell<Channel>>,
    faults: Rc<RefCell<Faults>>,
}

impl MemoryWriteHalf {
    pub fn close(&self) {
        let mut tx = self.tx.borrow_mut();
        tx.closed = true;
        tx.wake();
    }
}

/// Copy out of `chan` into `buf`, honoring the read faults.
///
/// Returns `None` when nothing is available yet and the caller should park.
fn try_read<B: IoBufMut>(
    chan: &Rc<RefCell<Channel>>,
    faults: &Rc<RefCell<Faults>>,
    buf: &mut B,
) -> Option<io::Result<usize>> {
    if let Some(kind) = faults.borrow_mut().read_error.take() {
        return Some(Err(io::Error::from(kind)));
    }

    let mut c = chan.borrow_mut();
    let cap = buf.buf_capacity();
    if cap == 0 {
        return Some(Ok(0));
    }

    if c.buf.is_empty() {
        // A closed and drained channel is a clean end of stream.
        return if c.closed { Some(Ok(0)) } else { None };
    }

    let limit = faults.borrow().max_read.unwrap_or(usize::MAX);
    let n = c.buf.len().min(cap).min(limit);

    let dst = &mut buf.as_uninit()[..n];
    for (slot, byte) in dst.iter_mut().zip(c.buf.drain(..n)) {
        slot.write(byte);
    }
    // SAFETY: the `n` bytes above were just initialized, and `n <= capacity`.
    unsafe { buf.set_len(n) };
    Some(Ok(n))
}

/// Copy `data` into `chan`, honoring the write faults.
fn try_write(
    chan: &Rc<RefCell<Channel>>,
    faults: &Rc<RefCell<Faults>>,
    data: &[u8],
) -> Option<io::Result<usize>> {
    {
        let mut f = faults.borrow_mut();
        if let Some(kind) = f.write_error.take() {
            return Some(Err(io::Error::from(kind)));
        }
        if f.stall_writes {
            return None;
        }
    }

    if data.is_empty() {
        return Some(Ok(0));
    }

    let mut c = chan.borrow_mut();
    if c.closed {
        return Some(Err(io::Error::from(io::ErrorKind::BrokenPipe)));
    }

    let limit = faults.borrow().max_write.unwrap_or(usize::MAX);
    let n = data.len().min(limit);
    c.buf.extend(&data[..n]);
    c.wake();
    Some(Ok(n))
}

/// Park until `chan` has data, the peer closes, or the fault state changes.
async fn wait_readable(chan: &Rc<RefCell<Channel>>) {
    std::future::poll_fn(|cx| {
        let mut c = chan.borrow_mut();
        if !c.buf.is_empty() || c.closed {
            std::task::Poll::Ready(())
        } else {
            c.waker = Some(cx.waker().clone());
            std::task::Poll::Pending
        }
    })
    .await
}

impl AsyncRead for MemoryReadHalf {
    async fn read<B: IoBufMut>(&mut self, mut buf: B) -> BufResult<usize, B> {
        loop {
            match try_read(&self.rx, &self.faults, &mut buf) {
                Some(r) => return BufResult(r, buf),
                None => wait_readable(&self.rx).await,
            }
        }
    }
}

impl AsyncWrite for MemoryWriteHalf {
    async fn write<B: IoBuf>(&mut self, buf: B) -> BufResult<usize, B> {
        loop {
            let r = { try_write(&self.tx, &self.faults, buf.as_init()) };
            match r {
                Some(r) => return BufResult(r, buf),
                None => {
                    // Stalled: yield so a concurrent task can clear the fault
                    // or make progress. A test that stalls forever relies on a
                    // timeout to fail rather than hang.
                    compio_runtime_yield().await;
                }
            }
        }
    }

    async fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }

    async fn shutdown(&mut self) -> io::Result<()> {
        self.close();
        Ok(())
    }
}

impl AsyncRead for MemoryStream {
    async fn read<B: IoBufMut>(&mut self, mut buf: B) -> BufResult<usize, B> {
        loop {
            match try_read(&self.rx, &self.faults, &mut buf) {
                Some(r) => return BufResult(r, buf),
                None => wait_readable(&self.rx).await,
            }
        }
    }
}

impl AsyncWrite for MemoryStream {
    async fn write<B: IoBuf>(&mut self, buf: B) -> BufResult<usize, B> {
        loop {
            let r = { try_write(&self.tx, &self.faults, buf.as_init()) };
            match r {
                Some(r) => return BufResult(r, buf),
                None => compio_runtime_yield().await,
            }
        }
    }

    async fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }

    async fn shutdown(&mut self) -> io::Result<()> {
        self.close_write();
        Ok(())
    }
}

/// Yield once to the executor.
async fn compio_runtime_yield() {
    let mut yielded = false;
    std::future::poll_fn(move |cx| {
        if yielded {
            std::task::Poll::Ready(())
        } else {
            yielded = true;
            cx.waker().wake_by_ref();
            std::task::Poll::Pending
        }
    })
    .await
}
