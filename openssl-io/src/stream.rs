//! The public completion-based TLS stream.

use std::future::Future;
use std::mem::MaybeUninit;
use std::pin::Pin;
use std::task::Poll;

use compio_buf::{BufResult, IoBuf, IoBufMut};
use compio_io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use openssl::ssl::{Ssl, SslRef};

use crate::engine::{MAX_RECORD, Progress, Role, TlsEngine};
use crate::error::Error;

/// Size of the crate-owned ciphertext buffers moved to and from the transport.
const CIPHER_CHUNK: usize = 16 * 1024;

/// An in-flight transport read. The future owns the half it is reading from and
/// hands it back on completion, so the stream never has to borrow across an
/// await.
type ReadOp<R> = Pin<Box<dyn Future<Output = (R, BufResult<usize, Vec<u8>>)>>>;
/// An in-flight transport write, owning its half for the same reason.
type WriteOp<W> = Pin<Box<dyn Future<Output = (W, BufResult<(), Vec<u8>>)>>>;

/// A TLS stream over any completion-based transport.
///
/// The transport is supplied as something splittable into a reading and a
/// writing half. [`compio::net::TcpStream`] and `UnixStream` qualify directly;
/// anything else can be passed as the `(read_half, write_half)` tuple produced
/// by `compio_io::split`, since any `(R, W)` pair is splittable.
///
/// # Cancellation
///
/// Abandoning a read or a write — by dropping the future, for instance when a
/// timeout fires — is safe and leaves the session usable. In-flight transport
/// operations live in the stream rather than in the returned future, so a
/// dropped future cannot lose a completion or leave the byte stream
/// misaligned. The next operation resumes where the abandoned one left off.
///
/// An abandoned *write* is indeterminate: its bytes may or may not have been
/// committed, and the count is lost with the future. The session itself stays
/// correct, and the staged plaintext is completed by the following write.
pub struct SslStream<R, W> {
    engine: TlsEngine,

    /// Present when no transport read is in flight.
    read_half: Option<R>,
    /// Present when no transport write is in flight.
    write_half: Option<W>,
    /// A retained transport read, survives an abandoned public future.
    read_op: Option<ReadOp<R>>,
    /// A retained transport write, likewise.
    write_op: Option<WriteOp<W>>,

    /// Ciphertext drained from the engine but not yet handed to a transport
    /// write. Keeping it here means a retained write operation is never
    /// overtaken or discarded when more ciphertext appears.
    outbound: Vec<u8>,

    /// Ciphertext received but not yet accepted by OpenSSL. The BIO pair is
    /// bounded, so `put_inbound` can take less than offered and the remainder
    /// must be held here rather than dropped.
    inbound: Vec<u8>,

    /// Stable copy of the plaintext currently offered to OpenSSL. A retried
    /// `SSL_write_ex` must see byte-identical contents, so the payload cannot
    /// be borrowed from the caller across an await.
    stage: Vec<u8>,
}

impl<R, W> SslStream<R, W>
where
    R: AsyncRead + 'static,
    W: AsyncWrite + 'static,
{
    /// Wrap an already-connected transport, supplied as its two halves.
    pub fn new(ssl: Ssl, read_half: R, write_half: W) -> Result<Self, Error> {
        Ok(Self {
            engine: TlsEngine::new(ssl)?,
            read_half: Some(read_half),
            write_half: Some(write_half),
            read_op: None,
            write_op: None,
            outbound: Vec::new(),
            inbound: Vec::new(),
            stage: Vec::with_capacity(MAX_RECORD),
        })
    }

    /// Perform the handshake as the initiating side.
    pub async fn connect(&mut self) -> Result<(), Error> {
        self.handshake(Role::Client).await
    }

    /// Perform the handshake as the accepting side.
    pub async fn accept(&mut self) -> Result<(), Error> {
        self.handshake(Role::Server).await
    }

    async fn handshake(&mut self, role: Role) -> Result<(), Error> {
        loop {
            let progress = self.engine.step_handshake(role)?;
            if let Progress::Done(_) = progress
                && !self.engine.is_handshaking()
            {
                // Emit anything the final step produced before returning.
                self.flush_outbound().await?;
                return Ok(());
            }
            self.serve(progress).await?;
        }
    }

    /// Send `close_notify`, flushing anything still queued first.
    ///
    /// Returns as soon as our notification has reached the transport. Waiting
    /// for the peer's is not required and would let a silent peer hang us.
    pub async fn close(&mut self) -> Result<(), Error> {
        // A staged write still owes OpenSSL an identical retry; finish it
        // before closing or those records would never be emitted.
        self.finish_staged_write().await?;

        loop {
            let progress = self.engine.shutdown()?;
            match progress {
                Progress::Done(_) => {
                    self.flush_outbound().await?;
                    return Ok(());
                }
                _ => self.serve(progress).await?,
            }
        }
    }

    /// Recover the transport halves.
    ///
    /// Fails while a transport operation is in flight, because handing back a
    /// half that the runtime may still write into would be unsound. The stream
    /// is returned intact in that case, so nothing is lost.
    // The error deliberately carries the whole stream back: refusing recovery
    // must not destroy the session the caller still owns.
    #[allow(clippy::result_large_err)]
    pub fn into_inner(self) -> Result<(R, W), (Self, Error)> {
        if self.read_op.is_some() || self.write_op.is_some() {
            let err = Error::Transport(std::io::Error::other(
                "a transport operation is still in flight",
            ));
            return Err((self, err));
        }
        match (self.read_half, self.write_half) {
            (Some(r), Some(w)) => Ok((r, w)),
            (read_half, write_half) => {
                let err = Error::Transport(std::io::Error::other("transport halves unavailable"));
                Err((
                    Self {
                        engine: self.engine,
                        read_half,
                        write_half,
                        read_op: None,
                        write_op: None,
                        outbound: self.outbound,
                        inbound: self.inbound,
                        stage: self.stage,
                    },
                    err,
                ))
            }
        }
    }

    /// Inspect the underlying TLS session.
    ///
    /// Scoped rather than returning a reference: the session lives behind the
    /// stream's own bookkeeping, so lending it for the duration of a closure is
    /// what can be offered safely.
    pub fn with_ssl<T>(&self, f: impl FnOnce(&SslRef) -> T) -> T {
        f(self.engine.ssl())
    }

    /// Negotiated protocol version, once the handshake has completed.
    pub fn version(&self) -> &'static str {
        self.engine.ssl().version_str()
    }

    /// Negotiated cipher suite name, once the handshake has completed.
    pub fn cipher(&self) -> Option<String> {
        self.engine
            .ssl()
            .current_cipher()
            .map(|c| c.name().to_owned())
    }

    /// True once the peer's `close_notify` has been observed.
    pub fn is_peer_closed(&self) -> bool {
        self.engine.is_peer_closed()
    }

    // --- pump ---------------------------------------------------------------

    /// React to one [`Progress`] report.
    async fn serve(&mut self, progress: Progress) -> Result<(), Error> {
        match progress {
            Progress::Done(_) => Ok(()),
            Progress::NeedsFlush => self.flush_outbound().await,
            Progress::NeedsInbound => {
                // Records OpenSSL has already produced must be on their way
                // before we wait on the peer, or a handshake deadlocks with our
                // own bytes still queued. But we deliberately do not wait for
                // that write to *complete*: if the peer is blocked writing to
                // us, it will not drain until we read, and waiting here would
                // deadlock both sides. Submitting and moving on lets the stored
                // write make progress while inbound is driven.
                self.submit_outbound().await?;
                self.pump_inbound().await
            }
        }
    }

    /// Drain ciphertext out of the engine into the backlog.
    fn collect_outbound(&mut self) {
        while self.engine.outbound_pending() > 0 {
            let mut buf = vec![0u8; CIPHER_CHUNK];
            let n = self.engine.take_outbound(&mut buf);
            if n == 0 {
                break;
            }
            buf.truncate(n);
            self.outbound.append(&mut buf);
        }
    }

    /// Begin writing the backlog if nothing is already in flight.
    fn start_write_op(&mut self) -> Result<(), Error> {
        if self.write_op.is_some() || self.outbound.is_empty() {
            return Ok(());
        }
        let buf = std::mem::take(&mut self.outbound);
        let half = self
            .write_half
            .take()
            .ok_or_else(|| Error::Transport(std::io::Error::other("write half in use")))?;
        self.write_op = Some(Box::pin(async move {
            let mut half = half;
            let res = half.write_all(buf).await;
            (half, res)
        }));
        Ok(())
    }

    /// Poll a stored write once, settling it only if it is already done.
    async fn advance_write_op(&mut self) -> Result<(), Error> {
        let Some(op) = self.write_op.as_mut() else {
            return Ok(());
        };
        let polled = std::future::poll_fn(|cx| Poll::Ready(op.as_mut().poll(cx))).await;
        if let Poll::Ready((half, BufResult(res, _))) = polled {
            self.write_op = None;
            self.write_half = Some(half);
            res.map_err(Error::Transport)?;
        }
        Ok(())
    }

    /// Wait for a stored write to finish.
    async fn settle_write_op(&mut self) -> Result<(), Error> {
        let Some(op) = self.write_op.as_mut() else {
            return Ok(());
        };
        let (half, BufResult(res, _)) = std::future::poll_fn(|cx| op.as_mut().poll(cx)).await;
        self.write_op = None;
        self.write_half = Some(half);
        res.map_err(Error::Transport)
    }

    /// Hand ciphertext to the transport without waiting for delivery.
    async fn submit_outbound(&mut self) -> Result<(), Error> {
        self.advance_write_op().await?;
        self.collect_outbound();
        self.start_write_op()?;
        self.advance_write_op().await
    }

    /// Wait until every byte of ciphertext produced so far has been delivered.
    async fn flush_outbound(&mut self) -> Result<(), Error> {
        loop {
            // Finish whatever is in flight first, so a retained operation from
            // an abandoned future is never overtaken or discarded.
            self.settle_write_op().await?;
            self.collect_outbound();
            if self.outbound.is_empty() {
                return Ok(());
            }
            self.start_write_op()?;
        }
    }

    /// Obtain more ciphertext and offer it to OpenSSL.
    async fn pump_inbound(&mut self) -> Result<(), Error> {
        // Anything the pair could not take last time comes first.
        if !self.inbound.is_empty() {
            let accepted = self.engine.put_inbound(&self.inbound);
            if accepted > 0 {
                self.inbound.drain(..accepted);
                return Ok(());
            }
        }

        let data = self.transport_read().await?;
        if data.is_empty() {
            self.engine.note_transport_eof();
            return Ok(());
        }

        let accepted = self.engine.put_inbound(&data);
        if accepted < data.len() {
            self.inbound.extend_from_slice(&data[accepted..]);
        }
        Ok(())
    }

    /// Drive the stored transport read to completion, creating it if needed.
    async fn transport_read(&mut self) -> Result<Vec<u8>, Error> {
        if self.read_op.is_none() {
            let half = self
                .read_half
                .take()
                .ok_or_else(|| Error::Transport(std::io::Error::other("read half in use")))?;
            let buf = Vec::with_capacity(CIPHER_CHUNK);
            self.read_op = Some(Box::pin(async move {
                let mut half = half;
                let res = half.read(buf).await;
                (half, res)
            }));
        }

        let op = self.read_op.as_mut().expect("just populated");
        let (half, BufResult(res, buf)) = std::future::poll_fn(|cx| op.as_mut().poll(cx)).await;

        self.read_op = None;
        self.read_half = Some(half);

        let n = res.map_err(Error::Transport)?;
        let mut buf = buf;
        buf.truncate(n);
        Ok(buf)
    }

    // --- application data ---------------------------------------------------

    /// Complete any staged write left behind by an abandoned future.
    ///
    /// OpenSSL has already seen the staged bytes and requires the retry to
    /// present them identically, so they cannot be discarded. Their byte count
    /// is lost with the abandoned future, which is what makes a cancelled write
    /// indeterminate.
    async fn finish_staged_write(&mut self) -> Result<(), Error> {
        while !self.stage.is_empty() {
            let progress = {
                let staged = std::mem::take(&mut self.stage);
                let p = self.engine.write_plaintext(&staged);
                self.stage = staged;
                p?
            };
            match progress {
                Progress::Done(_) => {
                    self.stage.clear();
                    self.flush_outbound().await?;
                }
                other => self.serve(other).await?,
            }
        }
        Ok(())
    }

    async fn write_plaintext(&mut self, data: &[u8]) -> Result<usize, Error> {
        if data.is_empty() {
            return Ok(0);
        }
        // Rule: a staged write outstanding from an abandoned future must be
        // resumed before new plaintext is accepted, or records would be emitted
        // out of order.
        self.finish_staged_write().await?;

        // One record is all `SSL_write_ex` will take, so staging more is only
        // wasted copying.
        let take = data.len().min(MAX_RECORD);
        self.stage.clear();
        self.stage.extend_from_slice(&data[..take]);

        loop {
            let progress = {
                let staged = std::mem::take(&mut self.stage);
                let p = self.engine.write_plaintext(&staged);
                self.stage = staged;
                p?
            };
            match progress {
                Progress::Done(n) => {
                    self.stage.clear();
                    // Only report bytes whose ciphertext has actually reached
                    // the transport.
                    self.flush_outbound().await?;
                    return Ok(n);
                }
                other => self.serve(other).await?,
            }
        }
    }

    async fn read_plaintext_into(&mut self, out: &mut [MaybeUninit<u8>]) -> Result<usize, Error> {
        if out.is_empty() {
            return Ok(0);
        }
        loop {
            let progress = self.engine.read_plaintext_uninit(out)?;
            match progress {
                Progress::Done(n) => {
                    if n > 0 || self.engine.is_peer_closed() {
                        return Ok(n);
                    }
                    // Zero without a peer close means the record was
                    // incomplete; keep pumping.
                    self.serve(Progress::NeedsInbound).await?;
                }
                other => self.serve(other).await?,
            }
        }
    }
}

impl<R, W> AsyncRead for SslStream<R, W>
where
    R: AsyncRead + 'static,
    W: AsyncWrite + 'static,
{
    async fn read<B: IoBufMut>(&mut self, mut buf: B) -> BufResult<usize, B> {
        let cap = buf.buf_capacity();
        if cap == 0 {
            return BufResult(Ok(0), buf);
        }

        // The caller's buffer is filled by OpenSSL during a synchronous call
        // and is never submitted to the transport.
        let res = {
            let uninit = buf.as_uninit();
            self.read_plaintext_into(uninit).await
        };

        match res {
            Ok(n) => {
                // SAFETY: `read_plaintext_into` initialized exactly `n` bytes
                // at the start of the uninitialized region.
                unsafe { buf.set_len(n) };
                BufResult(Ok(n), buf)
            }
            Err(e) => BufResult(Err(e.into()), buf),
        }
    }
}

impl<R, W> AsyncWrite for SslStream<R, W>
where
    R: AsyncRead + 'static,
    W: AsyncWrite + 'static,
{
    async fn write<B: IoBuf>(&mut self, buf: B) -> BufResult<usize, B> {
        let res = {
            let data = buf.as_init();
            if data.is_empty() {
                Ok(0)
            } else {
                self.write_plaintext(data).await
            }
        };
        match res {
            Ok(n) => BufResult(Ok(n), buf),
            Err(e) => BufResult(Err(e.into()), buf),
        }
    }

    async fn flush(&mut self) -> std::io::Result<()> {
        self.finish_staged_write()
            .await
            .map_err(std::io::Error::from)?;
        self.flush_outbound().await.map_err(std::io::Error::from)?;
        if let Some(half) = self.write_half.as_mut() {
            half.flush().await?;
        }
        Ok(())
    }

    /// Shuts the TLS session down, not merely the transport.
    ///
    /// Generic helpers reach for this entry point, so it must not be a way to
    /// bypass `close_notify` and leave the peer seeing a truncated stream.
    async fn shutdown(&mut self) -> std::io::Result<()> {
        self.close().await.map_err(std::io::Error::from)
    }
}
