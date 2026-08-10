//! The synchronous TLS state machine.
//!
//! This module contains no I/O and no async code. It owns the `SSL` object and
//! one half of a BIO pair, and it communicates purely through byte slices:
//! ciphertext is fed in, ciphertext is drained out, and every operation reports
//! what it needs next via [`Progress`].
//!
//! Keeping the state machine synchronous is deliberate. It is the hardest part
//! of the crate to get right, and this way it can be tested by driving two
//! engines against each other entirely in memory — no sockets, no runtime, no
//! timing.

use std::ffi::{c_int, c_void};

use foreign_types_shared::ForeignType;
use openssl::ssl::{Ssl, SslMode};

use crate::error::Error;
use crate::ffi::BioPair;

/// Buffering in each direction of the BIO pair.
///
/// A small multiple of the 16 KiB maximum TLS record. Large enough that a
/// typical record round-trips without repeated pumping, small enough that a
/// stalled peer cannot make us buffer without bound — which is precisely why
/// this crate uses a BIO pair rather than a memory BIO.
const PAIR_BUF: usize = 4 * MAX_RECORD;

/// `SSL3_RT_MAX_PLAIN_LENGTH`: the most plaintext OpenSSL will accept in one
/// `SSL_write_ex` call. Measured, not assumed — see `docs/CompioStream.md`.
pub(crate) const MAX_RECORD: usize = 16384;

/// Size of the crate-owned ciphertext buffers moved to and from the transport.
///
/// It lives here, beside [`MAX_RECORD`], rather than in a runtime adapter,
/// because every adapter stages ciphertext and none should have to depend on
/// another runtime's feature-gated module to learn how much to stage.
pub(crate) const CIPHER_CHUNK: usize = 16 * 1024;

/// Which side of the handshake to drive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Role {
    Client,
    Server,
}

/// What the state machine needs before it can make further progress.
///
/// The ordering matters: [`Progress::NeedsFlush`] always takes precedence over
/// [`Progress::NeedsInbound`]. OpenSSL legitimately reports "want read" while
/// records it has already produced are still queued, and waiting for the peer
/// without first sending those records deadlocks the connection. Making flush a
/// distinct, higher-priority state means a caller cannot get that ordering
/// wrong by accident.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Progress {
    /// The operation finished, transferring this many bytes of plaintext.
    Done(usize),
    /// Ciphertext is waiting to be sent. Drain it before doing anything else.
    NeedsFlush,
    /// More ciphertext from the peer is required.
    NeedsInbound,
}

/// Lifecycle of the session, tracked explicitly because several requirements
/// depend on operations behaving deterministically *after* a close or failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// Handshake not yet complete.
    Handshaking,
    /// Established and carrying application data.
    Open,
    /// The peer sent `close_notify`; reads report end-of-stream from here on.
    PeerClosed,
    /// We sent `close_notify`; writes are rejected from here on.
    LocalClosed,
    /// Both directions closed.
    Closed,
    /// Permanently failed. Every subsequent operation reports the same thing.
    Failed,
}

pub(crate) struct TlsEngine {
    ssl: Ssl,
    bio: BioPair,
    state: State,
    /// Set once the transport reports end-of-file, so the engine can tell a
    /// clean shutdown from a truncated one.
    transport_eof: bool,
    /// True when `SSL_write_ex` returned `WANT_*`. OpenSSL has already seen the
    /// buffer and requires the retry to present byte-identical contents, so the
    /// caller must not substitute a different payload.
    retry_owed: bool,
    /// Length of the buffer the pending retry is owed for, used to catch a
    /// caller violating the identical-argument rule.
    retry_len: usize,
}

impl TlsEngine {
    pub(crate) fn new(ssl: Ssl) -> Result<Self, Error> {
        let mut bio = BioPair::new(PAIR_BUF).ok_or_else(Error::tls)?;

        // Partial writes are enabled explicitly rather than relying on the
        // caller's context. `SslConnector`/`SslAcceptor` set this mode already,
        // but an `Ssl` built from a bare `SslContext` does not, and the write
        // path's correctness must not depend on how the caller built it.
        // SAFETY: `ssl` is a live SSL object for the lifetime of this call.
        unsafe {
            // `SSL_set_mode` is a macro in C, so go through SSL_ctrl directly.
            openssl_sys::SSL_ctrl(
                ssl.as_ptr(),
                openssl_sys::SSL_CTRL_MODE,
                SslMode::ENABLE_PARTIAL_WRITE.bits() as _,
                std::ptr::null_mut(),
            );
            // SSL takes ownership of its half for both read and write.
            openssl_sys::SSL_set_bio(ssl.as_ptr(), bio.ssl_side(), bio.ssl_side());
        }
        bio.take_ssl_side();

        Ok(Self {
            ssl,
            bio,
            state: State::Handshaking,
            transport_eof: false,
            retry_owed: false,
            retry_len: 0,
        })
    }

    pub(crate) fn ssl(&self) -> &Ssl {
        &self.ssl
    }

    /// Ciphertext waiting to go to the peer.
    pub(crate) fn outbound_pending(&self) -> usize {
        self.bio.pending()
    }

    /// Drain ciphertext into `out`, returning how many bytes were appended.
    pub(crate) fn take_outbound(&mut self, out: &mut [u8]) -> usize {
        self.bio.read(out)
    }

    /// Offer peer ciphertext to OpenSSL.
    ///
    /// Returns how many bytes were accepted, which may be fewer than offered
    /// because the pair is bounded. The caller must retain the remainder and
    /// offer it again rather than dropping it.
    pub(crate) fn put_inbound(&mut self, data: &[u8]) -> usize {
        self.bio.write(data)
    }

    /// Record that the transport will produce no more bytes.
    pub(crate) fn note_transport_eof(&mut self) {
        self.transport_eof = true;
    }

    pub(crate) fn is_peer_closed(&self) -> bool {
        matches!(self.state, State::PeerClosed | State::Closed)
    }

    pub(crate) fn is_locally_closed(&self) -> bool {
        matches!(self.state, State::LocalClosed | State::Closed)
    }

    pub(crate) fn is_handshaking(&self) -> bool {
        self.state == State::Handshaking
    }

    /// True when a byte-identical `SSL_write_ex` retry is outstanding.
    #[cfg(test)]
    pub(crate) fn retry_owed(&self) -> bool {
        self.retry_owed
    }

    /// Drive one handshake step.
    pub(crate) fn step_handshake(&mut self, role: Role) -> Result<Progress, Error> {
        if self.state == State::Failed {
            return Err(Error::tls());
        }
        // SAFETY: `ssl` is live; both calls are the documented entry points.
        let ret = unsafe {
            match role {
                Role::Client => openssl_sys::SSL_connect(self.ssl.as_ptr()),
                Role::Server => openssl_sys::SSL_accept(self.ssl.as_ptr()),
            }
        };

        if ret > 0 {
            self.state = State::Open;
            return Ok(Progress::Done(0));
        }
        self.classify(ret, true)
    }

    /// Read decrypted plaintext into `out`.
    #[cfg(test)]
    pub(crate) fn read_plaintext(&mut self, out: &mut [u8]) -> Result<Progress, Error> {
        // SAFETY: `&mut [u8]` is a valid `&mut [MaybeUninit<u8>]` — every
        // initialized byte is trivially a valid maybe-initialized byte, and the
        // callee only ever writes.
        let uninit = unsafe {
            std::slice::from_raw_parts_mut(
                out.as_mut_ptr() as *mut std::mem::MaybeUninit<u8>,
                out.len(),
            )
        };
        self.read_plaintext_uninit(uninit)
    }

    /// Read decrypted plaintext directly into uninitialized memory.
    ///
    /// This is what lets a caller's buffer be filled without an intermediate
    /// copy: OpenSSL writes into the buffer's spare capacity during this
    /// synchronous call, and the caller records how much was initialized.
    pub(crate) fn read_plaintext_uninit(
        &mut self,
        out: &mut [std::mem::MaybeUninit<u8>],
    ) -> Result<Progress, Error> {
        if out.is_empty() {
            return Ok(Progress::Done(0));
        }
        // A peer that closed cleanly yields end-of-stream forever, never an
        // error, and never a spurious read attempt.
        if self.is_peer_closed() {
            return Ok(Progress::Done(0));
        }
        if self.state == State::Failed {
            return Err(Error::tls());
        }

        let mut got = 0usize;
        // SAFETY: `out` is valid for `out.len()` bytes; `got` is a live local.
        let ret = unsafe {
            openssl_sys::SSL_read_ex(
                self.ssl.as_ptr(),
                out.as_mut_ptr() as *mut c_void,
                out.len(),
                &mut got,
            )
        };

        if ret > 0 {
            return Ok(Progress::Done(got));
        }
        self.classify(ret, false)
    }

    /// Offer plaintext to OpenSSL.
    ///
    /// `data` must be byte-identical across retries while [`Self::retry_owed`]
    /// is true; OpenSSL has already seen the buffer and re-presenting different
    /// contents is undefined. The caller owns the stable staging buffer.
    pub(crate) fn write_plaintext(&mut self, data: &[u8]) -> Result<Progress, Error> {
        if data.is_empty() {
            return Ok(Progress::Done(0));
        }
        if self.is_locally_closed() {
            return Err(Error::Closed);
        }
        if self.state == State::Failed {
            return Err(Error::tls());
        }
        debug_assert!(
            !self.retry_owed || self.retry_len == data.len(),
            "SSL_write_ex retry must present the identical buffer it was first given \
             (owed {} bytes, got {})",
            self.retry_len,
            data.len()
        );

        let mut put = 0usize;
        // SAFETY: `data` is valid for `data.len()` bytes; `put` is a live local.
        let ret = unsafe {
            openssl_sys::SSL_write_ex(
                self.ssl.as_ptr(),
                data.as_ptr() as *const c_void,
                data.len(),
                &mut put,
            )
        };

        if ret > 0 {
            self.retry_owed = false;
            self.retry_len = 0;
            return Ok(Progress::Done(put));
        }

        let progress = self.classify(ret, false)?;
        // OpenSSL saw this buffer and wants the same one back.
        self.retry_owed = true;
        self.retry_len = data.len();
        Ok(progress)
    }

    /// Send `close_notify`.
    ///
    /// `SSL_shutdown` is two-phase: 0 means our notification is sent but the
    /// peer's has not arrived. Callers must not wait for the peer, so 0 counts
    /// as success here.
    pub(crate) fn shutdown(&mut self) -> Result<Progress, Error> {
        if self.is_locally_closed() {
            // Idempotent: closing twice is not an error and must not emit a
            // second close_notify.
            return Ok(Progress::Done(0));
        }
        if self.state == State::Failed {
            return Err(Error::tls());
        }

        // SAFETY: `ssl` is live.
        let ret = unsafe { openssl_sys::SSL_shutdown(self.ssl.as_ptr()) };

        if ret >= 0 {
            self.state = if self.is_peer_closed() {
                State::Closed
            } else {
                State::LocalClosed
            };
            return Ok(Progress::Done(0));
        }
        self.classify(ret, false)
    }

    /// Translate an unsuccessful OpenSSL return into [`Progress`] or an error.
    ///
    /// Truncation is decided from the engine's own view of the transport, not
    /// from a particular `SSL_ERROR_*` code: OpenSSL 3.x commonly surfaces a
    /// truncated stream as `SSL_ERROR_SSL` rather than `SSL_ERROR_SYSCALL`, so
    /// keying off the code alone misclassifies it.
    fn classify(&mut self, ret: c_int, handshake: bool) -> Result<Progress, Error> {
        // SAFETY: `ssl` is live and `ret` is its most recent return value.
        let err = unsafe { openssl_sys::SSL_get_error(self.ssl.as_ptr(), ret) };

        match err {
            openssl_sys::SSL_ERROR_WANT_WRITE => Ok(Progress::NeedsFlush),

            openssl_sys::SSL_ERROR_WANT_READ => {
                // Outbound always outranks inbound.
                if self.outbound_pending() > 0 {
                    return Ok(Progress::NeedsFlush);
                }
                if self.transport_eof {
                    self.state = State::Failed;
                    return Err(Error::UnexpectedEof);
                }
                Ok(Progress::NeedsInbound)
            }

            openssl_sys::SSL_ERROR_ZERO_RETURN => {
                // The peer sent close_notify: an orderly end of stream.
                self.state = if self.is_locally_closed() {
                    State::Closed
                } else {
                    State::PeerClosed
                };
                Ok(Progress::Done(0))
            }

            _ => {
                self.state = State::Failed;

                if self.transport_eof {
                    return Err(Error::UnexpectedEof);
                }

                if handshake {
                    // SAFETY: `ssl` is live.
                    let verify = unsafe { openssl_sys::SSL_get_verify_result(self.ssl.as_ptr()) };
                    if verify != openssl_sys::X509_V_OK as i64 {
                        return Err(Error::verification(verify as i32));
                    }
                }
                Err(Error::tls())
            }
        }
    }
}

#[cfg(test)]
#[path = "../tests/common/certs.rs"]
mod common;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::common;

    /// Drives two engines against each other with no I/O whatsoever: whatever
    /// one produces becomes the other's input. If the state machine is correct,
    /// a full TLS session completes here.
    ///
    /// The queues are not incidental. `put_inbound` accepts only what the
    /// bounded pair has room for, so anything not accepted must be held and
    /// re-offered. Dropping it corrupts the record stream — which is precisely
    /// what a caller of this engine must not do either.
    struct Pair {
        client: TlsEngine,
        server: TlsEngine,
        /// Ciphertext in flight from client to server.
        c2s: Vec<u8>,
        /// Ciphertext in flight from server to client.
        s2c: Vec<u8>,
    }

    impl Pair {
        fn new() -> Self {
            let (c, s) = common::engine_ssl_pair();
            Pair {
                client: TlsEngine::new(c).unwrap(),
                server: TlsEngine::new(s).unwrap(),
                c2s: Vec::new(),
                s2c: Vec::new(),
            }
        }

        /// Drain `from`'s outbound ciphertext into `queue`, then feed at most
        /// `max_feed` bytes of `queue` to `to`, retaining any remainder.
        ///
        /// `max_feed` exists so tests can deliver a record a few bytes at a
        /// time, which is what a real transport does and which the engine must
        /// tolerate without reporting a premature end of stream.
        fn pump_limited(
            from: &mut TlsEngine,
            to: &mut TlsEngine,
            queue: &mut Vec<u8>,
            max_feed: usize,
        ) {
            let mut buf = vec![0u8; 8192];
            while from.outbound_pending() > 0 {
                let n = from.take_outbound(&mut buf);
                if n == 0 {
                    break;
                }
                queue.extend_from_slice(&buf[..n]);
            }

            let limit = queue.len().min(max_feed);
            let mut off = 0;
            while off < limit {
                let accepted = to.put_inbound(&queue[off..limit]);
                if accepted == 0 {
                    break; // receiver is full; keep the rest for next round
                }
                off += accepted;
            }
            queue.drain(..off);
        }

        /// Drain `from`'s outbound ciphertext into `queue`, then feed as much of
        /// `queue` as `to` will accept, retaining any remainder.
        fn pump(from: &mut TlsEngine, to: &mut TlsEngine, queue: &mut Vec<u8>) {
            Self::pump_limited(from, to, queue, usize::MAX);
        }

        fn client_to_server_bytes(&mut self) {
            Self::pump(&mut self.client, &mut self.server, &mut self.c2s);
        }

        fn server_to_client_bytes(&mut self) {
            Self::pump(&mut self.server, &mut self.client, &mut self.s2c);
        }

        fn handshake(&mut self) {
            for _ in 0..64 {
                let c = self.client.step_handshake(Role::Client).unwrap();
                self.client_to_server_bytes();
                let s = self.server.step_handshake(Role::Server).unwrap();
                self.server_to_client_bytes();

                if c == Progress::Done(0) && s == Progress::Done(0) {
                    return;
                }
            }
            panic!("handshake did not converge");
        }

        /// Write all of `data` from client to server and return what arrived.
        fn client_to_server(&mut self, data: &[u8]) -> Vec<u8> {
            self.transfer(data, Direction::ClientToServer, usize::MAX)
        }

        /// Write all of `data` from server to client and return what arrived.
        fn server_to_client(&mut self, data: &[u8]) -> Vec<u8> {
            self.transfer(data, Direction::ServerToClient, usize::MAX)
        }

        /// Move `data` in `dir`, delivering at most `max_feed` ciphertext bytes
        /// per round so tests can simulate fragmented delivery.
        fn transfer(&mut self, data: &[u8], dir: Direction, max_feed: usize) -> Vec<u8> {
            let mut sent = 0;
            let mut received = Vec::new();
            let mut rbuf = vec![0u8; 8192];

            let mut guard = 0;
            while sent < data.len() || received.len() < data.len() {
                guard += 1;
                assert!(guard < 1_000_000, "transfer failed to converge");

                let (writer, reader) = match dir {
                    Direction::ClientToServer => (&mut self.client, &mut self.server),
                    Direction::ServerToClient => (&mut self.server, &mut self.client),
                };

                if sent < data.len() {
                    match writer.write_plaintext(&data[sent..]).unwrap() {
                        Progress::Done(n) => sent += n,
                        Progress::NeedsFlush | Progress::NeedsInbound => {}
                    }
                }
                if let Progress::Done(n) = reader.read_plaintext(&mut rbuf).unwrap()
                    && n > 0
                {
                    received.extend_from_slice(&rbuf[..n]);
                }

                match dir {
                    Direction::ClientToServer => {
                        Self::pump_limited(
                            &mut self.client,
                            &mut self.server,
                            &mut self.c2s,
                            max_feed,
                        );
                        Self::pump(&mut self.server, &mut self.client, &mut self.s2c);
                    }
                    Direction::ServerToClient => {
                        Self::pump_limited(
                            &mut self.server,
                            &mut self.client,
                            &mut self.s2c,
                            max_feed,
                        );
                        Self::pump(&mut self.client, &mut self.server, &mut self.c2s);
                    }
                }
            }
            received
        }
    }

    #[derive(Clone, Copy)]
    enum Direction {
        ClientToServer,
        ServerToClient,
    }

    #[test]
    fn handshake_completes_in_memory() {
        let mut p = Pair::new();
        p.handshake();
        assert!(!p.client.is_handshaking());
        assert!(!p.server.is_handshaking());
        assert_eq!(p.client.ssl().version_str(), p.server.ssl().version_str());
    }

    #[test]
    fn round_trips_a_small_payload() {
        let mut p = Pair::new();
        p.handshake();
        let msg = b"under one record";
        assert_eq!(p.client_to_server(msg), msg);
    }

    #[test]
    fn round_trips_a_payload_spanning_many_records() {
        let mut p = Pair::new();
        p.handshake();
        // Comfortably larger than both a TLS record and the pair buffer, so it
        // cannot complete without repeated draining.
        let msg: Vec<u8> = (0..250_000u32).map(|i| (i % 251) as u8).collect();
        assert_eq!(p.client_to_server(&msg), msg);
    }

    #[test]
    fn round_trips_server_to_client() {
        let mut p = Pair::new();
        p.handshake();
        let msg: Vec<u8> = (0..60_000u32).map(|i| (i % 97) as u8).collect();
        assert_eq!(p.server_to_client(&msg), msg);
    }

    /// A real transport delivers records in arbitrary fragments. The engine
    /// must accumulate until a whole record is available rather than reporting
    /// a premature end of stream.
    #[test]
    fn tolerates_ciphertext_delivered_in_tiny_fragments() {
        let mut p = Pair::new();
        p.handshake();

        let msg: Vec<u8> = (0..20_000u32).map(|i| (i % 233) as u8).collect();
        // 7 bytes per round is far smaller than any TLS record header+body.
        let got = p.transfer(&msg, Direction::ClientToServer, 7);
        assert_eq!(got, msg);
    }

    /// Corrupt ciphertext must surface as a TLS protocol error, distinct from
    /// a transport problem or a truncation.
    #[test]
    fn corrupt_ciphertext_is_a_tls_error() {
        let mut p = Pair::new();
        p.handshake();

        // Produce a genuine record, then flip bits in its body so the MAC fails.
        assert!(matches!(
            p.client.write_plaintext(b"payload").unwrap(),
            Progress::Done(_)
        ));
        let mut buf = vec![0u8; 8192];
        let n = p.client.take_outbound(&mut buf);
        assert!(n > 0, "expected a record on the wire");
        for b in buf[n / 2..n].iter_mut() {
            *b ^= 0xFF;
        }
        assert_eq!(p.server.put_inbound(&buf[..n]), n);

        let mut out = [0u8; 64];
        match p.server.read_plaintext(&mut out) {
            Err(Error::Tls(_)) => {}
            other => panic!("expected Tls, got {other:?}"),
        }
    }

    /// When the peer stops draining, `SSL_write_ex` cannot make progress and
    /// OpenSSL demands the retry present the identical buffer. This exercises
    /// that path end to end: stall, observe the retry obligation, drain, and
    /// then complete with the same bytes.
    #[test]
    fn stalled_write_owes_an_identical_retry_and_then_succeeds() {
        let mut p = Pair::new();
        p.handshake();

        // Never drain the client's outbound side, so the pair fills up.
        let data = vec![0x3Cu8; MAX_RECORD];
        let mut stalled = None;
        for _ in 0..64 {
            match p.client.write_plaintext(&data).unwrap() {
                Progress::Done(_) => continue,
                other => {
                    stalled = Some(other);
                    break;
                }
            }
        }
        let stalled = stalled.expect("writing without draining should eventually stall");
        assert_eq!(
            stalled,
            Progress::NeedsFlush,
            "a full pair must ask to flush, never to read"
        );
        assert!(
            p.client.retry_owed(),
            "OpenSSL saw the buffer, so an identical retry is owed"
        );

        // Drain to the peer, then retry with the very same bytes.
        p.client_to_server_bytes();
        let mut sink = vec![0u8; 8192];
        while let Progress::Done(n) = p.server.read_plaintext(&mut sink).unwrap() {
            if n == 0 {
                break;
            }
            p.client_to_server_bytes();
        }

        match p.client.write_plaintext(&data).unwrap() {
            Progress::Done(n) => assert!(n > 0, "retry should make progress"),
            other => panic!("expected progress after draining, got {other:?}"),
        }
        assert!(!p.client.retry_owed(), "retry obligation should be cleared");
    }

    /// A single `SSL_write_ex` never takes more than one record, so oversized
    /// writes must report partial progress rather than stalling.
    #[test]
    fn oversized_write_reports_partial_progress() {
        let mut p = Pair::new();
        p.handshake();

        let data = vec![0x7Eu8; MAX_RECORD * 3];
        let progress = p.client.write_plaintext(&data).unwrap();
        match progress {
            Progress::Done(n) => {
                assert!(n > 0 && n < data.len(), "expected a partial write, got {n}");
                assert_eq!(n, MAX_RECORD, "expected exactly one record");
            }
            other => panic!("expected Done, got {other:?}"),
        }
    }

    /// The invariant that keeps handshakes from deadlocking.
    #[test]
    fn never_requests_inbound_while_outbound_is_pending() {
        let (c, _s) = common::engine_ssl_pair();
        let mut client = TlsEngine::new(c).unwrap();

        // The first handshake step produces a ClientHello and then wants the
        // peer's reply. Because those bytes are still queued, the engine must
        // ask to flush rather than to read.
        let progress = client.step_handshake(Role::Client).unwrap();
        assert!(client.outbound_pending() > 0, "expected a ClientHello");
        assert_eq!(progress, Progress::NeedsFlush);
    }

    #[test]
    fn short_inbound_retains_the_remainder() {
        let (c, _s) = common::engine_ssl_pair();
        let mut e = TlsEngine::new(c).unwrap();

        // Offer far more than the bounded pair can hold.
        let data = vec![0u8; PAIR_BUF * 2];
        let accepted = e.put_inbound(&data);
        assert!(
            accepted > 0 && accepted < data.len(),
            "expected a short accept, got {accepted}"
        );
    }

    #[test]
    fn clean_peer_closure_reads_as_end_of_stream_repeatedly() {
        let mut p = Pair::new();
        p.handshake();

        p.client.shutdown().unwrap();
        p.client_to_server_bytes();

        let mut buf = [0u8; 64];
        // The first read observes close_notify; every later one must agree,
        // and none may report an error.
        for _ in 0..3 {
            assert_eq!(
                p.server.read_plaintext(&mut buf).unwrap(),
                Progress::Done(0)
            );
        }
        assert!(p.server.is_peer_closed());
    }

    #[test]
    fn write_after_local_close_is_rejected_as_closed() {
        let mut p = Pair::new();
        p.handshake();
        p.client.shutdown().unwrap();

        match p.client.write_plaintext(b"too late") {
            Err(Error::Closed) => {}
            other => panic!("expected Closed, got {other:?}"),
        }
    }

    #[test]
    fn double_close_succeeds_without_a_second_notification() {
        let mut p = Pair::new();
        p.handshake();

        assert_eq!(p.client.shutdown().unwrap(), Progress::Done(0));
        let after_first = p.client.outbound_pending();
        assert!(after_first > 0, "first close should emit close_notify");

        assert_eq!(p.client.shutdown().unwrap(), Progress::Done(0));
        assert_eq!(
            p.client.outbound_pending(),
            after_first,
            "second close must not emit anything further"
        );
    }

    #[test]
    fn truncation_is_unexpected_eof_not_clean_end_of_stream() {
        let mut p = Pair::new();
        p.handshake();

        // Peer vanishes without sending close_notify.
        p.server.note_transport_eof();
        let mut buf = [0u8; 64];
        match p.server.read_plaintext(&mut buf) {
            Err(Error::UnexpectedEof) => {}
            other => panic!("expected UnexpectedEof, got {other:?}"),
        }
    }

    #[test]
    fn untrusted_certificate_is_a_verification_failure() {
        let (c, s) = common::untrusted_ssl_pair();
        let mut client = TlsEngine::new(c).unwrap();
        let mut server = TlsEngine::new(s).unwrap();
        let (mut c2s, mut s2c) = (Vec::new(), Vec::new());

        let mut last = None;
        for _ in 0..64 {
            match client.step_handshake(Role::Client) {
                Ok(_) => {}
                Err(e) => {
                    last = Some(e);
                    break;
                }
            }
            Pair::pump(&mut client, &mut server, &mut c2s);
            let _ = server.step_handshake(Role::Server);
            Pair::pump(&mut server, &mut client, &mut s2c);
        }

        match last {
            Some(Error::Verification { .. }) => {}
            other => panic!("expected Verification, got {other:?}"),
        }
    }
}
