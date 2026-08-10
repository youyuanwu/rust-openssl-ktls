# Compio OpenSSL Stream

`openssl-io` is an experimental crate providing an async TLS stream over OpenSSL for the
[compio](https://docs.rs/compio) runtime. It is not published, its API is unstable, and it targets
Linux only. Kernel TLS offload is deliberately out of scope — that is what `openssl-ktls` is for.

## Why a separate crate

The readiness-based async model hands a library a borrowed buffer and asks the operating system
whether a connection is ready before transferring. That matches `epoll`, but not completion-based
interfaces such as `io_uring`, where the caller submits a buffer the kernel takes ownership of and
returns only once the transfer has finished.

`openssl-ktls`'s Tokio stream is built the readiness way: it owns an `AsyncFd` and attaches a socket
BIO to the raw file descriptor. That approach cannot be retrofitted to compio, because the entire
buffer-ownership contract differs. Hence a separate crate rather than a feature flag.

## Architecture

Three layers, deliberately separated:

```
   caller ──► SslStream<R, W>          public API, compio_io::AsyncRead/AsyncWrite
                   │
                   ├── pump            async; moves ciphertext, owns in-flight transport ops
                   │
                   └── TlsEngine       synchronous; SSL + one half of a BIO pair, no I/O at all
                            │
                       BIO pair ──────► transport (R, W)
```

The engine performs no I/O whatsoever. It consumes ciphertext, produces ciphertext, and reports what
it needs next. Everything about the OpenSSL state machine — handshakes, record boundaries, closure,
error classification — is therefore testable by driving two engines against each other entirely in
memory, with no sockets, no runtime, and no timing. That is where most of this crate's tests live,
and it is why the async layer above stayed small.

### Why a BIO pair, not a memory BIO or a custom BIO_METHOD

A custom `BIO_METHOD` is the obvious idea and it does not work. OpenSSL calls BIO callbacks
synchronously and expects bytes or a retry signal immediately; a callback cannot `await` a compio
operation. You would still need the same pump, plus C-to-Rust callbacks, boxed callback state, panic
bridging, and method lifetime management. It buys nothing and costs a great deal of unsafe code.

That leaves memory BIOs or a BIO pair. Both use the same fill/drain pump. The difference is
backpressure, and it is not theoretical — measured against OpenSSL 3.5.5:

| | `BIO_new_bio_pair` (4 KiB buffers) | `BIO_s_mem()` |
|---|---|---|
| 10,000-byte write | accepts 4096 | — |
| next write while full | `-1`, `BIO_FLAGS_SHOULD_RETRY` set | — |
| 10,000,000-byte write | — | accepts all 10 MB |

With a memory write BIO, a large `SSL_write` serializes its entire ciphertext into process memory
before any of it reaches the transport, so peak memory scales with the caller's payload. With a pair,
OpenSSL reports `WANT_WRITE` once the buffer fills, forcing the pump to drain. Peak memory is bounded
by the configured buffer size instead.

`openssl-sys` 0.9 does not declare `BIO_new_bio_pair`, so `src/ffi.rs` declares it directly along with
`BIO_test_flags` and the two `BIO_ctrl` command constants. One ABI trap worth knowing: the buffer size
arguments are `size_t`, not `int`. Declaring them as `c_int` misaligns the argument list on 64-bit
targets.

BIO ownership is asymmetric and easy to get wrong. `SSL_set_bio` takes ownership of the half it is
given, and `SSL_free` releases it. The pair's two halves are **independent** — freeing one does not
free the other — so the application-side half must be freed separately, exactly once. `BioPair::drop`
does that, and `take_ssl_side` nulls the pointer that OpenSSL now owns so it is never double-freed.

## The invariant that makes cancellation safe

**Caller buffers are never submitted to the transport.**

OpenSSL borrows a caller's buffer only during a synchronous `SSL_read_ex` or `SSL_write_ex` call.
Everything that crosses the compio boundary is a crate-owned ciphertext buffer. This is structural,
built in from the first line of the Phase 0 spike, and it is what makes an abandoned operation safe:
the kernel never holds memory the caller might reclaim.

Reads go one step further and fill the caller's *uninitialized* spare capacity directly via
`read_plaintext_uninit`, so there is no intermediate plaintext copy either.

## In-flight operations live in the stream, not in the future

compio's cancellation is best-effort: dropping a submitted operation requests cancellation, but the
operation may still run, and the buffer is forfeited rather than returned. If a public future owned
an in-flight transport read and were dropped, bytes could be consumed from the socket with no way to
learn how many — silently misaligning the record stream.

So `SslStream` stores at most one in-flight operation per direction as ordinary struct state. Each
stored future *owns* the transport half it is using and hands it back on completion, which sidesteps
any self-referential borrow. A public operation polls the stored future; if the public future is
dropped, the stored one stays put and the next operation resumes polling it.

Consequences worth knowing:

- Abandoning a read is safe and the session stays usable. This is the timeout case, and it works.
- Abandoning a **write** is *indeterminate*: its bytes may or may not have been committed, and the
  count is lost with the future. The session stays correct and the staged plaintext is completed by
  the following write, but a caller cannot learn how much got through.
- `into_inner` refuses while an operation is in flight, returning the stream intact. Handing back a
  half the runtime may still be writing into would be unsound.
- `Drop` simply drops the stored futures, requesting cancellation without awaiting. It never blocks.

## Writes are staged, because OpenSSL demands identical retries

`SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER` permits a retried `SSL_write_ex` to use a *moved pointer*, but
the contents and length must be identical. `SSL_MODE_ENABLE_PARTIAL_WRITE` only changes behavior
after a successful partial write. Neither makes a borrowed caller slice safe to retry from across an
await.

So the write path copies plaintext into a stable core-owned staging buffer, and every call and retry
reads from it. Staging is capped at one record: `SSL_write_ex` accepts at most 16384 bytes
(`SSL3_RT_MAX_PLAIN_LENGTH`) per call — measured, not assumed — so staging more is wasted copying.

A staged write left behind by an abandoned future is **resumed**, never discarded, before new
plaintext is accepted. OpenSSL has already seen those bytes and is owed an identical retry.
Critically, a **read must not resume or clear a staged write**: if it did, it would clear staging on
the writer's behalf, and the writer would then wake, observe an idle state, and re-stage the same
payload — transmitting it twice.

Note `SslConnector` and `SslAcceptor` already enable all three relevant modes. The engine sets
`ENABLE_PARTIAL_WRITE` explicitly anyway, because a caller may pass an `Ssl` built from a bare
`SslContext`, and write correctness must not depend on how they constructed it.

## Ordering: submit outbound, but do not wait for it

OpenSSL reports `WANT_READ` while records it has already produced are still queued. Waiting for the
peer without sending those first deadlocks a handshake. `Progress` makes that unrepresentable:
`NeedsFlush` outranks `NeedsInbound`, so a caller cannot get the order wrong by accident.

But the converse is also a trap. Awaiting outbound *delivery* before reading deadlocks against a peer
that is itself blocked writing to us: it will not drain until we read, and we will not read until it
drains. So `NeedsInbound` submits outbound and polls it once, then drives inbound while the stored
write continues in the background.

## Buffer inventory

Per connection, at M1:

| Buffer | Size |
|---|---|
| BIO pair, SSL side | 64 KiB (4 × max record) |
| BIO pair, application side | 64 KiB |
| Write staging | ≤ 16 KiB (one record) |
| Outbound ciphertext backlog | grows to whatever one drain produces |
| Inbound ciphertext remainder | ≤ 16 KiB chunk, only what the pair could not accept |

The pair buffer size is the one tunable that cannot be avoided: it sets peak per-connection memory
and how often the pump round-trips.

## Scope

Delivered (M1):

- Client and server handshakes over any transport supplied as a read/write half pair.
- `compio_io::AsyncRead`/`AsyncWrite`, plus `flush`, `close`, `into_inner`, and scoped session access.
- Five-way error classification: TLS, certificate verification, transport, unexpected EOF, closed.
- Write commitment: a reported count means that ciphertext reached the transport.
- Cancellation safety.

Not yet built (M2):

- **Concurrent split halves.** Today the stream is `&mut self`, so one operation at a time. True
  full-duplex needs read and write halves sharing a core, which is where the multi-waiter waker
  machinery becomes necessary. Note an `Arc<WakeState>` is required rather than `Rc`, because `Waker`
  is `Send + Sync`.
- **Interoperability testing against an independent implementation.** rustls is the right peer;
  `tokio-openssl` and `openssl s_client` do not count, being wrappers around the same OpenSSL.
- **Renegotiation and post-handshake key update.** Neither `SSL_renegotiate` nor `SSL_key_update` is
  exposed by `openssl-sys` 0.9 or `openssl` 0.10, so this needs further hand-written FFI.
- **Detector-instrumented runs.** No single tool covers this: Miri cannot do FFI or networking, Rust's
  sanitizers need nightly, and Valgrind does not fully model io_uring. A polling-driver run under
  ASan is the closest available approximation, and it still would not validate kernel-side access
  after submission.

## MSRV

The workspace minimum is 1.95.0, raised from 1.90.0 for this crate. The requirement comes from
`compio-executor`'s use of `cfg_select!`, reached through the `compio` umbrella **dev-dependency**;
`openssl-io`'s own library dependencies (`compio-io`, `compio-buf`) build on 1.93. Should the raise
become inconvenient for `openssl-ktls` consumers, excluding `openssl-io` from the MSRV CI leg would
restore the old floor without affecting this crate.

## Test map

| Area | Where |
|---|---|
| OpenSSL state machine, in memory | `src/engine.rs` unit tests |
| BIO pair bindings and bounds | `src/ffi.rs` unit tests |
| Error classification | `src/error.rs` unit tests |
| In-memory transport and its fault hooks | `tests/transport.rs` |
| End-to-end TLS, deterministic | `tests/in_memory.rs` |
| End-to-end TLS over a real socket | `tests/tcp.rs` |

The in-memory transport exists because flush ordering, partial writes, stalled writes, fragmented
records, and truncation are timing-dependent over loopback TCP but deterministic in memory. TCP is a
confirmation pass, not the primary suite — and it doubles as evidence the stream is genuinely
transport-agnostic rather than quietly assuming a socket.
