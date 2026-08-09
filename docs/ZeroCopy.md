# Zero copy and the OpenSSL write path

Notes on which copies exist on the TLS write path, which can be removed, and why the
remaining ones are structural rather than accidental. The measurements referenced here
come from [Benchmarks.md](Benchmarks.md).

## Copies in the write path

| Mode | Userspace copies per byte | Kernel copy |
|---|---|---|
| socket BIO | 1 (fused with encryption) | yes |
| socket BIO + `BufWriter` | 2 | yes |
| KTLS | **0** | yes |
| KTLS + `SSL_sendfile` zerocopy | **0** | **no** |

There are two distinct copies, and they have very different answers.

## Copy 1: plaintext into the record buffer

A TLS record is a 5-byte header, then ciphertext, then a 16-byte AEAD tag (plus a
content-type byte inside the encryption in TLS 1.3). The output is larger than the input
and offset from it, so encrypting in place inside the caller's buffer would overwrite
adjacent memory. OpenSSL therefore encrypts into its own `wbuf`.

This copy is close to free in practice — it is fused with the AES pass, which already pays
the memory bandwidth — but it cannot be removed while framing happens in userspace.

**KTLS removes it.** `ktls_allocate_write_buffers` (`ssl/record/methods/ktls_meth.c`)
allocates nothing at all:

> We just use the end application buffer in the case of KTLS, so nothing to do.

`ktls_initialise_write_packets` points the `TLS_BUFFER` at the caller's buffer and OpenSSL
hands that pointer to `sendmsg`; the kernel does framing and crypto. `SSL_sendfile()` with
`SSL_OP_ENABLE_KTLS_TX_ZEROCOPY_SENDFILE` goes further and never brings the data into
userspace at all.

## Copy 2: record buffer into the kernel

`MSG_ZEROCOPY` (or io_uring's `SEND_ZC`) can elide this in principle, but not with
OpenSSL's buffer lifetime. The kernel documentation states the contract:

> Page pinning also changes system call semantics. It temporarily shares the buffer between
> process and network stack. Unlike with copying, the process cannot immediately overwrite
> the buffer after system call return without possibly modifying the data in flight.

`tls_retry_write_records` recycles `wbuf` as soon as `BIO_write` returns, so the next record
would overwrite pages the NIC has not read yet — corrupted records on the wire. Completion
arrives asynchronously on `MSG_ERRQUEUE`, long after the call returns.

Copying each record into an owned pool and deferring reuse until the notification would fix
the lifetime, but reintroduces exactly the copy being eliminated. The kernel docs also note
`MSG_ZEROCOPY` "is generally only effective at writes over around 10 KB", and TLS records
are 16 KiB — right at the threshold.

`sendfile` and `splice` are not alternatives here: they need a file descriptor, and what we
have is ciphertext in memory. NIC hardware TLS offload is not an alternative either — that
*is* KTLS, with the device doing the crypto.

## Why OpenSSL cannot encrypt directly into a custom BIO

This is the interesting one, because it looks like it should be possible — it is what
rustls does. The obstruction is a missing interface, not a fundamental limitation, and it
is missing at two levels.

**The BIO ABI is push-only.** `BIO_METHOD` offers `bwrite(bio, buf, len)`: the BIO
*receives* bytes that have already been written somewhere else. There is no
`reserve(n) -> buffer` / `commit(m)` pair, which is what "encrypt straight into the BIO"
would require. So under the default record method the record layer must own the memory it
encrypts into, and a copy at the BIO boundary is forced. That vtable predates the idea by
about 25 years and is frozen for compatibility — every custom BIO in existence implements
only those slots.

**The record layer itself can encrypt into foreign memory.** KTLS proves it, as above: it
allocates no write buffers and points them at the caller's memory. So "encrypt into memory
OpenSSL does not own" is a shipping code path.

The catch is that this extension point, `OSSL_RECORD_METHOD`, lives in
`include/internal/recordmethod.h`. There is no `include/openssl/recordmethod.h`, nothing in
the installed headers, and no public setter — the header notes that which record method to
use "is defined by the `SSL_METHOD`". It exists for OpenSSL's own protocols (TLS, DTLS,
QUIC, KTLS), not for applications. An application cannot supply a record method that
encrypts into its own BIO's buffer.

Even with such an interface it would not be free:

- The encryption step needs contiguous space sized for header, explicit IV and tag, with
  offsets computed into it. A `reserve` API would have to hand back a worst-case region,
  because the committed length is not known until padding and the AEAD tag are applied.
- On a failed write the record layer must retain the buffer. When that buffer is foreign,
  OpenSSL has to copy it out — the `TLS_BUFFER_is_app_buffer` and
  `SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER` branch in `tls_retry_write_records`. Foreign
  buffers reintroduce a copy on the retry path.

## Contrast with rustls

rustls is sans-I/O: the state machine never touches a socket. It encrypts each record into
an owned heap chunk pushed onto a `VecDeque<Vec<u8>>`, and those chunks stay alive until the
caller drains them — so an arbitrary number accumulate and `write_tls` can build `IoSlice`s
over them for a single `write_vectored`.

The crisp difference: **rustls encrypts into the buffer it will later gather from; OpenSSL
encrypts into a buffer it must immediately recycle.** That is why retrofitting a queuing or
vectored BIO onto OpenSSL costs a copy that rustls gets for free.

## Does any of this matter?

For the workload measured in [Benchmarks.md](Benchmarks.md), no. KTLS achieves zero
userspace copies and was still indistinguishable from the plain socket BIO at most payload
sizes, and slower at 8 MiB. The bottleneck was context switches and packet count, not
copies — roughly one context switch per 16 KiB record. Buffering, which *adds* a copy,
was worth 2.4x because it removed 64x the syscalls.

Eliminating a 16 KiB copy that AES already warmed in cache buys very little. Eliminating
several hundred wakeups buys a lot.
