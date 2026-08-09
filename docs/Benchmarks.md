# Write-path benchmarks

`openssl-ktls-tests/benches/write_throughput.rs` measures the cost of OpenSSL's write
path on an async loopback TLS connection.

```sh
# whole matrix (slow)
cargo bench --bench write_throughput

# one variant / one size
cargo bench --bench write_throughput -- tokio_openssl_bufwriter/1048576

# quick smoke run
cargo bench --bench write_throughput -- --warm-up-time 1 --measurement-time 2 --sample-size 10
```

## What is being measured

`SSL_write` does not hand your whole buffer to the socket in one go. `ssl3_write_bytes`
splits it into `split_send_fragment` (<=16 KiB) TLS records, and `tls_retry_write_records`
issues **one `BIO_write` per record buffer** — `numwpipes` is 1 unless you enable
pipelining. With a socket BIO that is one `write(2)` syscall per 16 KiB.

`write_counts.rs` measures this on the `tokio-openssl` custom-BIO path, which is the only
variant a Rust wrapper can observe: a 1 MiB write takes **64 write syscalls for 64
records**, and 2 when a `BufWriter` is interposed. The native socket BIO and the KTLS path
write from inside OpenSSL straight to the fd, so their syscall counts cannot be counted
in-process — but they follow from the same record layer. KTLS in particular does not batch:
`ktls_allocate_write_buffers` (`ssl/record/methods/ktls_meth.c`) asserts `numtempl == 1` and
sets `numwpipes = 1`, while `ssl3_write_bytes` still splits by `split_send_fragment`, so
KTLS is also one `sendmsg` per record. Use `strace` to confirm those two directly.

## Variants

| Benchmark id | Write path |
|---|---|
| `openssl_ktls_ktls` | `TokioSslStream` + `SSL_OP_ENABLE_KTLS` — kernel frames the records |
| `openssl_ktls_socket_bio` | `TokioSslStream` without KTLS — OpenSSL's native socket BIO |
| `tokio_openssl_custom_bio` | `tokio_openssl::SslStream<TcpStream>` — rust-openssl's custom BIO |
| `tokio_openssl_bufwriter` | `tokio_openssl::SslStream<BufWriter<TcpStream>>` — coalesced |

## Results

Measured on OpenSSL 3.5.5, Linux loopback. Each cell is the **min-max of the median
throughput across 3 separate process invocations**, because run-to-run variance is much
larger than criterion's within-run confidence intervals — the timed region is a
producer/consumer pipeline, so the writer's and drain task's core placement for the life of
a process moves the result by up to ~30%. Only differences whose ranges do not overlap are
meaningful. Absolute numbers are machine-specific.

| Payload | ktls | socket BIO | custom BIO | + BufWriter |
|---|---|---|---|---|
| 1 KiB | 79-81 | 78-90 | 77-84 | 79-100 |
| 16 KiB | 610-622 | 603-630 | 466-616 | 456-602 |
| 64 KiB | 607-631 | 613-646 | 458-622 | **902-968** |
| 1 MiB | 605-608 | 592-616 | 604-613 | **1390-1517** |
| 8 MiB | 477-494 | 568-609 | 576-608 | **1319-1471** |

(MiB/s.)

What the data does and does not support:

1. **Coalescing is a large, reproducible win above one record.** `BufWriter` is roughly
   1.5x at 64 KiB and 2.4x at 1-8 MiB, with ranges nowhere near overlapping the unbuffered
   variants. This is purely from issuing 2 syscalls instead of 64.
2. **At and below one record there is nothing to coalesce**, and no variant is
   distinguishable from another at 1 KiB. The 16 KiB row spans 456-630 across variants but
   the ranges overlap heavily, so it is inconclusive rather than a real ordering.
3. **KTLS is slower for very large writes.** At 8 MiB it lands at 477-494 against 568-609
   for the plain socket BIO — reproducible across runs and non-overlapping. At every other
   size the two are indistinguishable. This benchmark does not explain the 8 MiB result;
   note that KTLS does not reduce the syscall count, it only moves AES-GCM into the kernel.
4. **The two BIO designs are not distinguishable here.** This crate's native socket BIO and
   rust-openssl's custom BIO overlap at every payload size, so the syscall count dominates
   any BIO indirection cost — but "overlap" is a statement about this noise floor, not a
   proof of equality.

### Implication for a vectored BIO

A queuing/`writev` BIO cannot beat the `BufWriter` numbers above, because the win comes
from issuing fewer syscalls rather than from scatter-gather. It would also have to copy
each record into its own buffer — OpenSSL recycles `wbuf` as soon as `BIO_write` returns —
so it buys the same syscall reduction at the same copy cost, with far more unsafe code.
A vectored BIO would also disable KTLS, since `BIO_get_ktls_send` requires a real socket BIO.

## Methodology

The following choices matter for interpreting the numbers:

- **Handshakes are excluded.** One connection per variant is established up front and
  reused; only `write_all` + `flush` is timed.
- **`flush` is included** in every variant. Without it the `BufWriter` variant would be
  measuring memcpy into a userspace buffer.
- **The peer does not decrypt.** After the handshake the server drains raw ciphertext from
  a duplicate of its socket, so the receiver's AES-GCM cost stays out of the critical path
  and the measurement reflects the sender.
- **`TCP_NODELAY` is on everywhere.** Nagle would otherwise coalesce small segments in the
  kernel and mask the difference the benchmark is trying to show.
- **The KTLS variant self-checks.** If `ktls_send_enabled()` is false — usually because the
  kernel `tls` module is not loaded — the variant is skipped with a warning rather than
  silently benchmarking the non-KTLS path. Run `sudo modprobe tls` first.
- **One connection is reused** for every iteration and every payload size of a variant, so
  the congestion window and socket buffers are warm and are not re-measured per size.

Run-to-run variance between *process invocations* reaches ~30% on an otherwise idle
machine, far exceeding criterion's reported within-run intervals. Compare min-max bands
across several separate runs, not two medians; treat overlapping bands as inconclusive.

## Counting syscalls externally

`cargo test -p openssl-ktls-tests write_counts -- --nocapture` is the portable check. If
`strace` is available it can confirm the same thing end to end:

```sh
strace -f -c -e trace=write,writev,sendmsg \
  cargo bench --bench write_throughput -- tokio_openssl_custom_bio/1048576
```
