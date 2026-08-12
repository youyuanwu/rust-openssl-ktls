# Write-path benchmarks

`openssl-ktls-tests/benches/write_throughput.rs` measures the cost of OpenSSL's write
path on an async loopback TLS connection.

## Takeaway: buffered vs unbuffered

Put a `BufWriter` under the TLS stream when you write more than one 16 KiB record at a
time. It is worth ~2.4x at 1-8 MiB on a multi-thread runtime. Size the capacity to hold
many records — 1 MiB is what these benchmarks use. 64 KiB is already enough on a
`current_thread` runtime, but on a multi-thread one the benefit keeps growing to ~256 KiB
because the reader keeps parking (155 context switches per 8 MiB at 64 KiB, 34 at 1 MiB).

What you are actually paying for without it, per 16 KiB record and *not* per byte:

- **a reader wakeup.** Each `write(2)` pushes on loopback and wakes the peer, which drains
  it and parks again — ~1 OS context switch per record on a multi-thread runtime.
- **a trip through the TCP/loopback receive path.** Per packet, not per byte, and packets
  cannot exceed the 64 KiB GSO ceiling.

Not what you are paying for: syscall entry (~1 us, invisible here), and not the TLS records
themselves, which stay 16 KiB either way.

Consequences worth knowing:

- **Below one record a `BufWriter` is pure loss** — it adds a memcpy per record and has
  nothing to batch. Measurably slower when the capacity is too small to hold two records.
- **The win shrinks to ~1.3x on a `current_thread` runtime**, because half of it was
  cross-core wakeups that a single-threaded scheduler does not have.
- **KTLS does not help here.** It moves AES-GCM into the kernel but still emits one
  `sendmsg` per record, so it does not touch either cost above.

Evidence: [Results](#results), [Current-thread vs multi-thread](#current-thread-vs-multi-thread),
[Where the context switches come from](#where-the-context-switches-come-from),
[Is it just the syscall count?](#is-it-just-the-syscall-count).

All of this is measured on loopback with `TCP_NODELAY`, which maximises both costs — a real
NIC has a 1500-byte MTU and the peer is not on the same host, so the ratios will differ even
though the record-per-`write(2)` behaviour that causes them does not.

## Running

```sh
# whole matrix (slow)
cargo bench --bench write_throughput

# one variant / one size, both scheduler flavors
cargo bench --bench write_throughput -- 'tokio_openssl_bufwriter_\w+/1048576'

# one scheduler flavor only
cargo bench --bench write_throughput -- current_thread

# quick smoke run
cargo bench --bench write_throughput -- --warm-up-time 1 --measurement-time 2 --sample-size 10

# attribute the cost: syscalls, wakeups, context switches, packets
cargo run --release --example ctxsw
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

Each variant runs under both tokio schedulers, and the flavor is appended to the benchmark
id (`tokio_openssl_bufwriter_current_thread`):

| Suffix | Runtime |
|---|---|
| `_current_thread` | `new_current_thread` — writer and drain task share one thread |
| `_multi_thread` | `new_multi_thread().worker_threads(2)` — they can occupy separate cores |

The flavor is a dimension because the dominant cost below is the reader wakeup
(see [Why buffering helps](#why-buffering-helps)), and what a wakeup costs depends on
whether it crosses a core. Each flavor gets its own runtime and its own connections, since
a `TcpStream` is bound to the reactor that registered it.

## Results

Measured on OpenSSL 3.5.5, Linux loopback, on a **2-worker multi-thread runtime**
(`_multi_thread`). Each cell is the **min-max of the median throughput across 3 separate
process invocations**, because run-to-run variance is much
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
   variants. What that buys is analysed in
   [Is it just the syscall count?](#is-it-just-the-syscall-count) — it is not syscall entry
   cost, and it is not proportional to the number of syscalls saved.
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

### Current-thread vs multi-thread

Both flavors below come from the **same 3 process invocations on a different machine** than
the table above, so compare across the two tables only as ratios, never as absolute numbers.
KTLS is missing because that host has no `tls` kernel module.

| Payload | socket BIO | custom BIO | + BufWriter |
|---|---|---|---|
| 1 KiB | 161-167 / 95-99 | 164-167 / 97-101 | 161-168 / 95-101 |
| 16 KiB | 980-1154 / 452-516 | 1157-1185 / 486-508 | 1029-1172 / 479-706 |
| 64 KiB | 1057-1162 / 461-735 | 720-1145 / 519-728 | 1268-1443 / 895-934 |
| 1 MiB | 1040-1151 / 475-740 | 909-1142 / 504-733 | 1259-1574 / 1494-1511 |
| 8 MiB | 1000-1056 / 445-691 | 914-1046 / 462-687 | 1133-1442 / 1370-1436 |

(MiB/s, `current_thread` / `multi_thread`.)

1. **`current_thread` is ~2x faster for every unbuffered variant, at every payload size.**
   The ranges do not overlap anywhere in the first two columns — the largest gap is 16 KiB,
   where the single-threaded runtime more than doubles throughput. Even the 1 KiB row,
   where the variants are indistinguishable from each other, moves 95-101 to 161-167.
2. **For the buffered variant the two flavors are indistinguishable at 1-8 MiB** and
   `current_thread` wins only at 64 KiB and below.
3. Those two facts together are a direct test of the [wakeup
   explanation](#why-buffering-helps): the cost that `BufWriter` removes and the cost that
   `current_thread` removes are the *same* cost. Buffering removes reader wakeups by
   batching records into one syscall; a single-threaded runtime keeps the wakeups but makes
   each one a same-core task switch instead of a cross-core IPI. Apply either and the
   penalty goes; apply both and the second one buys almost nothing, which is what the
   overlapping 1-8 MiB buffered rows show.
4. **`BufWriter` is therefore worth much less on `current_thread`**: ~1.3x at 1 MiB against
   ~2.4x on the multi-thread runtime. It is still a win, and still the right default for a
   server, but the headline 2.4x is a property of the scheduler as much as of the syscall
   count.

This does not make `current_thread` a faster runtime in general — the benchmark deliberately
puts exactly two tasks on it, and the drain task does no decryption, so a single core is
enough to run both. A workload that can actually use the second core would not behave this
way.

## Why buffering helps

The obvious explanation — "fewer syscalls, so less syscall entry overhead" — does not
survive arithmetic. At 8 MiB the unbuffered variants run at ~590 MiB/s and the buffered one
at ~1400 MiB/s, which per 16 KiB record is:

| | per record | |
|---|---|---|
| unbuffered | 26.5 us | |
| buffered | 11.2 us | |
| **difference** | **15.3 us** | ~20x too large to be syscall entry cost (~1 us) |

Instrumenting an 8 MiB transfer (512 records) shows where it actually goes:

| | context switches | loopback packets | packet size | throughput |
|---|---|---|---|---|
| unbuffered | 390 (**0.76/record**) | 771 | 10.6 KiB | 406 MiB/s |
| buffered | 18 (0.04/record) | 188 | 43.6 KiB | 1241 MiB/s |

**Roughly one context switch per TLS record.** A cross-core wakeup costs ~5-15 us, which
closes the 15.3 us gap. Two effects compound:

1. **Wakeup amplification.** With `TCP_NODELAY` every 16 KiB write pushes immediately and
   wakes the reader, which drains it and parks again — one park/wake rendezvous per
   record. Batching amortises it over ~64 records.
   [Where the context switches come from](#where-the-context-switches-come-from) breaks
   this down, and the
   [current-thread comparison](#current-thread-vs-multi-thread) tests it by making the
   rendezvous same-core instead of removing it.
2. **Packet count.** Larger writes let the stack build bigger GSO super-packets, 10.6 KiB
   to 43.6 KiB here, so ~4x fewer traversals of the TCP and loopback receive path. That
   cost lands in softirq rather than in your syscall.

### Where the context switches come from

`cargo run --release --example ctxsw` attributes them. Per 8 MiB transfer:

| Runtime | Variant | write(2) | writer blocked | reader waits | ctx switches | MiB/s |
|---|---|---|---|---|---|---|
| multi_thread | unbuffered | 512 | 4 | 443 | 386 | 470 |
| multi_thread | buffered | 9 | 0.1 | 59 | 29 | 1366 |
| multi_thread | unbuffered, `unconstrained` | 512 | **0** | 433 | 372 | 477 |
| current_thread | unbuffered | 514 | 4 | **2** | **0.1** | 913 |
| current_thread | buffered | 11 | 2 | 2 | 0.2 | 1163 |

"Writer blocked" counts `Pending` from the client's `poll_write` (a full socket send
buffer); "reader waits" counts `Pending` from the drain task's `poll_read` (it emptied the
socket and parked).

**The switches are the reader parking and being woken, not the writer blocking.** Two
things follow from the table:

- **The writer essentially never blocks.** The `unconstrained` row disables tokio's
  128-operation coop budget and the count goes to exactly 0, which also identifies the
  other rows' 4 as `512 / 128` scheduler-forced yields rather than a full send buffer. Yet
  removing them changes neither the context switches (372 vs 386) nor the throughput
  (477 vs 470). The send buffer is never the constraint, because the drain keeps it empty.
- **The reader parks after almost every record.** 443 waits for 512 writes — 0.87 each.
  The drain reads 256 KiB at a time and never decrypts, so it consumes a 16 KiB record far
  faster than the writer can encrypt the next one. It finds the socket empty, re-arms
  epoll and parks; the next `write(2)` pushes on loopback synchronously, calls
  `sk_data_ready`, and wakes it. That park/wake pair is the context switch, and there is
  one per `write(2)` — not per record and not per byte.

That last distinction is the whole mechanism. **A `BufWriter` does not reduce records or
bytes; it reduces `write(2)` calls, and the rendezvous count follows the syscall count.**
512 writes produce 443 reader parks; 9 writes produce 59. The reader then gets 1 MiB per
wakeup instead of 16 KiB, so one park/wake amortises over ~64 records.

The `current_thread` rows confirm it from the other direction. The record count and the
syscall count are unchanged (514 writes), but the drain task *cannot run while the writer
runs*, so ciphertext accumulates in the socket buffer and the reader almost never finds it
empty: 2 waits instead of 443, and 0.1 OS context switches instead of 386. The producer and
consumer still hand off, but the handoff is a poll of another future on the same thread,
which costs ~100 ns rather than the ~5-15 us of a cross-core wakeup. Hence the ~2x in
[Current-thread vs multi-thread](#current-thread-vs-multi-thread) — and hence why that
speedup disappears once a `BufWriter` has already removed the wakeups.

### Is it just the syscall count?

No. Fewer syscalls is the lever, but almost none of the win is the syscall itself, and the
benefit is not proportional to how many are removed. Sweeping the `BufWriter` capacity
separates the effects. Counts below are per 8 MiB transfer and reproduce to within a
percent across runs; throughput is min-max of 3 runs.

| Runtime | Capacity | write(2) | ctxsw | lo packets | MiB/s |
|---|---|---|---|---|---|
| current_thread | unbuffered | 514 | 0.1 | 302-313 | 759-973 |
| current_thread | 32 KiB | 514 | 0.1 | 302 | 857-1226 |
| current_thread | 64 KiB | 172 | 0.0 | 173-176 | 1102-1397 |
| current_thread | 256 KiB | 37 | 0.1 | 161-162 | 1170-1356 |
| current_thread | 1 MiB | 11 | 0.1 | 153-154 | 1142-1412 |
| multi_thread | unbuffered | 512 | 350-380 | 757-760 | 444-496 |
| multi_thread | 32 KiB | 512 | 348-388 | 755-761 | 389-454 |
| multi_thread | 64 KiB | 171 | 153-155 | 254-255 | 785-833 |
| multi_thread | 256 KiB | 35 | 45-59 | 195-200 | 380-1193 |
| multi_thread | 1 MiB | 9 | 34-37 | 182-187 | 657-1346 |

The two large-capacity `multi_thread` rows are too noisy to read here — running the whole
sweep in one process makes core placement unstable — so take their throughput from the
[Results](#results) table instead. The counter columns are stable regardless.

Three findings, in order of how much they matter:

1. **The win saturates at a 64 KiB capacity, not at the smallest syscall count.** On
   `current_thread`, going from 514 to 172 syscalls is a real jump, but 172 to 11 — a
   further **16x** reduction — is indistinguishable (1102-1397 against 1142-1412). If the
   syscall count were the thing being paid for, that 16x would show. It does not.
   What stops improving at the same point is the **packet count**: 302, then 173, then 154.
   The `lo` MTU is 65536 and that is also the GSO ceiling, so once a `write(2)` reaches
   ~48 KiB the stack is already building maximum-size super-packets and 8 MiB cannot be
   carried in fewer than 128 of them. Larger writes cannot buy fewer traversals of the TCP
   and loopback receive path, which is where the per-push cost actually lands.
2. **Buffering that does not batch is a straight loss.** A 32 KiB buffer cannot hold two
   16 KiB records, so it flushes once per record: identical 512 syscalls, identical ~760
   packets, identical ~370 context switches — and it adds one memcpy per record. On
   `multi_thread` it is slower than unbuffered in all three runs (389-454 against 444-496).
   That is the price of the copy, visible because nothing offsets it.
3. **Syscall entry cost is invisible.** It is ~1 us against the 15.3 us per-record gap
   computed above, and finding 1 shows a 16x change in syscall count moving nothing.

So the buffered-vs-unbuffered difference decomposes into two costs that fewer, larger
`write(2)` calls avoid — reader park/wake rendezvous, and per-packet receive-path work —
minus one cost buffering adds, the extra memcpy. The split between the first two depends
entirely on the runtime: on `multi_thread` the rendezvous dominates (380 context switches
gone), while on `current_thread` there are no context switches to remove and the whole
~1.5x is the packet path.

### What actually changes size

Only the syscall does. Three sizes are easy to conflate:

| Layer | Unbuffered | Buffered |
|---|---|---|
| TLS record — what OpenSSL emits per `BIO_write` | 16 KiB | 16 KiB, unchanged |
| `write(2)` | 16 KiB | **1 MiB** |
| TCP segment on the wire | 10.6 KiB | 43.6 KiB |

With a `BufWriter` interposed, `BIO_write` still fires once per record, but it lands on
`BufWriter::poll_write`, which is a memcpy into the userspace buffer and **not** a syscall.
Only when that buffer fills, or on `flush`, does a single `write(2)` carrying ~64 records
reach the kernel. This is what `write_counts.rs` measures — the counting wrapper sits below
the `BufWriter`, so it counts real syscalls: 64 unbuffered versus 2 buffered per MiB.

The TLS protocol is untouched. Records are still <=16 KiB on the wire — that is a format
limit, not a tunable — and the receiver sees a byte-identical stream. Buffering changes only
how many syscalls carry those bytes.

The cost is one extra memcpy per record, which is why the benefit is size-dependent: worth
it by 2.4x at 1-8 MiB, and pure overhead at 1 KiB and 16 KiB where there is nothing to
batch. The 32 KiB row of the [capacity sweep](#is-it-just-the-syscall-count) prices that
copy on its own — same syscalls, same packets, ~10% slower. Note also that `TCP_NODELAY`
inflates the effect by forcing a push per record; with
Nagle enabled the gap would narrow, though not much at 16 KiB since Nagle does not hold back
segments larger than the MSS.

### Reproducing the instrumentation

The context-switch, syscall and park/wake counts come from `examples/ctxsw.rs`:

```sh
cargo run --release --example ctxsw
```

It counts context switches by summing `voluntary_ctxt_switches` +
`nonvoluntary_ctxt_switches` across `/proc/self/task/*/status` — the per-process
`/proc/self/status` only covers the main thread, and the work happens on tokio workers.

The packet counts in the first table were one-off and are not covered by the example; read
the `lo:` receive-packet column of `/proc/net/dev` around the transfer to repeat them.

### Implication for a vectored BIO

A queuing/`writev` BIO cannot beat the `BufWriter` numbers above, because the win comes from
issuing fewer and larger pushes rather than from scatter-gather — and it saturates once a
push reaches the ~64 KiB loopback GSO ceiling, which a `BufWriter` already does. It would
also have to copy
each record into its own buffer — OpenSSL recycles `wbuf` as soon as `BIO_write` returns —
so it buys the same syscall reduction at the same copy cost, with far more unsafe code.
A vectored BIO would also disable KTLS, since `BIO_get_ktls_send` requires a real socket BIO.

For contrast, rustls avoids that extra copy because it is sans-I/O: it encrypts directly
into owned chunks in a `VecDeque<Vec<u8>>` that stay alive until the caller drains them, so
`write_tls` can build `IoSlice`s over them and issue one `write_vectored`. OpenSSL cannot,
because its record layer owns the I/O loop and must recycle its write buffer per record.

Why OpenSSL cannot simply encrypt into the BIO's own buffer, and which copies on the write
path are removable at all, is covered in [ZeroCopy.md](ZeroCopy.md).

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
- **Both scheduler flavors share the same peer setup.** The drain task is `tokio::spawn`ed
  on the runtime under test, so on `current_thread` it is driven by the same `block_on`
  that drives the writer — the timed region then includes the drain's work rather than
  overlapping it with a second core.

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
