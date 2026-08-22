# Original write-throughput results

These are the historical measurements that predate the `rustls_openssl` variant.

## Multi-thread runtime

Measured on OpenSSL 3.5.5, Linux loopback, on a **2-worker multi-thread runtime**
(`_multi_thread`). Each cell is the **min-max of the median throughput across 3 separate
process invocations**, because run-to-run variance is much larger than Criterion's
within-run confidence intervals. Only differences whose ranges do not overlap are
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
   variants.
2. **At and below one record there is nothing to coalesce**, and no variant is
   distinguishable from another at 1 KiB. The 16 KiB ranges overlap heavily.
3. **KTLS is slower for very large writes.** At 8 MiB it lands at 477-494 against 568-609
   for the plain socket BIO. At every other size the two are indistinguishable.
4. **The two BIO designs are not distinguishable here.** Their ranges overlap at every
   payload size.

## Current-thread vs multi-thread

Both flavors below come from the **same 3 process invocations on a different machine** than
the table above. Compare across the two tables only as ratios, never as absolute numbers.
KTLS is missing because that host had no `tls` kernel module.

| Payload | socket BIO | custom BIO | + BufWriter |
|---|---|---|---|
| 1 KiB | 161-167 / 95-99 | 164-167 / 97-101 | 161-168 / 95-101 |
| 16 KiB | 980-1154 / 452-516 | 1157-1185 / 486-508 | 1029-1172 / 479-706 |
| 64 KiB | 1057-1162 / 461-735 | 720-1145 / 519-728 | 1268-1443 / 895-934 |
| 1 MiB | 1040-1151 / 475-740 | 909-1142 / 504-733 | 1259-1574 / 1494-1511 |
| 8 MiB | 1000-1056 / 445-691 | 914-1046 / 462-687 | 1133-1442 / 1370-1436 |

(MiB/s, `current_thread` / `multi_thread`.)

1. **`current_thread` is ~2x faster for every unbuffered variant, at every payload size.**
2. **For the buffered variant the two flavors are indistinguishable at 1-8 MiB**, and
   `current_thread` wins only at 64 KiB and below.
3. `BufWriter` and `current_thread` remove the same reader-wakeup cost in different ways.
4. **`BufWriter` is worth much less on `current_thread`**: about 1.3x at 1 MiB against
   about 2.4x on the multi-thread runtime.

See [the benchmark analysis](../../Benchmarks.md#why-buffering-helps) for the mechanism
behind these results.
