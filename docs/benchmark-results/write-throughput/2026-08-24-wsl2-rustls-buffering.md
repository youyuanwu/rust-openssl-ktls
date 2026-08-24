# Rustls buffering results: 2026-08-24 WSL2

These measurements run the full write-throughput matrix, including rustls using the
OpenSSL crypto provider with and without a 1 MiB Tokio `BufWriter` around its TCP
transport.

## Environment

- Commit: `4c1b62c5cdd4e677c1ec337c56b2f993c86d9072`
- Kernel: Linux 6.6.87.2-microsoft-standard-WSL2, x86-64
- CPU: AMD EPYC 7763 64-Core Processor; guest allocation of 8 cores / 16 threads
- Memory: 31 GiB
- Rust: 1.97.1
- OpenSSL: 3.0.13
- CPU frequency governor: unavailable in the WSL2 guest

## Method

The full six-variant matrix ran in three separate processes:

```sh
for run in 1 2 3; do
  cargo bench --bench write_throughput -- \
    --warm-up-time 1 \
    --measurement-time 2 \
    --sample-size 20 \
    --save-baseline "wsl2-2026-08-24-full-run-${run}"
done
```

Each cell is the min-max of the Criterion median throughput across those processes, in
MiB/s. Non-overlapping ranges are treated as distinguishable; overlapping ranges are
inconclusive. Buffer construction alone does not demonstrate syscall coalescing.

## Current-thread runtime

| Payload | KTLS | socket BIO | custom BIO | OpenSSL + BufWriter | rustls-openssl | rustls + BufWriter |
|---|---|---|---|---|---|---|
| 1 KiB | 72-74 | 86-87 | 87-87 | 86-89 | 80-81 | 82-84 |
| 16 KiB | 573-580 | 694-703 | 681-709 | 687-709 | 654-668 | 661-679 |
| 64 KiB | 574-580 | 697-710 | 670-715 | 704-950 | 838-850 | 778-831 |
| 1 MiB | 570-576 | 675-709 | 706-718 | 767-1126 | 907-917 | 1009-1048 |
| 8 MiB | 554-559 | 674-697 | 677-697 | 778-1097 | 876-901 | 950-1008 |

For rustls, buffering is distinguishably faster at 1 KiB, 1 MiB, and 8 MiB. The
mean-of-medians gains are approximately 3%, 13%, and 11%. It is distinguishably slower
at 64 KiB, while 16 KiB is inconclusive.

## Multi-thread runtime

| Payload | KTLS | socket BIO | custom BIO | OpenSSL + BufWriter | rustls-openssl | rustls + BufWriter |
|---|---|---|---|---|---|---|
| 1 KiB | 54-55 | 70-73 | 69-73 | 70-71 | 58-69 | 64-67 |
| 16 KiB | 386-447 | 429-616 | 415-599 | 284-575 | 268-536 | 342-414 |
| 64 KiB | 402-436 | 427-599 | 306-604 | 509-647 | 554-599 | 555-588 |
| 1 MiB | 434-446 | 589-607 | 609-616 | 1097-1108 | 601-610 | 1033-1049 |
| 8 MiB | 409-431 | 554-591 | 597-614 | 1107-1120 | 604-612 | 1040-1061 |

For rustls, buffering is distinguishably faster at 1 MiB and 8 MiB, reaching
approximately 1.72x and 1.73x the unbuffered throughput. Results through 64 KiB overlap
and are inconclusive.

## Buffered implementation comparison

Buffered rustls does not produce a distinguishable win over buffered tokio-openssl in any
row. Buffered tokio-openssl is distinguishably faster at 1 KiB and 16 KiB on
`current_thread`, and at 1 KiB, 1 MiB, and 8 MiB on `multi_thread`. At the two large
multi-thread payloads it is approximately 5% faster by the mean of the three medians.
The remaining buffered ranges overlap and are inconclusive.

## Conclusion

Transport buffering materially improves large-write rustls/OpenSSL throughput on both
runtimes used here, especially `multi_thread`. It does not beat the buffered
tokio-openssl path in this full run. These conclusions apply to this machine and benchmark
method; compare only measurements within this result set.
