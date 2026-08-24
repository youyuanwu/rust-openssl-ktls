# Rustls buffering results: 2026-08-24 WSL2

These measurements compare rustls using the OpenSSL crypto provider with and without a
1 MiB Tokio `BufWriter` around its TCP transport.

## Environment

- Commit: `4c1b62c5cdd4e677c1ec337c56b2f993c86d9072`
- Kernel: Linux 6.6.87.2-microsoft-standard-WSL2, x86-64
- CPU: AMD EPYC 7763 64-Core Processor; guest allocation of 8 cores / 16 threads
- Memory: 31 GiB
- Rust: 1.97.1
- OpenSSL: 3.0.13
- CPU frequency governor: unavailable in the WSL2 guest

## Method

Only `rustls_openssl` and `rustls_openssl_bufwriter` were measured. The focused matrix ran
in three separate processes:

```sh
for run in 1 2 3; do
  cargo bench --bench write_throughput -- \
    'rustls_openssl(_bufwriter)?_(current_thread|multi_thread)/' \
    --warm-up-time 1 \
    --measurement-time 2 \
    --sample-size 20 \
    --save-baseline "wsl2-2026-08-24-run-${run}"
done
```

Each cell is the min-max of the Criterion median throughput across those processes, in
MiB/s. Non-overlapping ranges are treated as distinguishable; overlapping ranges are
inconclusive. Buffer construction alone does not demonstrate syscall coalescing.

## Current-thread runtime

| Payload | rustls-openssl | + BufWriter |
|---|---|---|
| 1 KiB | 79-81 | 82-84 |
| 16 KiB | 659-674 | 653-666 |
| 64 KiB | 808-844 | 792-825 |
| 1 MiB | 878-912 | 926-959 |
| 8 MiB | 846-904 | 880-943 |

Buffering is distinguishably faster at 1 KiB and 1 MiB, by approximately 3% and 5%
respectively using the mean of the three medians. The ranges overlap at 16 KiB, 64 KiB,
and 8 MiB, so those payloads are inconclusive.

## Multi-thread runtime

| Payload | rustls-openssl | + BufWriter |
|---|---|---|
| 1 KiB | 58-63 | 61-67 |
| 16 KiB | 347-463 | 356-521 |
| 64 KiB | 541-575 | 551-572 |
| 1 MiB | 590-621 | 972-994 |
| 8 MiB | 533-606 | 1011-1047 |

Buffering is distinguishably faster at 1 MiB and 8 MiB, reaching approximately 1.62x and
1.78x the unbuffered throughput using the mean of the three medians. Results through
64 KiB overlap and are inconclusive.

## Conclusion

Transport buffering materially improves large-write rustls/OpenSSL throughput on the
multi-thread runtime used here. The current-thread benefit is small or inconclusive. These
conclusions apply to this machine and benchmark method; compare only measurements within
this result set.
