# Rustls provider results: 2026-08-24 WSL2

These measurements run the full write-throughput matrix with rustls using either the
OpenSSL or ring crypto provider, with and without a 1 MiB Tokio `BufWriter` around the TCP
transport.

## Environment

- Commit: `1c7b965f929a05dda3c8dd06fbd5a03d234c010f`
- Kernel: Linux 6.6.87.2-microsoft-standard-WSL2, x86-64
- CPU: AMD EPYC 7763 64-Core Processor; guest allocation of 8 cores / 16 threads
- Memory: 31 GiB
- Rust: 1.97.1
- OpenSSL: 3.0.13
- CPU frequency governor: unavailable in the WSL2 guest
- Rustls suite: TLS 1.2 ECDHE-RSA with ChaCha20-Poly1305-SHA256 for both providers

## Method

The full eight-variant matrix ran in three separate processes:

```sh
for run in 1 2 3; do
  cargo bench --locked -p openssl-ktls-tests --bench write_throughput -- \
    --warm-up-time 1 \
    --measurement-time 2 \
    --sample-size 20 \
    --save-baseline "wsl2-2026-08-24-provider-run-${run}"
done
```

Each cell is the min-max of the Criterion median throughput across those processes, in
MiB/s. Non-overlapping ranges are treated as distinguishable; overlapping ranges are
inconclusive. Compare only values within this result set.

## Current-thread runtime

| Payload | KTLS | socket BIO | custom BIO | OpenSSL + BufWriter | rustls/OpenSSL | rustls/OpenSSL + BufWriter | rustls/ring | rustls/ring + BufWriter |
|---|---|---|---|---|---|---|---|---|
| 1 KiB | 73-73 | 87-88 | 86-89 | 86-90 | 80-81 | 83-84 | 93-93 | 96-97 |
| 16 KiB | 575-580 | 559-697 | 658-716 | 644-704 | 669-676 | 668-678 | 752-755 | 741-761 |
| 64 KiB | 581-582 | 669-708 | 661-718 | 658-962 | 832-844 | 821-841 | 938-961 | 926-947 |
| 1 MiB | 571-578 | 669-706 | 667-718 | 992-1119 | 918-919 | 1045-1060 | 1042-1054 | 1079-1193 |
| 8 MiB | 560-562 | 653-700 | 654-705 | 989-1106 | 894-904 | 1030-1039 | 1015-1034 | 1177-1184 |

Ring is distinguishably faster than the OpenSSL rustls provider at every payload, with or
without buffering. Its mean-of-medians advantage is approximately 12-15% unbuffered and
10-16% buffered.

Buffering improves both providers at 1 KiB, 1 MiB, and 8 MiB. The 16 KiB and 64 KiB
ranges overlap.

## Multi-thread runtime

| Payload | KTLS | socket BIO | custom BIO | OpenSSL + BufWriter | rustls/OpenSSL | rustls/OpenSSL + BufWriter | rustls/ring | rustls/ring + BufWriter |
|---|---|---|---|---|---|---|---|---|
| 1 KiB | 53-57 | 70-72 | 69-72 | 70-77 | 60-68 | 63-71 | 78-80 | 78-88 |
| 16 KiB | 391-412 | 298-623 | 545-613 | 271-480 | 366-407 | 260-359 | 348-693 | 343-696 |
| 64 KiB | 429-454 | 407-609 | 437-624 | 516-649 | 574-575 | 569-578 | 653-664 | 639-656 |
| 1 MiB | 424-445 | 386-620 | 550-628 | 987-1116 | 613-614 | 1033-1049 | 699-713 | 1183-1206 |
| 8 MiB | 402-431 | 556-594 | 525-612 | 1005-1130 | 600-607 | 1054-1067 | 699-707 | 1210-1226 |

Ring is distinguishably faster than the OpenSSL rustls provider at 1 KiB and 64 KiB
through 8 MiB, in both buffering states. At 1 MiB and 8 MiB its advantage is approximately
15-16% unbuffered and 14-15% buffered. The 16 KiB ranges are inconclusive.

Buffering improves both providers at 1 MiB and 8 MiB by approximately 1.7x. Smaller
payloads are inconclusive except for the OpenSSL provider at 16 KiB, where buffering is
distinguishably slower.

## Cross-stack buffered comparison

At 1 MiB and 8 MiB on `multi_thread`, buffered rustls/ring is distinguishably faster than
buffered tokio-openssl by approximately 13%. It is also distinguishably faster at 8 MiB on
`current_thread` by approximately 11%; the 1 MiB current-thread ranges overlap.

## Conclusion

For the common negotiated suite and this benchmark method, ring is faster than the OpenSSL
rustls provider across nearly the entire matrix. Buffering remains important for large
multi-thread writes regardless of provider. The best large-write result is buffered
rustls/ring. At small multi-thread payloads, ring's 1 KiB provider win and the OpenSSL
provider's 16 KiB buffering regression are conclusive; only overlapping ranges are
inconclusive.
