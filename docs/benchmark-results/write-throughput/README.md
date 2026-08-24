# Write-throughput benchmark results

- [Original results](original.md) — historical four-variant measurements referenced by
  the benchmark analysis.
- [2026-08-22 WSL2 results](2026-08-22-wsl2.md) — five-variant measurements including
  `rustls_openssl`.
- [2026-08-24 WSL2 rustls buffering results](2026-08-24-wsl2-rustls-buffering.md) —
  focused comparison of buffered and unbuffered `rustls_openssl`.

Results from different files are not directly comparable because they were collected on
different machines and with different Criterion sampling parameters.
