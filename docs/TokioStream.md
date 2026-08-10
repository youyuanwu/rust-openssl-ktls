# The tokio stream

`openssl_io::tokio::SslStream<S>` is a readiness-based async OpenSSL stream. It is the second
binding in this crate; the first, `openssl_io::compio::SslStream`, is completion-based and is
described in [CompioStream.md](CompioStream.md).

This document records why the two differ where they do, and the outcome of the experiment that
motivated the work.

## The experiment

The compio stream was built in three layers: a synchronous `TlsEngine` that performs no I/O at
all, an async pump, and a public stream. Keeping the engine synchronous was originally a testing
convenience — it let the whole OpenSSL state machine be driven in memory with no runtime involved.

The question this work asked was whether that separation was real. If the engine is genuinely
runtime-agnostic, a second stream built on a *different* async model should need only a new pump.

### Result: the hypothesis held

The engine required no runtime-specific logic, no `cfg(feature)`, and no behavioural change. The
complete diff to `src/engine.rs` across the whole of this work is three items, none of which
alters what the state machine does:

| Change | Why |
|---|---|
| `PAIR_BUF` made `pub(crate)` | so a pump can assert its own ciphertext backlog can absorb a completely full pair |
| `CIPHER_CHUNK` moved here from the compio module | every pump stages ciphertext; none should have to reach into another runtime's feature-gated module to learn how much |
| `retry_owed` widened from `cfg(test)` to `cfg(any(test, debug_assertions))` | the readiness pump asserts the retry invariant in debug builds, not only in tests |

The one shared change outside the engine is `unsafe impl Send for BioPair` in `src/ffi.rs`. The
tokio stream has to move into a spawned task; `openssl::ssl::Ssl` is already `Send + Sync`, and
`BioPair` owns its raw `BIO` pointers exclusively and never shares them, so transferring ownership
is sound. `Sync` is deliberately *not* implemented — two threads calling `BIO_read`/`BIO_write`
through a shared reference would be unsound, and nothing in the crate needs it.

A CI step asserts the engine stays runtime-free by rejecting any non-comment line in `engine.rs`
that mentions a runtime, an async construct, or a feature conditional.

### One planning assumption was wrong

The plan asserted that making `BioPair: Send` would additively widen `compio::SslStream` to `Send`.
It does not, and the claim was disproved by compilation. `compio.rs` stores its in-flight transport
operations as `Pin<Box<dyn Future<...>>>` with no `+ Send` bound, so the stream is `!Send`
regardless of what `BioPair` implements. Making it `Send` would require `+ Send` on those aliases
plus `R: Send, W: Send` bounds on the impl blocks — a public API narrowing, and out of scope.

The practical consequence is benign: the compio stream's public auto-traits are unchanged, so the
"no behavioural change to the existing binding" requirement is met more strictly than planned.

## Where the two streams diverge, and why

Every divergence below is forced by the async model, not chosen for convenience.

### A write means "accepted by TLS", not "delivered"

The compio stream reports a plaintext count only once the corresponding ciphertext has reached the
transport. The tokio stream cannot make that promise, because tokio documents
`AsyncWriteExt::write` as cancel-safe: if it is dropped while pending, *no data was written*. And
`AsyncWrite::poll_write`'s contract states that `Poll::Pending` means nothing was consumed.

Holding the plaintext count back until delivery would require returning `Pending` after OpenSSL had
already consumed the caller's buffer, which breaks that guarantee. So `poll_write` returns once
`SSL_write_ex` accepts, and `poll_flush`/`poll_shutdown` are the delivery boundaries.

Delivery is nonetheless *attempted* on every write, and any ciphertext left over is drained by the
next operation in **either** direction. That second part matters: without it, the extremely common
`write_all(...).await` followed by `read(...).await` would deadlock whenever the transport went
pending on the final chunk, because nothing would ever push the remaining ciphertext out. The read
path therefore drains the write-side backlog. `write_all_then_read_round_trip_without_explicit_flush_when_transport_stalls`
covers exactly this, with the transport stalling part-way through a record.

### The decision to park is made before OpenSSL is called

Once `SSL_write_ex` returns `WANT_READ`/`WANT_WRITE`, OpenSSL records a retry obligation and
requires the *identical* buffer next time. Presenting a different one is not a soft failure but a
session-killing `SSL_ERROR_SSL` with reason `bad write retry` — measured, not assumed.

A readiness-based pump has no way to guarantee the next poll carries the same buffer. So the write
path decides whether to park *before* entering OpenSSL:

1. Reject a pre-handshake call, then surface any latched transport error, then short-circuit an
   empty slice.
2. Collect engine output and drain all previously buffered ciphertext.
3. If any remains because the transport is pending, register the write waiter and return `Pending`
   **without calling `SSL_write_ex`**.
4. Only with both the backlog and the BIO pair empty, offer at most one record.
5. Collect the resulting ciphertext, attempt a best-effort drain, and return the accepted count.

This bounds caller-funded ciphertext to a single record and makes "pending consumed nothing"
structural rather than a matter of care. A debug assertion checks no pending return leaves a retry
owed.

Two arms of step 5 are worth naming. `SSL_write_ex` can return `Done(0)` for a *non-empty* slice
when the peer's `close_notify` is observed on the write path, with the retry flag armed; that is
treated as a terminal closed-session condition rather than a zero-length success, because a
zero-length success would violate the "a non-empty write never reports zero" rule and the owed
retry length could not be reconstructed later. Separately, a post-handshake `NeedsInbound` on the
write path — which renegotiation or a TLS 1.3 `KeyUpdate` would produce — terminates the write
direction. That is the concrete caller-visible cost of deferring those features; reads, flush and
shutdown continue to work so the peer is not left truncated.

### Waker ownership is handed back explicitly

A transport typically retains **one** waker per direction. `tokio::io::split` serialises polls
behind a lock and releases it on return, so a reader and a writer genuinely interleave.

That creates a hazard. When the read path drains the write-side backlog and the transport returns
`Pending`, the reader's waker overwrites the writer's in the transport's single write slot. If the
read future is then dropped — by a timeout, say — the transport later wakes a dead task and a
writer parked in `poll_write` sleeps forever.

So whenever the read path polls the transport's write side and gets `Pending`, it wakes the stored
write waiter before returning, handing registration ownership back. The writer re-polls,
re-registers, and progress resumes. `tests/tokio_wakers.rs` proves this with two explicit waker
schedules and a dropped-reader regression test; removing the hand-back makes two of them fail.

The complementary rule prevents a wake storm: the "wake both directions" rule fires only on
*observable* progress — bytes moved, EOF observed, or a lifecycle transition — never
unconditionally on poll exit. A poll that achieves nothing wakes nothing, which is asserted
directly.

### The handshake must be explicit

`poll_read` and `poll_write` refuse to run before `connect()` or `accept()` has completed, with a
distinct `Error::HandshakeRequired` that is not one of the five operational classifications. The
role cannot be inferred from a bare `Ssl`, so starting a handshake implicitly would mean guessing.
The refusal touches nothing: zero transport polls and zero bytes, asserted by instrumentation.

### Half-shutdown is transport-determined

Shutting the write side down leaves reads working *if the underlying transport's own write
shutdown preserves its read direction*. Both `tokio::net::TcpStream` and the in-memory duplex do
(`TcpStream::poll_shutdown` calls `shutdown(Write)`), and both are tested. A transport whose
shutdown closes both directions gets that behaviour instead; this is not something the stream can
promise on a transport's behalf.

### Errors cross as `std::io::Error`

The tokio traits return `std::io::Error`, so the crate's classification is preserved as the boxed
payload and recovered with `Error::downcast_io`. `ErrorKind` alone cannot distinguish a TLS
protocol failure from a certificate rejection. Errors are wrapped exactly once — double-wrapping
would break the downcast.

## Buffers

| Buffer | Size | Purpose |
|---|---|---|
| BIO pair, each direction | `PAIR_BUF` = 65,536 | bounded handoff between OpenSSL and the pump |
| Ciphertext backlog | ceiling `OUTBOUND_LIMIT` = 65,536 | ciphertext produced but not yet accepted by the transport |
| Transport read scratch | `CIPHER_CHUNK` = 16,384 | staging for inbound ciphertext |

One `SSL_write_ex` accepts at most `MAX_RECORD` = 16,384 plaintext bytes, producing 16,406
ciphertext bytes (measured). Because admission requires both the backlog and the pair to be empty,
the backlog holds at most one record after any admitted write. `OUTBOUND_LIMIT` is the structural
ceiling that guarantees a completely full pair can always be absorbed — asserted at compile time to
be at least `PAIR_BUF` — not the expected occupancy.

Caller buffers are never handed to the transport, and are never held across a poll return.

## Test map

| Area | Where |
|---|---|
| OpenSSL state machine, in memory | `src/engine.rs` unit tests |
| BIO pair bindings and bounds | `src/ffi.rs` unit tests |
| Error classification | `src/error.rs` unit tests |
| tokio transport and its fault hooks | `tests/tokio_transport.rs` |
| End-to-end TLS, deterministic | `tests/tokio_in_memory.rs` |
| Waker schedules and cancellation hand-back | `tests/tokio_wakers.rs` |
| End-to-end TLS over a real socket | `tests/tokio_tcp.rs` |
| Interoperability with `tokio-openssl` | `tests/tokio_interop.rs` |

The in-memory transport is the primary suite. It provides per-call read and write caps, a
reopenable write gate, a byte budget that strands a record part-way, injectable one-shot read and
write errors, truncation without `close_notify`, half-close on shutdown, per-direction waker slots,
poll and byte counters, an ordered event log, and drop observation. `tokio::io::duplex` offers none
of these. Timeouts are failure detectors only — no test sleeps for synchronisation.

## Parity with the compio suite

Behavioural coverage is mirrored. Rows marked *divergent* assert a deliberately different result.

| Behaviour | compio | tokio | |
|---|---|---|---|
| Handshake over a handle-free transport | `handshake_completes_over_a_transport_with_no_handle` | `explicit_handshake_completes_in_both_roles` | divergent — tokio refuses an implicit handshake |
| Round trip, both directions | `round_trips_in_both_directions` | `small_and_multi_record_payloads_round_trip_in_both_directions` | equivalent |
| Payload spanning many records | `round_trips_a_payload_spanning_many_records` | `small_and_multi_record_payloads_round_trip_in_both_directions` | equivalent |
| Small read buffer leaves a remainder | `small_read_buffer_leaves_the_remainder` | `a_small_buffer_leaves_the_remainder_for_the_next_read` | equivalent |
| Oversized write reports a partial count | `oversized_write_reports_a_partial_count` | `an_oversized_write_reports_one_record_and_an_empty_write_is_a_no_op` | equivalent |
| Short transport writes | `survives_short_transport_writes` | `transport_writes_truncated_to_a_few_bytes_still_deliver_every_record` | equivalent |
| Fragmented delivery | `survives_fragmented_delivery` | `reads_fragmented_below_a_record_deliver_intact_plaintext` | equivalent |
| Empty buffers are no-ops | `empty_buffers_are_no_ops` | `an_empty_buffer_after_the_handshake_is_a_no_op` | equivalent |
| Clean close reads as EOF, repeatedly | `clean_close_reads_as_end_of_stream_repeatedly` | `peer_closure_reads_as_sticky_end_of_stream` | equivalent |
| Double close succeeds | `double_close_succeeds` | `repeated_shutdown_succeeds_without_a_second_close_notify` | equivalent |
| Write after close is closed | `write_after_close_is_reported_as_closed` | `a_write_after_closure_is_classified_as_a_closed_session` | equivalent |
| Trait shutdown performs a TLS close | `trait_shutdown_performs_a_tls_close` | `shutdown_sends_close_notify_and_the_peer_sees_sticky_end_of_stream` | equivalent |
| Truncation distinct from clean EOF | `truncation_is_distinct_from_clean_end_of_stream` | `truncation_is_distinct_from_a_clean_end_of_stream` | equivalent |
| Untrusted certificate fails | `untrusted_certificate_fails_verification` | `an_untrusted_certificate_fails_the_handshake_by_value` | equivalent |
| Transport failure classified | `transport_failure_is_classified_as_transport` | `every_operational_classification_is_recovered_by_value` | equivalent |
| Handshake transport failure | `transport_failure_during_handshake_is_classified` | `provoke_transport_failure` | equivalent |
| Peer disconnect during server handshake | `peer_disconnect_during_server_handshake_is_unexpected_eof` | `provoke_unexpected_eof` | equivalent |
| `into_inner` recovers an idle transport | `into_inner_recovers_the_transport_when_idle` | `into_inner_returns_an_idle_transport` | equivalent |
| `into_inner` refuses with work outstanding | `into_inner_refuses_while_an_operation_is_in_flight` | `into_inner_refuses_with_queued_ciphertext_and_returns_the_intact_stream` | divergent — tokio holds no in-flight op, so the refusal is about queued ciphertext |
| Abandoned read leaves the session usable | `abandoned_read_leaves_the_session_usable` | `a_cancelled_pending_read_loses_no_plaintext` | divergent — tokio loses no plaintext at all; compio forfeits the buffer |
| Abandoned write, session stays correct | `abandoned_write_then_read_keeps_the_session_correct` | `a_cancelled_pending_write_delivers_none_of_its_own_plaintext` | divergent — tokio delivers *nothing*; compio may have committed a prefix |
| Abandoned write then flush settles it | `abandoned_write_then_flush_settles_it` | `a_gated_transport_accepts_the_write_but_delivers_only_after_flush` | divergent — see the delivery-boundary section |
| Abandoned write then close sends close_notify | `abandoned_write_then_close_still_sends_close_notify` | `shutdown_after_a_closed_latch_still_delivers_one_close_notify` | equivalent |
| Close idempotent after a rejected write | `close_stays_idempotent_after_a_rejected_write` | `shutdown_after_a_closed_latch_still_delivers_one_close_notify` | equivalent |
| Repeated cancellation stays sound | `repeated_cancellation_keeps_the_session_sound` | `a_cancelled_pending_read_loses_no_plaintext` | equivalent |
| Drop without close neither panics nor blocks | `dropping_without_close_neither_panics_nor_blocks` | `dropping_without_shutdown_neither_blocks_nor_leaks_the_transport` | equivalent |
| Drop with an operation in flight | `dropping_with_an_operation_in_flight_neither_panics_nor_blocks` | — | **exception**: tokio stores no in-flight operation, so the state cannot exist |
| TLS over a real socket | `handshake_and_round_trip_over_tcp` | `handshake_and_round_trip_over_tcp` | equivalent |

Rows with no compio counterpart, because they test behaviour the completion model does not have:
the waker schedules and dropped-reader hand-back (`tests/tokio_wakers.rs`), the pre-handshake
refusal, the deferred-delivery round trip, the read-path skip guard, the one-record backlog bound,
and half-shutdown over both transports.

## Acceptance coverage

| Story | Covered by |
|---|---|
| P1 client from tokio | `explicit_handshake_completes_in_both_roles`, `round_trip`, `an_untrusted_certificate_fails_the_handshake_by_value`, `read_before_the_handshake_is_refused_without_touching_the_transport` |
| P2 server-side termination | `explicit_handshake_completes_in_both_roles`, `small_and_multi_record_payloads_round_trip_in_both_directions`, `provoke_unexpected_eof` |
| P3 transport without a handle | `tests/tokio_in_memory.rs` throughout, plus `tests/tokio_tcp.rs` for the same type over a socket |
| P4 concurrent read and write | `split_halves_exchange_multiple_records_from_separate_tasks`, both waker schedules, `a_half_shutdown_stream_keeps_reading_until_the_peer_closes` |
| P5 clean close | `shutdown_sends_close_notify_and_the_peer_sees_sticky_end_of_stream`, `repeated_shutdown_succeeds_without_a_second_close_notify`, `truncation_is_distinct_from_a_clean_end_of_stream` |
| P6 abandoning an operation | `a_cancelled_pending_write_delivers_none_of_its_own_plaintext`, `a_cancelled_pending_read_loses_no_plaintext` |
| P7 interoperability | `this_crate_as_client_against_a_tokio_openssl_server`, `this_crate_as_server_against_a_tokio_openssl_client` |
| P8 selecting one runtime | CI dependency-graph and feature-reachability assertions |

The interoperability peer is `tokio-openssl`: an independently written *stream wrapper* over the
same TLS library. It validates this crate's pump and public behaviour against a separate code path.
It is not evidence of interoperability with a different TLS implementation, which remains deferred.

## Not implemented

- Renegotiation and post-handshake key update. A `KeyUpdate` arriving on the write path terminates
  the write direction, as described above. Neither `SSL_renegotiate` nor `SSL_key_update` is
  exposed by the Rust OpenSSL bindings, so this needs further FFI.
- Interoperability with a TLS library other than OpenSSL.
- Sanitizer-instrumented runs.

## Performance

Out of scope for this work, deliberately, and no performance claim is made anywhere in it. The
experiment was about whether one state machine could drive both async models correctly.

Routing ciphertext through a BIO pair costs one more copy than attaching OpenSSL to a socket
directly. [ZeroCopy.md](ZeroCopy.md) has the copy accounting and the analysis of which of those
copies can be removed. Notably that analysis applies *only* to the readiness-based side: eliminating
the drain copy requires handing the transport a pointer into the BIO's ring buffer, which is safe
when the kernel copies before the call returns, and unsound for a completion-based runtime that
holds the buffer past submission. Pursuing it would be separate, measured work.
