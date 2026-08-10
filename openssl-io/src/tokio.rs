//! The public readiness-based TLS stream for the [tokio] runtime.
//!
//! # Status
//!
//! **Not yet implemented.** This module is a placeholder: selecting the `tokio`
//! feature currently compiles the shared TLS engine and the crate's error type,
//! but exposes no stream. It exists so the feature, the module path, and the
//! runtime-free dependency graph can be established and kept honest by CI
//! before any readiness pump is written.
//!
//! The eventual binding will wrap a single
//! `S: ::tokio::io::AsyncRead + ::tokio::io::AsyncWrite + Unpin` transport and
//! implement Tokio's `AsyncRead` and `AsyncWrite` over the same synchronous
//! engine the [`crate::compio`] binding drives. Its write, cancellation, split,
//! shutdown, and buffering semantics differ from the completion-based binding
//! and will be documented here rather than by analogy.
//!
//! Note that `mod tokio` shadows the `tokio` crate at this crate's root, so
//! every path to the external crate is written absolutely as `::tokio::...`,
//! here and in shared code.
//!
//! [tokio]: https://docs.rs/tokio
