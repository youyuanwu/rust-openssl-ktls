//! This crate provides KTLS compatible openssl SslStream implementation.
//!
//! We cannot use the openssl::ssl::SslStream directly here
//! because its BIOs are not compatible with KTLS.
//! The BIO blocks the ctrl messages that needs to be passed down to
//! the next BIO layer.

// Only support linux
// Raw fd does not exist on windows.
#![cfg(target_os = "linux")]

pub mod ffi;

pub mod option;
mod stream;
pub use stream::SslStream;

#[cfg(feature = "tokio")]
pub mod tokio_stream;
#[cfg(feature = "tokio")]
pub type TokioSslStream = tokio_stream::SslStream;

pub mod error;
