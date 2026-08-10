//! Fixtures shared by the integration tests.
//!
//! Every test target links this whole module, so the runtime-specific
//! transports are gated by the feature that supplies their traits. `certs` is
//! runtime-agnostic and always available.

pub mod certs;
#[cfg(feature = "compio")]
pub mod memory;
#[cfg(feature = "tokio")]
pub mod tokio_memory;
