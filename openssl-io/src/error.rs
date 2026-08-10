//! Classified errors.
//!
//! Callers must be able to tell a certificate problem from a dead connection
//! from a protocol violation *without* parsing message text, so the variants
//! below are the contract. See `Error` for what each one means.

use std::fmt;
use std::io;

use openssl::error::ErrorStack;

/// Why a TLS operation failed.
///
/// Every variant is matchable on its own; nothing here requires inspecting a
/// human-readable string.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// The TLS protocol itself failed — a bad record, an alert from the peer,
    /// an unsupported parameter.
    Tls(ErrorStack),

    /// The peer's certificate was rejected. Carries OpenSSL's verify result
    /// code so the specific reason is available without string matching.
    Verification {
        /// OpenSSL's `X509_V_ERR_*` code.
        code: i32,
        /// The accompanying error stack, if OpenSSL queued one.
        stack: ErrorStack,
    },

    /// The underlying transport failed.
    Transport(io::Error),

    /// The transport ended without a TLS `close_notify`.
    ///
    /// Distinct from a clean end-of-stream, which is reported as a zero-length
    /// read rather than an error. A truncated connection may indicate an
    /// attacker cutting the stream short, so it must not be mistaken for an
    /// orderly shutdown.
    UnexpectedEof,

    /// The session has been closed and cannot carry more application data.
    Closed,
}

impl Error {
    /// Build a `Verification` error from a session whose handshake failed
    /// certificate checking.
    pub(crate) fn verification(code: i32) -> Self {
        Error::Verification {
            code,
            stack: ErrorStack::get(),
        }
    }

    /// Build a `Tls` error from OpenSSL's current error stack.
    pub(crate) fn tls() -> Self {
        Error::Tls(ErrorStack::get())
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Tls(_) => write!(f, "TLS protocol error"),
            Error::Verification { code, .. } => {
                write!(f, "certificate verification failed (code {code})")
            }
            Error::Transport(e) => write!(f, "transport error: {e}"),
            Error::UnexpectedEof => {
                write!(f, "transport closed before TLS close_notify (truncated)")
            }
            Error::Closed => write!(f, "session is closed"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Tls(e) => Some(e),
            Error::Verification { stack, .. } => Some(stack),
            Error::Transport(e) => Some(e),
            Error::UnexpectedEof | Error::Closed => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Transport(e)
    }
}

impl From<Error> for io::Error {
    /// Map to the closest `io::ErrorKind` so the classification survives the
    /// conversion the `compio_io` traits force on us.
    fn from(e: Error) -> Self {
        let kind = match &e {
            Error::UnexpectedEof => io::ErrorKind::UnexpectedEof,
            Error::Closed => io::ErrorKind::NotConnected,
            Error::Verification { .. } => io::ErrorKind::InvalidData,
            Error::Tls(_) => io::ErrorKind::InvalidData,
            Error::Transport(inner) => inner.kind(),
        };
        io::Error::new(kind, e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn variants_are_distinguishable_without_message_text() {
        let cases: Vec<Error> = vec![
            Error::tls(),
            Error::verification(20),
            Error::Transport(io::Error::from(io::ErrorKind::ConnectionReset)),
            Error::UnexpectedEof,
            Error::Closed,
        ];

        // Matching on the value alone must be enough to tell them apart.
        let mut seen = 0;
        for e in &cases {
            seen |= match e {
                Error::Tls(_) => 1,
                Error::Verification { .. } => 2,
                Error::Transport(_) => 4,
                Error::UnexpectedEof => 8,
                Error::Closed => 16,
            };
        }
        assert_eq!(seen, 31, "every variant should be reachable and distinct");
    }

    #[test]
    fn verification_exposes_its_code() {
        match Error::verification(18) {
            Error::Verification { code, .. } => assert_eq!(code, 18),
            other => panic!("expected Verification, got {other:?}"),
        }
    }

    #[test]
    fn io_conversion_preserves_classification() {
        let io_err: io::Error = Error::UnexpectedEof.into();
        assert_eq!(io_err.kind(), io::ErrorKind::UnexpectedEof);

        let io_err: io::Error = Error::Closed.into();
        assert_eq!(io_err.kind(), io::ErrorKind::NotConnected);

        let io_err: io::Error =
            Error::Transport(io::Error::from(io::ErrorKind::ConnectionReset)).into();
        assert_eq!(io_err.kind(), io::ErrorKind::ConnectionReset);

        // The original classified error survives as the source, so a caller
        // that wants the detail can still recover it.
        let io_err: io::Error = Error::verification(20).into();
        let src = io_err
            .get_ref()
            .and_then(|e| e.downcast_ref::<Error>())
            .expect("classified error should survive as the io::Error payload");
        assert!(matches!(src, Error::Verification { code: 20, .. }));
    }
}
