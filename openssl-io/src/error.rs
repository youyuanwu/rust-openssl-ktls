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
///
/// [`Error::Tls`], [`Error::Verification`], [`Error::Transport`],
/// [`Error::UnexpectedEof`], and [`Error::Closed`] are the five *operational*
/// classifications: something went wrong while carrying the session.
/// [`Error::HandshakeRequired`] is not one of them — it reports that the caller
/// sequenced its own API calls wrongly, before any I/O was attempted.
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

    /// A read or a write was attempted before a handshake had completed.
    ///
    /// This is a *caller-sequencing fault*, not one of the five operational
    /// classifications above: nothing failed on the wire, and by the time it is
    /// reported no caller plaintext has been consumed and no transport read or
    /// write has been performed. Handshaking is never started implicitly,
    /// because the role — initiating or accepting — cannot be inferred from a
    /// read or a write.
    ///
    /// Call the stream's explicit connect or accept operation first, then retry.
    /// The marker is matchable by value, both directly and — after the
    /// conversion the async I/O traits force — through
    /// [`Error::downcast_io`].
    HandshakeRequired,
}

impl Error {
    /// Recover this crate's classification from an [`io::Error`].
    ///
    /// The async I/O traits force every failure through `std::io::Error`, and
    /// `io::ErrorKind` alone is too coarse to tell a certificate rejection from
    /// a protocol violation. Every `io::Error` this crate produces therefore
    /// carries the original [`Error`] as its boxed payload, and this helper is
    /// the documented way back to it — no message text is ever parsed.
    ///
    /// Returns `None` for an `io::Error` that did not come from this crate.
    ///
    /// ```
    /// use std::io;
    /// use openssl_io::Error;
    ///
    /// let io_err = io::Error::from(Error::HandshakeRequired);
    /// assert_eq!(io_err.kind(), io::ErrorKind::InvalidInput);
    /// assert!(matches!(
    ///     Error::downcast_io(&io_err),
    ///     Some(Error::HandshakeRequired)
    /// ));
    ///
    /// // An unrelated error has no classification to recover.
    /// assert!(Error::downcast_io(&io::Error::from(io::ErrorKind::TimedOut)).is_none());
    /// ```
    ///
    /// # Convert exactly once
    ///
    /// The round-trip holds through a *single* conversion. Wrapping an
    /// already-converted value again — `io::Error::other(io_err)` — buries the
    /// classification one layer deeper, and this helper then returns `None`.
    /// Adapters must hand out the result of one `Error` → `io::Error`
    /// conversion unchanged.
    ///
    /// ```
    /// use std::io;
    /// use openssl_io::Error;
    ///
    /// let once = io::Error::from(Error::Closed);
    /// assert!(Error::downcast_io(&once).is_some());
    ///
    /// let twice = io::Error::other(once);
    /// assert!(Error::downcast_io(&twice).is_none(), "do not double-wrap");
    /// ```
    pub fn downcast_io(error: &io::Error) -> Option<&Error> {
        error.get_ref()?.downcast_ref::<Error>()
    }

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
            Error::HandshakeRequired => {
                write!(f, "handshake must complete before reading or writing")
            }
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Tls(e) => Some(e),
            Error::Verification { stack, .. } => Some(stack),
            Error::Transport(e) => Some(e),
            Error::UnexpectedEof | Error::Closed | Error::HandshakeRequired => None,
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
    /// conversion the async I/O traits force on us.
    ///
    /// The `Error` itself is preserved as the boxed payload, so the exact
    /// classification remains recoverable with [`Error::downcast_io`]. Apply
    /// this conversion exactly once: re-wrapping the result loses that route.
    fn from(e: Error) -> Self {
        let kind = match &e {
            Error::UnexpectedEof => io::ErrorKind::UnexpectedEof,
            Error::Closed => io::ErrorKind::NotConnected,
            Error::Verification { .. } => io::ErrorKind::InvalidData,
            Error::Tls(_) => io::ErrorKind::InvalidData,
            Error::Transport(inner) => inner.kind(),
            // A sequencing fault is a misuse of the API, not bad data on the
            // wire, so it maps to the "you asked for something invalid" kind.
            Error::HandshakeRequired => io::ErrorKind::InvalidInput,
        };
        io::Error::new(kind, e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every variant, so a new one cannot be added without being covered here.
    fn all_variants() -> Vec<Error> {
        vec![
            Error::tls(),
            Error::verification(20),
            Error::Transport(io::Error::from(io::ErrorKind::ConnectionReset)),
            Error::UnexpectedEof,
            Error::Closed,
            Error::HandshakeRequired,
        ]
    }

    #[test]
    fn variants_are_distinguishable_without_message_text() {
        // Matching on the value alone must be enough to tell them apart.
        let mut seen = 0;
        for e in &all_variants() {
            seen |= match e {
                Error::Tls(_) => 1,
                Error::Verification { .. } => 2,
                Error::Transport(_) => 4,
                Error::UnexpectedEof => 8,
                Error::Closed => 16,
                Error::HandshakeRequired => 32,
            };
        }
        assert_eq!(seen, 63, "every variant should be reachable and distinct");
    }

    /// The sequencing marker is a caller fault, not an operational failure, so
    /// it must not be confusable with any of the five.
    #[test]
    fn handshake_required_differs_from_every_operational_classification() {
        for e in &all_variants() {
            let is_marker = matches!(e, Error::HandshakeRequired);
            let is_operational = matches!(
                e,
                Error::Tls(_)
                    | Error::Verification { .. }
                    | Error::Transport(_)
                    | Error::UnexpectedEof
                    | Error::Closed
            );
            assert_ne!(
                is_marker, is_operational,
                "{e:?} must be exactly one of marker or operational"
            );
        }
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

        let io_err: io::Error = Error::verification(20).into();
        assert_eq!(io_err.kind(), io::ErrorKind::InvalidData);

        let io_err: io::Error = Error::tls().into();
        assert_eq!(io_err.kind(), io::ErrorKind::InvalidData);

        let io_err: io::Error = Error::HandshakeRequired.into();
        assert_eq!(io_err.kind(), io::ErrorKind::InvalidInput);

        // The original classified error survives as the source, so a caller
        // that wants the detail can still recover it.
        let io_err: io::Error = Error::verification(20).into();
        let src = io_err
            .get_ref()
            .and_then(|e| e.downcast_ref::<Error>())
            .expect("classified error should survive as the io::Error payload");
        assert!(matches!(src, Error::Verification { code: 20, .. }));
    }

    /// `ErrorKind` alone is too coarse to classify with, but it must still say
    /// something useful: no variant may collapse to the catch-all `Other`.
    #[test]
    fn io_conversion_yields_a_meaningful_kind() {
        for e in all_variants() {
            let debug = format!("{e:?}");
            let kind = io::Error::from(e).kind();
            assert_ne!(kind, io::ErrorKind::Other, "{debug} degraded to Other");
        }
    }

    /// The documented public recovery route, for every variant.
    #[test]
    fn downcast_io_recovers_every_classification() {
        for e in all_variants() {
            let expected = format!("{e:?}");
            let io_err = io::Error::from(e);
            let recovered =
                Error::downcast_io(&io_err).expect("classification should be recoverable");
            assert_eq!(format!("{recovered:?}"), expected);
        }
    }

    #[test]
    fn downcast_io_ignores_foreign_errors() {
        let foreign = io::Error::from(io::ErrorKind::TimedOut);
        assert!(Error::downcast_io(&foreign).is_none());

        let foreign = io::Error::other("something else entirely");
        assert!(Error::downcast_io(&foreign).is_none());
    }

    /// Trait adapters convert once and hand the result out unchanged. Wrapping
    /// an already-converted error buries the payload a layer deeper and breaks
    /// the direct downcast, which is why the rule exists.
    #[test]
    fn double_wrapping_destroys_the_recovery_route() {
        let once = io::Error::from(Error::Closed);
        assert!(Error::downcast_io(&once).is_some());
        assert_eq!(once.kind(), io::ErrorKind::NotConnected);

        let twice = io::Error::other(once);
        assert!(
            Error::downcast_io(&twice).is_none(),
            "adapters must not re-wrap an already converted io::Error"
        );
        // The meaningful kind is lost too.
        assert_eq!(twice.kind(), io::ErrorKind::Other);
    }
}
