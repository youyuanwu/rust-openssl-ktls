use std::{error, ffi::c_int, fmt, io};

use openssl::{error::ErrorStack, ssl::ErrorCode};

#[derive(Debug)]
pub(crate) enum InnerError {
    Io(io::Error),
    Ssl(ErrorStack),
}

/// An SSL error.
#[derive(Debug)]
pub struct Error {
    pub(crate) code: ErrorCode,
    pub(crate) cause: Option<InnerError>,
}

impl Error {
    pub fn code(&self) -> ErrorCode {
        self.code
    }

    pub fn io_error(&self) -> Option<&io::Error> {
        match self.cause {
            Some(InnerError::Io(ref e)) => Some(e),
            _ => None,
        }
    }

    pub fn into_io_error(self) -> Result<io::Error, Error> {
        match self.cause {
            Some(InnerError::Io(e)) => Ok(e),
            _ => Err(self),
        }
    }

    pub fn ssl_error(&self) -> Option<&ErrorStack> {
        match self.cause {
            Some(InnerError::Ssl(ref e)) => Some(e),
            _ => None,
        }
    }

    pub(crate) fn make(ret: c_int, ssl: &openssl::ssl::SslRef) -> Self {
        use foreign_types_shared::ForeignTypeRef;
        let code = unsafe { ErrorCode::from_raw(openssl_sys::SSL_get_error(ssl.as_ptr(), ret)) };

        let cause = match code {
            ErrorCode::SSL => Some(InnerError::Ssl(ErrorStack::get())),
            ErrorCode::SYSCALL => {
                let errs = ErrorStack::get();
                if errs.errors().is_empty() {
                    // get last error from io
                    let e = std::io::Error::last_os_error();
                    Some(InnerError::Io(e))
                } else {
                    Some(InnerError::Ssl(errs))
                }
            }
            ErrorCode::ZERO_RETURN => None,
            ErrorCode::WANT_READ | ErrorCode::WANT_WRITE => {
                // get last error from io
                let e = std::io::Error::last_os_error();
                Some(InnerError::Io(e))
            }
            _ => None,
        };

        Error { code, cause }
    }

    pub fn from_io(e: io::Error) -> Self {
        Error {
            code: ErrorCode::SYSCALL,
            cause: Some(InnerError::Io(e)),
        }
    }
}

impl From<ErrorStack> for Error {
    fn from(e: ErrorStack) -> Error {
        Error {
            code: ErrorCode::SSL,
            cause: Some(InnerError::Ssl(e)),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.code {
            ErrorCode::ZERO_RETURN => fmt.write_str("the SSL session has been shut down"),
            ErrorCode::WANT_READ => match self.io_error() {
                Some(_) => fmt.write_str("a nonblocking read call would have blocked"),
                None => fmt.write_str("the operation should be retried"),
            },
            ErrorCode::WANT_WRITE => match self.io_error() {
                Some(_) => fmt.write_str("a nonblocking write call would have blocked"),
                None => fmt.write_str("the operation should be retried"),
            },
            ErrorCode::SYSCALL => match self.io_error() {
                Some(err) => write!(fmt, "{err}"),
                None => fmt.write_str("unexpected EOF"),
            },
            ErrorCode::SSL => match self.ssl_error() {
                Some(e) => write!(fmt, "{e}"),
                None => fmt.write_str("OpenSSL error"),
            },
            _ => write!(fmt, "unknown error code {}", self.code.as_raw()),
        }
    }
}

impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self.cause {
            Some(InnerError::Io(ref e)) => Some(e),
            Some(InnerError::Ssl(ref e)) => Some(e),
            None => None,
        }
    }
}
