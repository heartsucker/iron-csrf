//! Module containing the CSRF error types.
//!

use std::error::Error;
use std::fmt;

use iron::prelude::*;
use iron::status;

/// An `enum` of all CSRF related errors.
#[derive(Debug)]
pub enum CsrfError {
    InternalError,
    ValidationFailure,
}

impl Error for CsrfError {
    fn description(&self) -> &str {
        match *self {
            CsrfError::InternalError => "Internal Server Error (CSRF)",
            CsrfError::ValidationFailure => "Forbidden: CSRF Validation Failed",
        }
    }
}

impl fmt::Display for CsrfError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self)
    }
}

impl From<CsrfError> for IronError {
    fn from(err: CsrfError) -> IronError {
        IronError {
            response: Response::with((status::Forbidden, format!("{}", err))),
            error: Box::new(err),
        }
    }
}

pub enum CsrfConfigError {
    // TODO add more of these
    InvalidTtl,
    NoProtectedMethods,
    Unspecified,
}
