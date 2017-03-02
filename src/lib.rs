//! Crate providing cross-site request forgery (CSRF) protection for Iron.
//!
//! ## Overview
//!
//! `iron_csrf` is used as `iron::AroundMiddleware` that checks all requests with the HTTP method
//! POST, PUT, PATCH, and DELETE for the presence of a CSRF token, and it generates tokens that can
//! be  used inside the application for use when generating the `Response`.
//!
//! ## Hello, CSRF.
//!
//! The following is a simple server that prints the contents of the CSRF token. It  demonstrates
//! how to wrap the middleware and access the string contents of the `CsrfToken`.
//!
//! ```
//! extern crate iron;
//! extern crate iron_csrf;
//!
//! use iron::AroundMiddleware;
//! use iron::prelude::*;
//! use iron::status;
//! use iron_csrf::{CsrfProtectionMiddleware, CsrfToken, CsrfConfig,
//!     ChaCha20Poly1305CsrfProtection};
//!
//! fn main() {
//!     // Make a key
//!     // Note: You will want to load a persistent key in production
//!     // TODO
//!
//!     // Set up CSRF protection with the default config
//!     let password = b"correct horse battery staple";
//!     let protect = ChaCha20Poly1305CsrfProtection::from_password(password).unwrap();
//!     let config = CsrfConfig::default();
//!     let middleware = CsrfProtectionMiddleware::new(protect, config);
//!
//!     // Set up routes
//!     let handler = middleware.around(Box::new(index));
//!
//!     // Make and start the server
//!     Iron::new(handler); //.http("localhost:8080").unwrap();
//! }
//!
//! fn index(request: &mut Request) -> IronResult<Response> {
//!     let token = request.extensions.get::<CsrfToken>().unwrap();
//!     let msg = format!("Hello, CSRF Token: {}", token.b64_string());
//!     Ok(Response::with((status::Ok, msg)))
//! }
//!
//! ```
//!
//! ## Protection
//! There are three ways that `iron_csrf` checks for the presence of a CSRF token.
//!
//! - The field `csrf-token` in requests with `Content-Type: application/x-www-form-urlencoded`
//! - The query parameter `csrf-token`
//! - The header `X-CSRF-Token`
//!
//! The selection is done short circuit, so the first present wins, and retrieval on fails if the
//! token is not present in any of the fields.
//!
//! Tokens have a time to live (TTL) that defaults to 3600 seconds. If a token is stale, validation
//! will fail.
//!
//! In the provided implementations, tokens are cryptographically signed, so tampering with a token
//! or its signature will cause the validation to fail. Validation failures will return a `403
//! Forbidden`.
//!
//! Signatures and other data needed for validation are stored in a cookie that is sent to the user
//! via the `Set-Cookie` header.
//!
//! ## Unsupported: `multipart/form-data`
//! Because of how the `iron` library handles middleware and streaming requests, it is not possible
//! (or at least not feasible) at this time to intercept requests and check the multipart forms.

extern crate chrono;
extern crate cookie;
extern crate crypto;
#[cfg(test)]
extern crate env_logger;
#[macro_use]
extern crate hyper;
extern crate iron;
#[cfg(test)]
extern crate iron_test;
#[macro_use]
extern crate log;
extern crate protobuf;
extern crate ring;
extern crate rustc_serialize;
extern crate time;
extern crate untrusted;
extern crate urlencoded;
#[cfg(test)]
extern crate urlencoding;

mod core;
pub mod error;
mod transport;

pub use core::*;
