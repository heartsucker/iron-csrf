//! Crate providing cross-site request forgery (CSRF) protection for Iron.
//!
//! ## Overview
//!
//! `iron_csrf` is used as `iron::BeforeMiddleware` that checks all requests with
//! the HTTP method POST, PUT, PATCH, and DELETE for the presence of a CSRF token,
//! and it generates tokens that can be used inside the application for use when
//! generating the `Response`.
//!
//! ## Hello, world.
//!
//! The following is a simple server that prints the contents of the CSRF token. It
//! demonstrates how to chain the middleware and access the string contents of the
//! `CsrfToken`.
//!
//! ```
//! extern crate iron;
//! extern crate iron_csrf;
//! extern crate ring;
//!
//! use iron::prelude::*;
//! use iron::status;
//! use iron_csrf::{CsrfProtectionMiddleware, HmacCsrfProtection, CsrfToken};
//! use ring::{digest, hmac};
//! use ring::rand::SystemRandom;
//!
//! fn main() {
//!     // Make a key
//!     // Note: You will want to load a persistent key in production
//!     let rng = SystemRandom::new();
//!     let key = hmac::SigningKey::generate(&digest::SHA512, &rng).unwrap();
//!
//!     // Set up CSRF protection with tokens with a short TTL
//!     let protect = HmacCsrfProtection::new(key, Some(300));
//!     let middleware = CsrfProtectionMiddleware::new(protect);
//!
//!     // Set up routes
//!     let mut chain = Chain::new(|request: &mut Request| {
//!         let token = request.extensions.get::<CsrfToken>().unwrap();
//!         let msg = format!("Hello, CSRF Token: {}", token.b64_string());
//!         Ok(Response::with((status::Ok, msg)))
//!     });
//!     chain.link_before(middleware);
//!
//!     // Make and start the server
//!     Iron::new(chain); //.http("localhost:8080").unwrap();
//! }
//!
//! ```
//!
//! ## Protection
//! There are three ways that `iron_csrf` checks for the presence of a CSRF token.
//!
//! - The field `csrf-token` in requests with `Content-Type: multipart/form-data`
//! - The query parameter `csrf-token`
//! - The header `X-CSRF-Token`
//!
//! The selection is done short circuit, so the first present wins, and retrieval
//! only fails if the token is not present in any of the fields.
//!
//! Tokens have a time to live (TTL) that defaults to 3600 seconds. If a token is
//! stale, validation will fail.
//!
//! In the provided implementations, tokens are cryptographically signed, so tampering
//! with a token or its signature will cause the validation to fail.
//!
//! Validation failures will return a `403 Forbidden`.


extern crate chrono;
#[macro_use]
extern crate hyper;
extern crate iron;
extern crate protobuf;
extern crate ring;
extern crate rustc_serialize;
extern crate untrusted;
extern crate urlencoded;

mod csrf;
mod middleware;
pub mod serial;

pub use csrf::{CsrfProtection, HmacCsrfProtection, Ed25519CsrfProtection, CsrfToken};
pub use middleware::{CsrfProtectionMiddleware, XCsrfToken};
