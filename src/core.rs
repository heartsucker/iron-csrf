//! Module containing the core functionality for CSRF protection.

use std::collections::HashSet;
use std::str;

use chrono::Duration;
use cookie::Cookie;
use crypto::aead::{AeadEncryptor, AeadDecryptor};
use crypto::chacha20poly1305::ChaCha20Poly1305;
use crypto::scrypt::{scrypt, ScryptParams};
use iron::headers::{SetCookie, Cookie as IronCookie};
use iron::method;
use iron::middleware::{AroundMiddleware, Handler};
use iron::prelude::*;
use iron::status;
use iron::typemap;
use ring::rand::SystemRandom;
use protobuf;
use protobuf::Message;
use rustc_serialize::base64::{FromBase64, ToBase64, STANDARD};
use time;
use urlencoded::{UrlEncodedQuery, UrlEncodedBody};

use error::{CsrfError, CsrfConfigError};
use transport::{CsrfTokenTransport, CsrfCookieTransport};

/// The name of the cookie for the CSRF validation data and signature.
pub const CSRF_COOKIE_NAME: &'static str = "csrf";

/// The name of the form field for the CSRF token.
pub const CSRF_FORM_FIELD: &'static str = "csrf-token";

/// The name of the HTTP header for the CSRF token.
pub const CSRF_HEADER: &'static str = "X-CSRF-Token";

/// The name of the query parameter for the CSRF token.
pub const CSRF_QUERY_STRING: &'static str = "csrf-token";

// TODO why doesn't this show up in the docs?
/// The HTTP header for the CSRF token.
header! { (XCsrfToken, CSRF_HEADER) => [String] }

/// An encoded CSRF token.
///
// # Examples
/// ```ignore
/// use iron::Request;
/// use iron_csrf::CsrfToken;
///
/// fn get_token(request: &Request) -> String {
///     let token = request.extensions.get::<CsrfToken>().unwrap();
///     token.b64_string()
///     // CiDR/7m9X/3CVATatXBK72R7Clbvg2DwO74nO3oAO6BsYQ==
/// }
/// ```
#[derive(Eq, PartialEq, Debug)]
pub struct CsrfToken {
    bytes: Vec<u8>,
}

impl CsrfToken {
    fn new(bytes: Vec<u8>) -> Self {
        CsrfToken { bytes: bytes }
    }

    pub fn b64_string(&self) -> String {
        self.bytes.to_base64(STANDARD)
    }

    // TODO fn b64_url_safe_string
}

/// An encoded CSRF cookie.
#[derive(Debug, Eq, PartialEq)]
pub struct CsrfCookie {
    bytes: Vec<u8>,
}

impl CsrfCookie {
    fn new(bytes: Vec<u8>) -> Self {
        CsrfCookie { bytes: bytes }
    }

    /// Retrieve the CSRF token as a base64 encoded string.
    pub fn b64_string(&self) -> String {
        self.bytes.to_base64(STANDARD)
    }

    // TODO fn b64_url_safe_string
}

/// The configuation used to initialize `CsrfProtection`.
pub struct CsrfConfig {
    // TODO make this an Option
    ttl_seconds: i64,
    protected_methods: HashSet<method::Method>,
    secure_cookie: bool,
}

impl CsrfConfig {

    /// Create a new builder that is initializd with the default configuration.
    pub fn build() -> CsrfConfigBuilder {
        CsrfConfigBuilder { config: CsrfConfig::default() }
    }
}

impl Default for CsrfConfig {
    fn default() -> Self {
        let protected_methods: HashSet<method::Method> =
            vec![method::Post, method::Put, method::Patch, method::Delete]
                .iter()
                .cloned()
                .collect();
        CsrfConfig {
            ttl_seconds: 3600,
            protected_methods: protected_methods,
            secure_cookie: false,
        }
    }
}

/// A utility to help build a `CsrfConfig` in an API backwards compatible way.
pub struct CsrfConfigBuilder {
    config: CsrfConfig,
}

impl CsrfConfigBuilder {
    /// Set the TTL in seconds for CSRF cookies and tokens.
    ///
    /// Default: `3600`
    pub fn ttl_seconds(mut self, ttl_seconds: i64) -> Self {
        self.config.ttl_seconds = ttl_seconds;
        self
    }

    /// Set the HTTP methods that are require CSRF protection.
    ///
    /// Default: `POST`, `PUT`, `PATCH`, `DELETE`
    pub fn protected_methods(mut self, protected_methods: HashSet<method::Method>) -> Self {
        self.config.protected_methods = protected_methods;
        self
    }

    /// Set the `Secure` flag on the CSRF cookie. If this is set to true, then user agents will
    /// only send the cookie over HTTPS.
    ///
    /// Default: false/absent.
    pub fn secure_cookie(mut self, secure_cookie: bool) -> Self {
        self.config.secure_cookie = secure_cookie;
        self
    }

    /// Validate and build the `CsrfConfig`.
    pub fn finish(self) -> Result<CsrfConfig, CsrfConfigError> {
        let config = self.config;
        if config.ttl_seconds < 0 {
            return Err(CsrfConfigError::InvalidTtl);
        }

        if config.protected_methods.is_empty() {
            return Err(CsrfConfigError::NoProtectedMethods);
        }
        Ok(config)
    }
}

/// Base trait that allows an `iron` application to be wrapped with CSRF protection.
pub trait CsrfProtection: Sized + Send + Sync {

    /// Returns the internal representation of a CSRF token given a slice of decoded bytes.
    fn parse_token(&self, bytes: &[u8]) -> Result<CsrfTokenTransport, CsrfError>;

    /// Returns the internal representation of a CSRF cookie given a slice of decoded bytes.
    fn parse_cookie(&self, bytes: &[u8]) -> Result<CsrfCookieTransport, CsrfError>;

    /// Creates a CSRF token and cookie with the given TTL in seconds.
    fn generate_token_pair(&self, previous_token: Option<Vec<u8>>, ttl_seconds: i64) -> Result<(CsrfToken, CsrfCookie), CsrfError>;

    /// Returns whether
    fn verify_token_pair(&self, token: &CsrfTokenTransport, cookie: &CsrfCookieTransport) -> bool {
        let tokens_match = token.get_token() == cookie.get_token();
        let not_expired = cookie.get_expires() > time::precise_time_s() as u64;
        tokens_match && not_expired
    }
}

/// Uses the ChaCha20Poly1305 AEAD to provide signed, encrypted CSRF tokens and cookies.
pub struct ChaCha20Poly1305CsrfProtection {
    rng: SystemRandom,
    key: [u8; 32],
    nonce: [u8; 8],
    aad: [u8; 32],
}

impl ChaCha20Poly1305CsrfProtection {

    /// Using `scrypt` with params `n=14`, `r=8`, `p=1`, generate the key material used for the
    /// underlying ChaCha20Poly1305 AEAD.
    ///
    /// # Panics
    /// This function may panic if the underlying library fails catastrophically.
    pub fn from_password(password: &[u8]) -> Result<ChaCha20Poly1305CsrfProtection, CsrfError> {
        // TODO add check for password length

        // scrypt is *slow*, so use these params for testing
        #[cfg(test)]
        let params = ScryptParams::new(1, 8, 1);
        #[cfg(not(test))]
        let params = ScryptParams::new(14, 8, 1);

        let salt = b"iron-csrf-scrypt-salt";
        let mut out = [0; 72];
        info!("Generating key material. This may take some time.");
        scrypt(password, salt, &params, &mut out);
        info!("Key material generated.");

        let mut key = [0; 32];
        let mut nonce = [0; 8];
        let mut aad = [0; 32];

        for i in 0..32 {
            key[i] = out[i]
        }

        for i in 0..8 {
            nonce[i] = out[i + 32]
        }

        for i in 0..32 {
            aad[i] = out[i + 40]
        }

        // create this once so that if the params are bad, that panic happens during the program
        // init, not during the first request
        let _ = ChaCha20Poly1305::new(&key, &nonce, &aad);

        Ok(ChaCha20Poly1305CsrfProtection {
            rng: SystemRandom::new(),
            key: key,
            nonce: nonce,
            aad: aad,
        })
    }

    fn aead(&self) -> ChaCha20Poly1305 {
        ChaCha20Poly1305::new(&self.key, &self.nonce, &self.aad)
    }

    fn random_bytes(&self, buf: &mut [u8]) -> Result<(), CsrfError> {
        self.rng
            .fill(buf)
            .map_err(|_| {
                warn!("Failed to get random bytes");
                CsrfError::InternalError
            })
    }

    fn generate_cookie(&self, token: &[u8], ttl_seconds: i64) -> Result<CsrfCookie, CsrfError> {
        let mut aead = self.aead();
        let expires = time::precise_time_s() as u64 + ttl_seconds as u64;

        let mut cookie_unencrypted = CsrfCookieTransport::new();
        cookie_unencrypted.set_token(token.to_vec());
        cookie_unencrypted.set_expires(expires);
        let cookie_unencrypted = cookie_unencrypted.write_to_bytes()
            .map_err(|err| {
                warn!("Could not write CSRF cookie: {}", err);
                CsrfError::InternalError
            })?;
        let mut cookie_encrypted = vec![0; cookie_unencrypted.len()];
        let mut sig = vec![0; 16];
        aead.encrypt(&cookie_unencrypted, &mut cookie_encrypted, &mut sig);
        cookie_encrypted.extend(sig);

        Ok(CsrfCookie::new(cookie_encrypted))
    }

    fn generate_token(&self, token: &[u8]) -> Result<CsrfToken, CsrfError> {
        let mut aead = self.aead();

        let mut token_unencrypted = CsrfTokenTransport::new();
        token_unencrypted.set_token(token.to_vec());
        let token_unencrypted = token_unencrypted.write_to_bytes()
            .map_err(|err| {
                warn!("Could not write CSRF token: {}", err);
                CsrfError::InternalError
            })?;
        let mut token_encrypted = vec![0; token_unencrypted.len()];
        let mut sig = vec![0; 16];
        aead.encrypt(&token_unencrypted, &mut token_encrypted, &mut sig);
        token_encrypted.extend(sig);

        Ok(CsrfToken::new(token_encrypted))
    }
}

impl CsrfProtection for ChaCha20Poly1305CsrfProtection {

    fn parse_cookie(&self, cookie: &[u8]) -> Result<CsrfCookieTransport, CsrfError> {
        if cookie.len() <= 16 {
            return Err(CsrfError::ValidationFailure);
        }

        let encrypted_body = &cookie[0..(cookie.len() - 16)];
        let sig = &cookie[(cookie.len() - 16)..cookie.len()];

        let mut aead = self.aead();
        let mut decrypted_body = vec![0; encrypted_body.len()];
        let valid = aead.decrypt(encrypted_body, &mut decrypted_body, sig);

        if !valid {
            info!("Unable to decrypt and authenticate CSRF cookie");
            return Err(CsrfError::ValidationFailure)
        }

        protobuf::core::parse_from_bytes::<CsrfCookieTransport>(&decrypted_body)
            .map(|r| {
                debug!("Successfully parsed CSRF cookie contents");
                r
            })
            .map_err(|err| {
                info!("Unable to parse CSRF cookie contents: {}", err);
                CsrfError::ValidationFailure
            })
    }

    fn parse_token(&self, token: &[u8]) -> Result<CsrfTokenTransport, CsrfError> {
        if token.len() <= 16 {
            return Err(CsrfError::ValidationFailure);
        }

        let encrypted_body = &token[0..(token.len() - 16)];
        let sig = &token[(token.len() - 16)..token.len()];

        let mut aead = self.aead();
        let mut decrypted_body = vec![0; encrypted_body.len()];
        let valid = aead.decrypt(encrypted_body, &mut decrypted_body, sig);

        if !valid {
            info!("Unable to decrypt and authenticate CSRF token");
            return Err(CsrfError::ValidationFailure)
        }

        protobuf::core::parse_from_bytes::<CsrfTokenTransport>(&decrypted_body)
            .map(|r| {
                debug!("Successfully parsed CSRF token contents");
                r
            })
            .map_err(|err| {
                info!("Unable to parse CSRF token contents: {}", err);
                CsrfError::ValidationFailure
            })
    }

    fn generate_token_pair(&self, previous_token: Option<Vec<u8>>, ttl_seconds: i64) -> Result<(CsrfToken, CsrfCookie), CsrfError> {
        let mut token = vec![0; 64];
        match previous_token {
            Some(ref previous) if previous.len() == 64 => {
                for i in 0..64 {
                    token[i] = previous[i];
                }
            }
            _ => self.random_bytes(&mut token)?,
        }

        match (self.generate_token(&token), self.generate_cookie(&token, ttl_seconds)) {
            (Ok(t), Ok(c)) => Ok((t, c)),
            _ => Err(CsrfError::ValidationFailure),
        }
    }
}

impl typemap::Key for CsrfToken {
    type Value = CsrfToken;
}

struct CsrfHandler<P: CsrfProtection, H: Handler> {
    protect: P,
    config: CsrfConfig,
    handler: H,
}

impl<P: CsrfProtection, H: Handler> CsrfHandler<P, H> {
    fn new(protect: P, config: CsrfConfig, handler: H) -> Self {
        CsrfHandler {
            protect: protect,
            config: config,
            handler: handler,
        }
    }

    // TODO have this return an &str
    fn extract_csrf_cookie(&self, request: &Request) -> Option<Vec<u8>> {
        request.headers
            .get::<IronCookie>()
            .and_then(|raw_cookie| {
                raw_cookie.0
                    .iter()
                    .filter_map(|c| {
                        Cookie::parse_encoded(c.clone())
                            .ok()
                            .and_then(|cookie| match cookie.name_value() {
                                (CSRF_COOKIE_NAME, value) => Some(value.to_string()),
                                _ => None,
                            })
                            .and_then(|c| c.from_base64().ok())
                    })
                    .collect::<Vec<Vec<u8>>>()
                    .first()
                    .map(|c| c.clone())
            })
    }

    // TODO have this return an &str
    fn extract_csrf_token(&self, mut request: &mut Request) -> Option<Vec<u8>> {
        let f_token = self.extract_csrf_token_from_form_url_encoded(&mut request);
        let q_token = self.extract_csrf_token_from_query(&mut request);
        let h_token = self.extract_csrf_token_from_headers(&mut request);

        debug!("CSRF token found in Form: {}, Query: {}, Header: {}",
               f_token.is_some(),
               q_token.is_some(),
               h_token.is_some());

        f_token.or(q_token).or(h_token)
    }

    // TODO have this return an &str
    fn extract_csrf_token_from_form_url_encoded(&self,
                                                mut request: &mut Request)
                                                -> Option<Vec<u8>> {
        let token = request.get_ref::<UrlEncodedBody>()
            .ok()
            .and_then(|form| form.get(CSRF_FORM_FIELD))
            .and_then(|vs| {
                vs.iter()
                    .filter_map(|v| v.from_base64().ok())
                    .next()
            });

        // TODO remove token from form

        token.map(|t| t.clone())
    }

    // TODO have this return an &str
    fn extract_csrf_token_from_query(&self, mut request: &mut Request) -> Option<Vec<u8>> {
        let token = request.get_ref::<UrlEncodedQuery>()
            .ok()
            .and_then(|query| query.get(CSRF_QUERY_STRING))
            .and_then(|vs| {
                vs.iter()
                    .filter_map(|v| v.from_base64().ok())
                    .next()
            });

        // TODO remove token from query

        token.map(|t| t.clone())
    }

    // TODO have this return an &str
    fn extract_csrf_token_from_headers(&self, mut request: &mut Request) -> Option<Vec<u8>> {
        let token = request.headers
            .get::<XCsrfToken>()
            .map(|t| t.to_string())
            .and_then(|s| s.from_base64().ok());
        let _ = request.headers.remove::<XCsrfToken>();
        token
    }
}

impl<P: CsrfProtection + Sized + 'static, H: Handler> Handler for CsrfHandler<P, H> {
    fn handle(&self, mut request: &mut Request) -> IronResult<Response> {
        // before
        let token_opt = self.extract_csrf_token(&mut request)
            .and_then(|t| self.protect.parse_token(&t).ok());
        let cookie_opt = self.extract_csrf_cookie(&request)
            .and_then(|c| self.protect.parse_cookie(&c).ok());

        if self.config.protected_methods.contains(&request.method) {
            debug!("CSRF elements present. Token: {}, Cookie: {}",
                   token_opt.is_some(),
                   cookie_opt.is_some());

            match (token_opt.clone(), cookie_opt) {
                (Some(token), Some(cookie)) => {
                    let no_match = token.get_token() != cookie.get_token();
                    let expired = cookie.get_expires() < time::precise_time_s() as u64;

                    if no_match && expired {
                        // TODO differentiate between server error and validation error
                        return Ok(Response::with((status::Forbidden, "CSRF Error")));
                    }
                }
                _ => return Ok(Response::with((status::Forbidden, "CSRF Error"))),
            }
        }

        let (token, csrf_cookie) = self.protect.generate_token_pair(token_opt.map(|mut t| t.take_token()),
                                                                    self.config.ttl_seconds)?;
        let _ = request.extensions.insert::<CsrfToken>(token);

        // main
        let mut response = self.handler.handle(&mut request)?;

        // after
        let cookie = Cookie::build(CSRF_COOKIE_NAME, csrf_cookie.b64_string())
            // TODO config for path
            .path("/")
            .http_only(true)
            .secure(self.config.secure_cookie)
            // TODO config flag for SameSite
            .max_age(Duration::seconds(self.config.ttl_seconds))
            .finish();
        let mut cookies = vec![format!("{}", cookie.encoded())]; // TODO is this formatting dumb?

        // TODO write a test to ensure other cookies are not over written / deleted
        {
            if let Some(set_cookie) = response.headers.get::<SetCookie>() {
                cookies.extend(set_cookie.0.clone())
            }
        }
        response.headers.set(SetCookie(cookies));

        Ok(response)
    }
}

/// An implementation of `iron::Middleware` that provides transparent wrapping of an application
/// with CSRF protection.
// TODO example
pub struct CsrfProtectionMiddleware<P: CsrfProtection> {
    protect: P,
    config: CsrfConfig,
}

impl<P: CsrfProtection + Sized + 'static> CsrfProtectionMiddleware<P> {
    pub fn new(protect: P, config: CsrfConfig) -> Self {
        CsrfProtectionMiddleware {
            protect: protect,
            config: config,
        }
    }
}

impl<P: CsrfProtection + Sized + 'static> AroundMiddleware for CsrfProtectionMiddleware<P> {
    fn around(self, handler: Box<Handler>) -> Box<Handler> {
        Box::new(CsrfHandler::new(self.protect, self.config, handler))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::header::Headers;
    use hyper::method::Method::Extension;
    use iron_test::request as mock_request;
    use iron_test::response::extract_body_to_string;
    use urlencoding::encode as url_encode;

    // TODO write test that ensures encrypted messages don't contain the plaintext

    #[test]
    fn test_chachah20poly1305_csrf_protection() {
        let password = b"hunter2";
        let protect = ChaCha20Poly1305CsrfProtection::from_password(password)
            .expect("couldn't create protection");
        let (token, cookie) = protect.generate_token_pair(None, 300)
            .expect("couldn't generate token/cookie pair");
        let token = token.b64_string().from_base64().expect("token not base64");
        let token = protect.parse_token(&token).expect("token not parsed");
        let cookie = cookie.b64_string().from_base64().expect("cookie not base64");
        let cookie = protect.parse_cookie(&cookie).expect("cookie not parsed");
        assert!(protect.verify_token_pair(&token, &cookie),
                "could not verify token/cookie pair");
    }

    #[test]
    fn test_config() {
        // ttl of 0 is allowed
        assert!(CsrfConfig::build().ttl_seconds(0).finish().is_ok());

        // negative ttl is not allowed
        assert!(CsrfConfig::build().ttl_seconds(-1).finish().is_err());

        // empty set of protected methods is not allowed
        assert!(CsrfConfig::build().protected_methods(HashSet::new()).finish().is_err())
    }

    fn test_encrypted_protection<P: CsrfProtection>(middleware: CsrfProtectionMiddleware<P>) {
        // check token validates
        let (token, cookie) = middleware.protect.generate_token_pair(None, 300).unwrap();
        let token = token.b64_string().from_base64().expect("token not base64");
        let token = middleware.protect.parse_token(&token).expect("token not parsed");
        let cookie = cookie.b64_string().from_base64().expect("cookie not base64");
        let cookie = middleware.protect.parse_cookie(&cookie).expect("cookie not parsed");
        assert!(middleware.protect.verify_token_pair(&token, &cookie));

        // check modified token doesn't validate
        let (token, cookie) = middleware.protect.generate_token_pair(None,300).unwrap();
        let mut token = token.b64_string().from_base64().expect("token not base64");
        token[0] = token[0] ^ 0x01;
        assert!(middleware.protect.parse_token(&token).is_err());
        token[0] = token[0] ^ 0x01; // flip the bit back
        let len = token.len();
        token[len - 1] = token[len - 1] ^ 0x01;
        assert!(middleware.protect.parse_token(&token).is_err());

        // check modified cookie doesn't validate
        let mut cookie = cookie.b64_string().from_base64().expect("cookie not base64");
        cookie[0] = cookie[0] ^ 0x01;
        assert!(middleware.protect.parse_cookie(&cookie).is_err());
        cookie[0] = cookie[0] ^ 0x01; // flip the bit back
        let len = cookie.len();
        cookie[len - 1] = cookie[len - 1] ^ 0x01;
        assert!(middleware.protect.parse_cookie(&cookie).is_err());

        // check the token is invalid with ttl = 0 for tokens that are never valid
        let (token, cookie) = middleware.protect.generate_token_pair(None, 0).unwrap();
        let token = token.b64_string().from_base64().expect("token not base64");
        let token = middleware.protect.parse_token(&token).expect("token not parsed");
        let cookie = cookie.b64_string().from_base64().expect("cookie not base64");
        let cookie = middleware.protect.parse_cookie(&cookie).expect("cookie not parsed");
        assert!(!middleware.protect.verify_token_pair(&token, &cookie));

        // check tokens don't validate each other
        let (token, _) = middleware.protect.generate_token_pair(None, 300).unwrap();
        let (_, cookie) = middleware.protect.generate_token_pair(None, 300).unwrap();
        let token = token.b64_string().from_base64().expect("token not base64");
        let token = middleware.protect.parse_token(&token).expect("token not parsed");
        let cookie = cookie.b64_string().from_base64().expect("cookie not base64");
        let cookie = middleware.protect.parse_cookie(&cookie).expect("cookie not parsed");
        assert!(!middleware.protect.verify_token_pair(&token, &cookie));

        // TODO set ttl = 1, sleep 2, check validation fails
        // TODO check token is same when passed old token
    }

    fn mock_handler(request: &mut Request) -> IronResult<Response> {
        // TODO check that CSRF token isn't in header/form/query
        // TODO check that CSRF cookie isn't in header
        let token = request.extensions
            .get::<CsrfToken>()
            .map(|t| t.b64_string())
            .unwrap_or("".to_string());
        Ok(Response::with((status::Ok, token)))
    }

    fn test_middleware<P: CsrfProtection + 'static>(protect: P) {
        let config = CsrfConfig::default();
        let middleware = CsrfProtectionMiddleware::new(protect, config);
        let handler = middleware.around(Box::new(mock_handler));

        // do one GET to get the token
        let response = mock_request::get("http://localhost/", Headers::new(), &handler).unwrap();
        assert_eq!(response.status, Some(status::Ok));

        let (csrf_token, csrf_cookie) = {
            let headers = response.headers.clone();
            let set_cookie = headers.get::<SetCookie>().unwrap();
            let cookie = Cookie::parse(set_cookie.0[0].clone()).unwrap();
            (extract_body_to_string(response), format!("{}", cookie))
        };

        let body_methods = vec![method::Post,
                                method::Put,
                                method::Patch,
                                method::Connect,
                                Extension("WAT".to_string())];

        let all_methods = vec![method::Get,
                               method::Post,
                               method::Put,
                               method::Patch,
                               method::Delete,
                               method::Options,
                               method::Connect,
                               method::Trace,
                               Extension("WAT".to_string())];

        ///////////////////////////////////////////////////////////////////////////////////

        let path = "http://localhost/";
        let mut headers = Headers::new();
        headers.set(IronCookie(vec![csrf_cookie.clone()]));
        let body = "";

        let response = mock_request::get(path, headers.clone(), &handler).unwrap();
        assert_eq!(response.status, Some(status::Ok));

        let response = mock_request::head(path, headers.clone(), &handler).unwrap();
        assert_eq!(response.status, Some(status::Ok));

        let response = mock_request::head(path, headers.clone(), &handler).unwrap();
        assert_eq!(response.status, Some(status::Ok));

        let response = mock_request::request(method::Trace, path, body, headers.clone(), &handler)
            .unwrap();
        assert_eq!(response.status, Some(status::Ok));

        let response =
            mock_request::request(method::Connect, path, body, headers.clone(), &handler).unwrap();
        assert_eq!(response.status, Some(status::Ok));

        let response = mock_request::request(Extension("WAT".to_string()),
                                             path,
                                             body,
                                             headers.clone(),
                                             &handler)
            .unwrap();
        assert_eq!(response.status, Some(status::Ok));

        let response = mock_request::post(path, headers.clone(), body, &handler).unwrap();
        assert_eq!(response.status, Some(status::Forbidden));

        let response = mock_request::put(path, headers.clone(), body, &handler).unwrap();
        assert_eq!(response.status, Some(status::Forbidden));

        let response = mock_request::put(path, headers.clone(), body, &handler).unwrap();
        assert_eq!(response.status, Some(status::Forbidden));

        let response = mock_request::patch(path, headers.clone(), body, &handler).unwrap();
        assert_eq!(response.status, Some(status::Forbidden));

        ///////////////////////////////////////////////////////////////////////////////////

        let path = "http://localhost/";
        let mut headers = Headers::new();
        headers.set(IronCookie(vec![csrf_cookie.clone()]));
        headers.set(XCsrfToken(csrf_token.clone()));
        let body = "";

        for verb in all_methods.iter().cloned() {
            let response = mock_request::request(verb, path, body, headers.clone(), &handler)
                .unwrap();
            assert_eq!(response.status, Some(status::Ok));
        }

        ///////////////////////////////////////////////////////////////////////////////////

        let path = format!("http://localhost/?{}={}",
                           CSRF_QUERY_STRING,
                           url_encode(&csrf_token));
        let path = path.as_str();
        let mut headers = Headers::new();
        headers.set(IronCookie(vec![csrf_cookie.clone()]));
        let body = "";

        for verb in all_methods.iter().cloned() {
            let response = mock_request::request(verb, path, body, headers.clone(), &handler)
                .unwrap();
            assert_eq!(response.status, Some(status::Ok));
        }

        ///////////////////////////////////////////////////////////////////////////////////

        let path = "http://localhost/";
        let mut headers = Headers::new();
        headers.set(IronCookie(vec![csrf_cookie.clone()]));
        headers.set_raw("content-type",
                        vec![b"application/x-www-form-urlencoded".to_vec()]);
        let body = format!("{}={}", CSRF_QUERY_STRING, url_encode(&csrf_token));
        let body = body.as_str();

        for verb in body_methods.iter().cloned() {
            let response = mock_request::request(verb, path, body, headers.clone(), &handler)
                .unwrap();
            assert_eq!(response.status, Some(status::Ok));
        }
    }

    #[test]
    fn test_chacha20poly1305_protection() {
        let password = b"hunter2";
        let protect = ChaCha20Poly1305CsrfProtection::from_password(password)
            .expect("failed to make protection");
        let middleware = CsrfProtectionMiddleware::new(protect, CsrfConfig::default());
        test_encrypted_protection(middleware);
    }

    #[test]
    fn test_chacha20poly1305_middleware() {
        let password = b"hunter2";
        let protect = ChaCha20Poly1305CsrfProtection::from_password(password)
            .expect("failed to make protection");
        test_middleware(protect);
    }

    // TODO test form extraction
    // TODO test query extraction
    // TODO test headers extraction
    // TODO test that verifies protected_method feature/configuration
}
