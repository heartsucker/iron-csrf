//! Module containing the core functionality for CSRF protection.

use std::error::Error;
use std::collections::HashSet;
use std::{fmt, mem, str};

use chrono::Duration;
use cookie::Cookie;
use crypto::aead::{AeadEncryptor, AeadDecryptor};
use crypto::aes::KeySize;
use crypto::aes_gcm::AesGcm;
use crypto::scrypt::{scrypt, ScryptParams};
use iron::headers::{SetCookie, Cookie as IronCookie};
use iron::method;
use iron::middleware::{AroundMiddleware, Handler};
use iron::prelude::*;
use iron::status;
use iron::typemap;
use ring::rand::SystemRandom;
use rustc_serialize::base64::{self, FromBase64, ToBase64};
use time;
use urlencoded::{UrlEncodedQuery, UrlEncodedBody};


/// The name of the cookie for the CSRF validation data and signature.
pub const CSRF_COOKIE_NAME: &'static str = "csrf";

/// The name of the form field for the CSRF token.
pub const CSRF_FORM_FIELD: &'static str = "csrf-token";

/// The name of the HTTP header for the CSRF token.
pub const CSRF_HEADER: &'static str = "X-CSRF-Token";

/// The name of the query parameter for the CSRF token.
pub const CSRF_QUERY_STRING: &'static str = "csrf-token";

/// An `enum` of all CSRF related errors.
#[derive(Debug)]
pub enum CsrfError {
    InternalError,
    ValidationFailure,
}

impl Error for CsrfError {
    fn description(&self) -> &str {
        match *self {
            CsrfError::InternalError => "CSRF library error",
            CsrfError::ValidationFailure => "CSRF validation failed",
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

// TODO why doesn't this show up in the docs?
/// The HTTP header for the CSRF token.
header! { (XCsrfToken, CSRF_HEADER) => [String] }

/// An encoded CSRF token.
///
/// # Examples
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

    /// Retrieve the CSRF token as a base64 encoded string.
    pub fn b64_string(&self) -> String {
        self.bytes.to_base64(base64::STANDARD)
    }

    /// Retrieve the CSRF token as a URL safe base64 encoded string.
    pub fn b64_url_string(&self) -> String {
        self.bytes.to_base64(base64::URL_SAFE)
    }
}

/// An encoded CSRF cookie.
#[derive(Debug, Eq, PartialEq)]
struct CsrfCookie {
    bytes: Vec<u8>,
}

impl CsrfCookie {
    fn new(bytes: Vec<u8>) -> Self {
        CsrfCookie { bytes: bytes }
    }

    fn b64_string(&self) -> String {
        self.bytes.to_base64(base64::STANDARD)
    }
}

/// Internal represenation of unencrypted data.
#[derive(Clone, Debug)]
struct UnencryptedCsrfToken {
    token: Vec<u8>,
}

impl UnencryptedCsrfToken {
    fn new(token: Vec<u8>) -> Self {
        UnencryptedCsrfToken { token: token }
    }
}

/// Internal represenation of unencrypted data.
#[derive(Clone, Debug)]
struct UnencryptedCsrfCookie {
    expires: i64,
    token: Vec<u8>,
}

impl UnencryptedCsrfCookie {
    fn new(expires: i64, token: Vec<u8>) -> Self {
        UnencryptedCsrfCookie {
            expires: expires,
            token: token,
        }
    }
}

/// The configuation used to initialize `CsrfProtectionMiddleware`.
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

/// Uses AES + HMAC to provide signed, encrypted CSRF tokens and cookies.
pub struct CsrfProtection {
    rng: SystemRandom,
    aes_key: [u8; 32],
}

impl CsrfProtection {
    /// Using `scrypt` with params `n=14`, `r=8`, `p=1`, generate the key material used for the
    /// underlying crypto functions.
    ///
    /// # Panics
    /// This function may panic if the underlying crypto library fails catastrophically.
    pub fn from_password(password: &[u8]) -> CsrfProtection {
        // scrypt is *slow*, so use these params for testing
        #[cfg(test)]
        let params = ScryptParams::new(1, 8, 1);
        #[cfg(not(test))]
        let params = ScryptParams::new(14, 8, 1);

        let salt = b"iron-csrf-scrypt-salt";
        let mut aes_key = [0; 32];
        info!("Generating key material. This may take some time.");
        scrypt(password, salt, &params, &mut aes_key);
        info!("Key material generated.");

        CsrfProtection::from_key(aes_key)
    }

    pub fn from_key(aes_key: [u8; 32]) -> Self {
        CsrfProtection {
            rng: SystemRandom::new(),
            aes_key: aes_key,
        }
    }

    fn aead<'a>(&self, nonce: &[u8; 12]) -> AesGcm<'a> {
        AesGcm::new(KeySize::KeySize256, &self.aes_key, nonce, &[])
    }

    fn random_bytes(&self, buf: &mut [u8]) -> Result<(), CsrfError> {
        self.rng
            .fill(buf)
            .map_err(|_| {
                warn!("Failed to get random bytes");
                CsrfError::InternalError
            })
    }

    fn verify_token_pair(&self,
                         token: &UnencryptedCsrfToken,
                         cookie: &UnencryptedCsrfCookie)
                         -> bool {
        let tokens_match = token.token == cookie.token;
        let not_expired = cookie.expires > time::precise_time_s() as i64;
        tokens_match && not_expired
    }

    fn generate_cookie(&self, token: &[u8], ttl_seconds: i64) -> Result<CsrfCookie, CsrfError> {
        if cfg!(test) {
            assert!(token.len() == 64);
        }

        let expires = time::precise_time_s() as i64 + ttl_seconds;
        let expires_bytes = unsafe { mem::transmute::<i64, [u8; 8]>(expires) };

        let mut nonce = [0; 12];
        self.random_bytes(&mut nonce)?;

        let mut padding = [0; 16];
        self.random_bytes(&mut padding)?;

        let mut plaintext = [0; 88];

        for i in 0..16 {
            plaintext[i] = padding[i];
        }
        for i in 0..8 {
            plaintext[i + 16] = expires_bytes[i];
        }
        for i in 0..64 {
            plaintext[i + 24] = token[i];
        }

        let mut ciphertext = [0; 88];
        let mut tag = [0; 16];
        let mut aead = self.aead(&nonce);

        aead.encrypt(&plaintext, &mut ciphertext, &mut tag);

        let mut transport = [0; 116];

        for i in 0..88 {
            transport[i] = ciphertext[i];
        }
        for i in 0..12 {
            transport[i + 88] = nonce[i];
        }
        for i in 0..16 {
            transport[i + 100] = tag[i];
        }

        Ok(CsrfCookie::new(transport.to_vec()))
    }

    fn generate_token(&self, token: &[u8]) -> Result<CsrfToken, CsrfError> {
        if cfg!(test) {
            assert!(token.len() == 64);
        }

        let mut nonce = [0; 12];
        self.random_bytes(&mut nonce)?;

        let mut padding = [0; 16];
        self.random_bytes(&mut padding)?;

        let mut plaintext = [0; 80];

        for i in 0..16 {
            plaintext[i] = padding[i];
        }
        for i in 0..64 {
            plaintext[i + 16] = token[i];
        }

        let mut ciphertext = [0; 80];
        let mut tag = vec![0; 16];
        let mut aead = self.aead(&nonce);

        aead.encrypt(&plaintext, &mut ciphertext, &mut tag);

        let mut transport = [0; 108];

        for i in 0..80 {
            transport[i] = ciphertext[i];
        }
        for i in 0..12 {
            transport[i + 80] = nonce[i];
        }
        for i in 0..16 {
            transport[i + 92] = tag[i];
        }

        Ok(CsrfToken::new(transport.to_vec()))
    }

    fn parse_cookie(&self, cookie: &[u8]) -> Result<UnencryptedCsrfCookie, CsrfError> {
        if cookie.len() != 116 {
            return Err(CsrfError::ValidationFailure);
        }

        let mut ciphertext = [0; 88];
        let mut plaintext = [0; 88];
        let mut nonce = [0; 12];
        let mut tag = [0; 16];

        for i in 0..88 {
            ciphertext[i] = cookie[i];
        }
        for i in 0..12 {
            nonce[i] = cookie[i + 88];
        }
        for i in 0..16 {
            tag[i] = cookie[i + 100];
        }

        let mut aead = self.aead(&nonce);
        if !aead.decrypt(&ciphertext, &mut plaintext, &tag) {
            info!("Failed to decrypt CSRF cookie");
            return Err(CsrfError::ValidationFailure);
        }

        let mut expires_bytes = [0; 8];
        let mut token = [0; 64];

        // skip 16 bytes of padding
        for i in 0..8 {
            expires_bytes[i] = plaintext[i + 16];
        }
        for i in 0..64 {
            token[i] = plaintext[i + 24];
        }

        let expires = unsafe { mem::transmute::<[u8; 8], i64>(expires_bytes) };

        Ok(UnencryptedCsrfCookie::new(expires, token.to_vec()))
    }

    fn parse_token(&self, token: &[u8]) -> Result<UnencryptedCsrfToken, CsrfError> {
        if token.len() != 108 {
            return Err(CsrfError::ValidationFailure);
        }

        let mut ciphertext = [0; 80];
        let mut plaintext = [0; 80];
        let mut nonce = [0; 12];
        let mut tag = [0; 16];

        for i in 0..80 {
            ciphertext[i] = token[i];
        }
        for i in 0..12 {
            nonce[i] = token[i + 80];
        }
        for i in 0..16 {
            tag[i] = token[i + 92];
        }

        let mut aead = self.aead(&nonce);
        if !aead.decrypt(&ciphertext, &mut plaintext, &tag) {
            info!("Failed to decrypt CSRF token");
            return Err(CsrfError::ValidationFailure);
        }

        let mut token = [0; 64];

        // skip 16 bytes of padding
        for i in 0..64 {
            token[i] = plaintext[i + 16];
        }

        Ok(UnencryptedCsrfToken::new(token.to_vec()))
    }

    fn generate_token_pair(&self,
                           previous_token: Option<Vec<u8>>,
                           ttl_seconds: i64)
                           -> Result<(CsrfToken, CsrfCookie), CsrfError> {
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

struct CsrfHandler<H: Handler> {
    protect: CsrfProtection,
    config: CsrfConfig,
    handler: H,
}

impl<H: Handler> CsrfHandler<H> {
    fn new(protect: CsrfProtection, config: CsrfConfig, handler: H) -> Self {
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
        request.get_ref::<UrlEncodedBody>()
            .ok()
            .and_then(|form| form.get(CSRF_FORM_FIELD))
            .and_then(|vs| {
                vs.iter()
                    .filter_map(|v| v.from_base64().ok())
                    .next()
            })
            .map(|t| t.clone())
    }

    // TODO have this return an &str
    fn extract_csrf_token_from_query(&self, mut request: &mut Request) -> Option<Vec<u8>> {
        request.get_ref::<UrlEncodedQuery>()
            .ok()
            .and_then(|query| query.get(CSRF_QUERY_STRING))
            .and_then(|vs| {
                vs.iter()
                    .filter_map(|v| v.from_base64().ok())
                    .next()
            })
            .map(|t| t.clone())
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

impl<H: Handler> Handler for CsrfHandler<H> {
    fn handle(&self, mut request: &mut Request) -> IronResult<Response> {
        // before
        let token_opt = self.extract_csrf_token(&mut request)
            .and_then(|t| self.protect.parse_token(&t).ok());
        let cookie_opt = self.extract_csrf_cookie(&request)
            .and_then(|c| self.protect.parse_cookie(&c).ok());

        if self.config.protected_methods.contains(&request.method) {
            debug!("csrf elements present. token: {}, cookie: {}",
                   token_opt.is_some(),
                   cookie_opt.is_some());

            match (token_opt.clone(), cookie_opt) {
                (Some(token), Some(cookie)) => {
                    let verified = self.protect.verify_token_pair(&token, &cookie);
                    if !verified {
                        // TODO differentiate between server error and validation error
                        return Ok(Response::with((status::Forbidden, "CSRF Error")));
                    }
                }
                _ => return Ok(Response::with((status::Forbidden, "CSRF Error"))),
            }
        }

        let (token, csrf_cookie) = self.protect
            .generate_token_pair(token_opt.map(|t| t.token), self.config.ttl_seconds)?;
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

        {
            if let Some(set_cookie) = response.headers.get::<SetCookie>() {
                cookies.extend(set_cookie.0.clone())
            }
        }
        response.headers.set(SetCookie(cookies));

        Ok(response)
    }
}

/// An implementation of `iron::AroundMiddleware` that provides transparent wrapping of an
/// application with CSRF protection.
// TODO example
pub struct CsrfProtectionMiddleware {
    protect: CsrfProtection,
    config: CsrfConfig,
}

impl CsrfProtectionMiddleware {
    pub fn new(protect: CsrfProtection, config: CsrfConfig) -> Self {
        CsrfProtectionMiddleware {
            protect: protect,
            config: config,
        }
    }
}

impl AroundMiddleware for CsrfProtectionMiddleware {
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

    lazy_static! {
        static ref BODY_METHODS: Vec<method::Method> = vec![method::Post,
                                                        method::Put,
                                                        method::Patch,
                                                        method::Connect,
                                                        Extension("WAT".to_string())];
    }

    lazy_static! {
        static ref ALL_METHODS: Vec<method::Method> = vec![method::Get,
                                                       method::Post,
                                                       method::Put,
                                                       method::Patch,
                                                       method::Delete,
                                                       method::Options,
                                                       method::Connect,
                                                       method::Trace,
                                                       Extension("WAT".to_string())];
    }

    const TEST_QUERY_PARAM: &'static str = "test-param";
    const TEST_QUERY_VALUE: &'static str = "test-value";
    const TEST_COOKIE_NAME: &'static str = "some-cookie";
    const TEST_COOKIE_VALUE: &'static str = "some-value";

    // TODO write test that ensures encrypted messages don't contain the plaintext

    #[test]
    fn cookies_and_tokens_can_be_verfied() {
        let password = b"hunter2";
        let protect = CsrfProtection::from_password(password);
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
    fn config_properties() {
        // ttl of 0 is allowed
        assert!(CsrfConfig::build().ttl_seconds(0).finish().is_ok());

        // negative ttl is not allowed
        assert!(CsrfConfig::build().ttl_seconds(-1).finish().is_err());

        // empty set of protected methods is not allowed
        assert!(CsrfConfig::build().protected_methods(HashSet::new()).finish().is_err())
    }

    fn get_middleware() -> CsrfProtectionMiddleware {
        let password = b"hunter2";
        let protect = CsrfProtection::from_password(password);
        CsrfProtectionMiddleware::new(protect, CsrfConfig::default())
    }

    #[test]
    fn middleware_validates_token() {
        let middleware = get_middleware();

        let (token, cookie) = middleware.protect.generate_token_pair(None, 300).unwrap();
        let token = token.b64_string().from_base64().expect("token not base64");
        let token = middleware.protect.parse_token(&token).expect("token not parsed");
        let cookie = cookie.b64_string().from_base64().expect("cookie not base64");
        let cookie = middleware.protect.parse_cookie(&cookie).expect("cookie not parsed");

        assert!(middleware.protect.verify_token_pair(&token, &cookie));
    }

    #[test]
    fn middleware_fails_modified_token() {
        let middleware = get_middleware();

        let (token, _) = middleware.protect.generate_token_pair(None, 300).unwrap();
        let mut token = token.b64_string().from_base64().expect("token not base64");

        // flip a bit in the padding
        token[0] = token[0] ^ 0x01;
        assert!(middleware.protect.parse_token(&token).is_err());
        token[0] = token[0] ^ 0x01; // flip the bit back

        // flip a bit in the token
        token[16] = token[16] ^ 0x01;
        assert!(middleware.protect.parse_token(&token).is_err());
        token[16] = token[16] ^ 0x01; // flip the bit back

        // flip a bit in the tag
        let len = token.len();
        token[len - 1] = token[len - 1] ^ 0x01;
        assert!(middleware.protect.parse_token(&token).is_err());
    }

    #[test]
    fn middleware_fails_modified_cookie() {
        let middleware = get_middleware();

        let (_, cookie) = middleware.protect.generate_token_pair(None, 300).unwrap();
        let mut cookie = cookie.b64_string().from_base64().expect("cookie not base64");

        // flip a bit in the padding
        cookie[0] = cookie[0] ^ 0x01;
        assert!(middleware.protect.parse_cookie(&cookie).is_err());
        cookie[0] = cookie[0] ^ 0x01; // flip the bit back

        // flip a bit in the expiry/token
        cookie[16] = cookie[16] ^ 0x01;
        assert!(middleware.protect.parse_cookie(&cookie).is_err());
        cookie[16] = cookie[16] ^ 0x01; // flip the bit back

        // flip a bit in the tag
        let len = cookie.len();
        cookie[len - 1] = cookie[len - 1] ^ 0x01;
        assert!(middleware.protect.parse_cookie(&cookie).is_err());
    }

    #[test]
    fn middleware_fails_expired_tokens() {
        let middleware = get_middleware();

        let (token, cookie) = middleware.protect.generate_token_pair(None, 0).unwrap();

        let token = token.b64_string().from_base64().expect("token not base64");
        let token = middleware.protect.parse_token(&token).expect("token not parsed");

        let cookie = cookie.b64_string().from_base64().expect("cookie not base64");
        let cookie = middleware.protect.parse_cookie(&cookie).expect("cookie not parsed");

        assert!(!middleware.protect.verify_token_pair(&token, &cookie));
    }

    #[test]
    fn middleware_fails_mismatched_tokens() {
        let middleware = get_middleware();

        let (token, _) = middleware.protect.generate_token_pair(None, 300).unwrap();
        let (_, cookie) = middleware.protect.generate_token_pair(None, 300).unwrap();

        let token = token.b64_string().from_base64().expect("token not base64");
        let token = middleware.protect.parse_token(&token).expect("token not parsed");

        let cookie = cookie.b64_string().from_base64().expect("cookie not base64");
        let cookie = middleware.protect.parse_cookie(&cookie).expect("cookie not parsed");

        assert!(!middleware.protect.verify_token_pair(&token, &cookie));
    }

    // TODO set ttl = 1, sleep 2, check validation fails
    // TODO check token is same when passed old token

    fn mock_header_handler(request: &mut Request) -> IronResult<Response> {
        assert_eq!(request.headers.get::<XCsrfToken>(), None);

        let token = request.extensions
            .get::<CsrfToken>()
            .map(|t| t.b64_string())
            .unwrap_or("<no token>".to_string());

        Ok(Response::with((status::Ok, token)))
    }

    fn mock_handler(request: &mut Request) -> IronResult<Response> {
        let token = request.extensions
            .get::<CsrfToken>()
            .map(|t| t.b64_string())
            .unwrap_or("<no token>".to_string());

        Ok(Response::with((status::Ok, token)))
    }

    fn mock_query_handler(request: &mut Request) -> IronResult<Response> {
        let token = request.extensions
            .get::<CsrfToken>()
            .map(|t| t.b64_string())
            .unwrap_or("<no token>".to_string());

        if BODY_METHODS.contains(&request.method) {
            let form_data = request.get_ref::<UrlEncodedQuery>().expect("no url encoded query");

            assert_eq!(form_data.get(TEST_QUERY_PARAM), Some(&vec!(TEST_QUERY_VALUE.to_string())));
            // TODO assert_eq!(form_data.get(CSRF_QUERY_STRING), None);
        }

        Ok(Response::with((status::Ok, token)))
    }

    fn mock_url_form_handler(request: &mut Request) -> IronResult<Response> {
        let token = request.extensions
            .get::<CsrfToken>()
            .map(|t| t.b64_string())
            .unwrap_or("<no token>".to_string());

        if BODY_METHODS.contains(&request.method) {
            let form_data = request.get_ref::<UrlEncodedBody>().expect("not url form encoded");

            assert_eq!(form_data.get(TEST_QUERY_PARAM), Some(&vec!(TEST_QUERY_VALUE.to_string())));
            // TODO assert_eq!(form_data.get(CSRF_QUERY_STRING), None);
        }

        Ok(Response::with((status::Ok, token)))
    }

    fn mock_cookie_handler(_: &mut Request) -> IronResult<Response> {
        let cookie = Cookie::new(TEST_COOKIE_NAME, TEST_COOKIE_VALUE);
        let mut response = Response::with((status::Ok, ""));
        response.headers.set(SetCookie(vec![format!["{}", cookie]]));
        Ok(response)
    }

    fn get_handler_token_cookie<H: Handler>(handler: H) -> (Box<Handler>, CsrfToken, String) {
        let middleware = get_middleware();
        let handler = middleware.around(Box::new(handler));

        // do one GET to get the token
        let response = mock_request::get("http://localhost/", Headers::new(), &handler).unwrap();
        assert_eq!(response.status, Some(status::Ok));

        let (csrf_token, csrf_cookie) = {
            let headers = response.headers.clone();
            let set_cookie = headers.get::<SetCookie>().unwrap();
            let cookie = Cookie::parse(set_cookie.0[0].clone()).unwrap();
            (CsrfToken::new(extract_body_to_string(response).from_base64().unwrap()),
             format!("{}", cookie))
        };

        (handler, csrf_token, csrf_cookie)
    }

    #[test]
    fn methods_without_token() {
        let (handler, _, csrf_cookie) = get_handler_token_cookie(mock_handler);
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
    }

    #[test]
    fn methods_with_csrf_header() {
        let (handler, csrf_token, csrf_cookie) = get_handler_token_cookie(mock_header_handler);

        let path = "http://localhost/";
        let mut headers = Headers::new();
        headers.set(IronCookie(vec![csrf_cookie.clone()]));
        headers.set(XCsrfToken(csrf_token.b64_string()));
        let body = "";

        for verb in ALL_METHODS.iter().cloned() {
            let response = mock_request::request(verb, path, body, headers.clone(), &handler)
                .unwrap();
            assert_eq!(response.status, Some(status::Ok));
        }
    }

    #[test]
    fn methods_with_csrf_url() {
        let (handler, csrf_token, csrf_cookie) = get_handler_token_cookie(mock_query_handler);
        let path = format!("http://localhost/?{}={}&{}={}",
                           CSRF_QUERY_STRING,
                           csrf_token.b64_url_string(),
                           TEST_QUERY_PARAM,
                           TEST_QUERY_VALUE);
        let path = path.as_str();
        let mut headers = Headers::new();
        headers.set(IronCookie(vec![csrf_cookie.clone()]));
        let body = "";

        for verb in ALL_METHODS.iter().cloned() {
            let response = mock_request::request(verb, path, body, headers.clone(), &handler)
                .unwrap();
            assert_eq!(response.status, Some(status::Ok));
        }
    }

    #[test]
    fn methods_with_csrf_url_form() {
        let (handler, csrf_token, csrf_cookie) = get_handler_token_cookie(mock_url_form_handler);
        let path = "http://localhost/";
        let mut headers = Headers::new();
        headers.set(IronCookie(vec![csrf_cookie.clone()]));
        headers.set_raw("content-type",
                        vec![b"application/x-www-form-urlencoded".to_vec()]);
        let body = format!("{}={}&{}={}", CSRF_QUERY_STRING, csrf_token.b64_url_string(), TEST_QUERY_PARAM, TEST_QUERY_VALUE);
        let body = body.as_str();

        for verb in BODY_METHODS.iter().cloned() {
            let response = mock_request::request(verb, path, body, headers.clone(), &handler)
                .unwrap();
            assert_eq!(response.status, Some(status::Ok));
        }
    }

    #[test]
    fn cookies_not_overwritten() {
        let middleware = get_middleware();
        let handler = middleware.around(Box::new(mock_cookie_handler));

        let response = mock_request::get("http://localhost/", Headers::new(), &handler).unwrap();
        let set_cookie = response.headers.get::<SetCookie>().expect("SetCookie header not set");

        assert!(set_cookie.0.len() == 2);
        assert!(set_cookie.0.iter().find(|c| c.contains(TEST_COOKIE_NAME) && c.contains(TEST_COOKIE_VALUE)).is_some())
    }

    // TODO test that verifies protected_method feature/configuration

}
