use std::error::Error;
use std::fmt;
use std::str;

use chrono::Duration;
use cookie::Cookie;
use iron::headers::{SetCookie, Cookie as IronCookie};
use iron::method;
use iron::middleware::{AroundMiddleware, Handler};
use iron::prelude::*;
use iron::status;
use iron::typemap;
use protobuf;
use protobuf::Message;
use ring::hmac;
use ring::hmac::SigningKey;
use ring::signature;
use ring::signature::Ed25519KeyPair;
use rustc_serialize::base64::{ToBase64, FromBase64, STANDARD};
use time;
use untrusted;
use urlencoded::{UrlEncodedQuery, UrlEncodedBody};

use serial::{CsrfTokenTransport, CsrfCookieTransport};

/// HTTP header that `iron_csrf` uses to identify the CSRF token
header! { (XCsrfToken, "X-CSRF-Token") => [String] }

const CSRF_COOKIE_NAME: &'static str = "csrf";

#[derive(Debug)]
pub struct CsrfCookie {
    // TODO padding
    expires: u64,
    nonce: Vec<u8>,
    signature: Vec<u8>
}

impl CsrfCookie {
    pub fn new(expires: u64, nonce: Vec<u8>, signature: Vec<u8>) -> Self {
        CsrfCookie {
            expires: expires,
            nonce: nonce,
            signature: signature,
        }
    }
}

pub struct CsrfConfig {
    ttl_seconds: i64,
}

impl CsrfConfig {
    pub fn default() -> Self {
        CsrfConfig {
            ttl_seconds: 3600,
        }
    }
}

pub struct CsrfConfigBuilder {
    config: CsrfConfig,
}

// TODO use Default trait
// TODO use build/finish, not new/build
// TODO verify ttl_seconds is >= 0
impl CsrfConfigBuilder {
    pub fn new() -> Self {
        CsrfConfigBuilder {
            config: CsrfConfig::default(),
        }
    }

    pub fn ttl_seconds(mut self, ttl_seconds: i64) -> Self {
        self.config.ttl_seconds = ttl_seconds;
        self
    }

    pub fn build(self) -> CsrfConfig {
        self.config
    }
}

#[derive(Eq, PartialEq, Debug)]
pub struct CsrfToken {
    nonce: Vec<u8>,
}

impl CsrfToken {
    fn new(nonce: Vec<u8>) -> Self {
        CsrfToken {
            nonce: nonce
        }
    }

    pub fn b64_string(&self) -> Result<String, ()> {
        let mut transport = CsrfTokenTransport::new();
        transport.set_nonce(self.nonce.clone());
        transport.write_to_bytes()
            .map(|bytes| bytes.to_base64(STANDARD))
            .map_err(|_| ())
    }

    fn parse_b64(string: &str) -> Result<Self, ()> {
        let bytes = string.as_bytes().from_base64().map_err(|_| ())?;
        let mut transport = protobuf::core::parse_from_bytes::<CsrfTokenTransport>(&bytes).map_err(|_| ())?;

        let token = CsrfToken {
            nonce: transport.take_nonce()
        };
        Ok(token)
    }
}

pub trait CsrfProtection: Sized + Send + Sync {

    fn sign_bytes(&self, bytes: &[u8]) -> Vec<u8>;

    // TODO single source this
    fn verify_token_pair(&self, token: &CsrfToken, cookie: &CsrfCookie) -> bool;

    fn generate_token_pair(&self, ttl_seconds: i64) -> (CsrfToken, CsrfCookie) {
        let expires = time::precise_time_ns() + (ttl_seconds as u64) * 1_000_000;
        let nonce = vec!(0); // TODO
        let sig = self.sign_bytes(&nonce);
        (CsrfToken::new(nonce.clone()), CsrfCookie::new(expires, nonce, sig.to_vec()))
    }
}

pub struct Ed25519CsrfProtection {
    key_pair: Ed25519KeyPair,
    pub_key: Vec<u8>,
}

impl Ed25519CsrfProtection {
    pub fn new(key_pair: Ed25519KeyPair, pub_key: Vec<u8>) -> Self {
        Ed25519CsrfProtection {
            key_pair: key_pair,
            pub_key: pub_key,
        }
    }
}

impl CsrfProtection for Ed25519CsrfProtection {
    fn sign_bytes(&self, bytes: &[u8]) -> Vec<u8> {
        Vec::from(self.key_pair.sign(bytes).as_slice())
    }

    fn verify_token_pair(&self, token: &CsrfToken, cookie: &CsrfCookie) -> bool {
        let msg = untrusted::Input::from(token.nonce.as_slice());
        let sig = untrusted::Input::from(&cookie.signature);
        let valid_sig = signature::verify(&signature::ED25519,
                                          untrusted::Input::from(&self.pub_key),
                                          msg,
                                          sig)
            .is_ok();
        let nonces_match = token.nonce == cookie.nonce;
        let not_expired = cookie.expires > time::precise_time_ns();
        valid_sig && nonces_match && not_expired
    }
}

pub struct HmacCsrfProtection {
    key: SigningKey,
}

impl HmacCsrfProtection {
    pub fn new(key: SigningKey) -> Self {
        HmacCsrfProtection {
            key: key,
        }
    }
}

impl CsrfProtection for HmacCsrfProtection {
    fn sign_bytes(&self, bytes: &[u8]) -> Vec<u8> {
        let sig = hmac::sign(&self.key, bytes);
        Vec::from(sig.as_ref())
    }

    fn verify_token_pair(&self, token: &CsrfToken, cookie: &CsrfCookie) -> bool {
        let valid_sig = hmac::verify_with_own_key(&self.key, &token.nonce, &cookie.signature).is_ok();
        let nonces_match = token.nonce == cookie.nonce;
        let not_expired = cookie.expires > time::precise_time_ns();
        valid_sig && nonces_match && not_expired
    }
}

#[derive(Debug)]
struct CsrfError {
}

impl Error for CsrfError {
    fn description(&self) -> &str {
        "CsrfError"
    }
}

impl fmt::Display for CsrfError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self)
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

    fn validate_request(&self, mut request: &mut Request) -> IronResult<()> {
        match request.method {
            method::Post | method::Put | method::Patch | method::Delete => {
                let token_opt = self.extract_csrf_token(&mut request);
                let cookie_opt = self.extract_csrf_cookie(&request);
                match (token_opt, cookie_opt) {
                    (Some(token), Some(cookie)) => {
                        if self.protect.verify_token_pair(&token, &cookie) {
                            Ok(())
                        } else {
                            Err(IronError::new(CsrfError{},
                                               status::InternalServerError))
                        }
                    }
                    _ => Err(IronError::new(CsrfError{}, status::Forbidden)),
                }
            }
            _ => Ok(()),
        }
    }

    fn extract_csrf_cookie(&self, request: &Request) -> Option<CsrfCookie> {
        request.headers.get::<IronCookie>()
            .and_then(|raw_cookie| {
                raw_cookie.0.iter().filter_map(|c| {
                    Cookie::parse_encoded(c.clone()).ok()
                        .and_then(|cookie| {
                            match cookie.name_value() {
                                (CSRF_COOKIE_NAME, value) => Some(value.to_string()),
                                _ => None
                            }
                        })
                })
                .collect::<Vec<String>>()
                .first()
                .and_then(|string| protobuf::core::parse_from_bytes::<CsrfCookieTransport>(string.clone().into_bytes().as_slice()).ok())
            })
            .map(|mut transport| CsrfCookie::new(transport.get_expires(),
                                                 transport.take_nonce(),
                                                 transport.take_signature()))
    }

    fn extract_csrf_token(&self, mut request: &mut Request) -> Option<CsrfToken> {
        let f_token = self.extract_csrf_token_from_form(&mut request);
        let q_token = self.extract_csrf_token_from_query(&mut request);
        let h_token = self.extract_csrf_token_from_headers(&mut request);

        f_token.or(q_token).or(h_token)
    }

    fn extract_csrf_token_from_form(&self, mut request: &mut Request) -> Option<CsrfToken> {
        let token = request.get_ref::<UrlEncodedBody>()
            .ok()
            .and_then(|form| form.get("csrf-token"))
            .and_then(|v| v.first())
            .and_then(|token_str| CsrfToken::parse_b64(token_str).ok());

        // TODO remove token from form

        token
    }

    fn extract_csrf_token_from_query(&self, mut request: &mut Request) -> Option<CsrfToken> {
        let token = request.get_ref::<UrlEncodedQuery>()
            .ok()
            .and_then(|query| query.get("csrf-token"))
            .and_then(|v| v.first())
            .and_then(|token_str| CsrfToken::parse_b64(token_str).ok());

        // TODO remove token from query

        token
    }

    fn extract_csrf_token_from_headers(&self, mut request: &mut Request) -> Option<CsrfToken> {
        let token = request.headers
            .get::<XCsrfToken>()
            .and_then(|token_str| CsrfToken::parse_b64(token_str).ok());

        let _ = request.headers.remove::<XCsrfToken>();

        token
    }
}

impl<P: CsrfProtection + Sized + 'static, H: Handler> Handler for CsrfHandler<P, H> {
    fn handle(&self, mut request: &mut Request) -> IronResult<Response> {
        // before
        try!(self.validate_request(request));
        let (token, cookie) = self.protect.generate_token_pair(self.config.ttl_seconds);
        let _ = request.extensions.insert::<CsrfToken>(token);

        // main
        let mut response = self.handler.handle(&mut request)?;

        // after
        let nonce_str = cookie.nonce.as_slice().to_base64(STANDARD);
        let cookie = Cookie::build("csrf", nonce_str)
            .path("/")
            .http_only(true)
            .max_age(Duration::seconds(self.config.ttl_seconds))
            .finish();
        let cookie = format!("{}", cookie.encoded()); // TODO is this dumb?

        // TODO don't set cookie, append if Set-Cookie alread exists
        response.headers.set(SetCookie(vec![cookie]));

        Ok(response)
    }
}

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
    use ring::digest;
    use ring::rand::SystemRandom;
    use ring::signature::Ed25519KeyPair;

    #[test]
    fn test_csrf_token_serde() {
        let token = CsrfToken::new(b"fake signature".to_vec());
        let parsed = CsrfToken::parse_b64(&token.b64_string().unwrap()).unwrap();
        assert_eq!(token, parsed)
    }

    #[test]
    fn test_ed25519_csrf_protection() {
        let rng = SystemRandom::new();
        let (_, key_bytes) = Ed25519KeyPair::generate_serializable(&rng).unwrap();
        let key_pair = Ed25519KeyPair::from_bytes(&key_bytes.private_key, &key_bytes.public_key)
            .unwrap();
        let protect = Ed25519CsrfProtection::new(key_pair, key_bytes.public_key.to_vec());

        // check token validates
        let (token, cookie) = protect.generate_token_pair(300);
        assert!(protect.verify_token_pair(&token, &cookie));

        // check modified token doesn't validate
        let (mut token, cookie) = protect.generate_token_pair(300);
        token.nonce[0] = token.nonce[0] ^ 0x07;
        assert!(!protect.verify_token_pair(&token, &cookie));

        // check modified cookie  doesn't validate
        let (token, mut cookie) = protect.generate_token_pair(300);
        cookie.nonce[0] = cookie.nonce[0] ^ 0x07;
        assert!(!protect.verify_token_pair(&token, &cookie));

        // TODO check modified signature

        // check the token is invalid with ttl = 0 for tokens that are never valid
        let (token, cookie)= protect.generate_token_pair(0);
        assert!(!protect.verify_token_pair(&token, &cookie));
    }

    #[test]
    fn test_hmac_csrf_protection() {
        let rng = SystemRandom::new();
        let key = SigningKey::generate(&digest::SHA512, &rng).unwrap();
        let protect = HmacCsrfProtection::new(key);

        // check token validates
        let (token, cookie) = protect.generate_token_pair(300);
        assert!(protect.verify_token_pair(&token, &cookie));

        // check modified token doesn't validate
        let (mut token, cookie) = protect.generate_token_pair(300);
        token.nonce[0] = token.nonce[0] ^ 0x07;
        assert!(!protect.verify_token_pair(&token, &cookie));

        // check modified cookie  doesn't validate
        let (token, mut cookie) = protect.generate_token_pair(300);
        cookie.nonce[0] = cookie.nonce[0] ^ 0x07;
        assert!(!protect.verify_token_pair(&token, &cookie));

        // TODO check modified signature

        // check the token is invalid with ttl = 0 for tokens that are never valid
        let (token, cookie)= protect.generate_token_pair(0);
        assert!(!protect.verify_token_pair(&token, &cookie));
    }

    #[test]
    fn test_ed25519_middleware() {
        let rng = SystemRandom::new();
        let (_, key_bytes) = Ed25519KeyPair::generate_serializable(&rng).unwrap();
        let key_pair = Ed25519KeyPair::from_bytes(&key_bytes.private_key, &key_bytes.public_key)
            .unwrap();
        let protect = Ed25519CsrfProtection::new(key_pair, key_bytes.public_key.to_vec());
        let config = CsrfConfig::default();
        let _ = CsrfProtectionMiddleware::new(protect, config);

        // TODO test request/response with actual handler
    }

    // TODO test form extraction
    // TODO test query extraction
    // TODO test headers extraction
}
