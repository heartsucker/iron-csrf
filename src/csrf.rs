use std::error::Error;
use std::fmt;

use std::str;
use std::mem;

use chrono::Duration;
use chrono::prelude::*;
use iron::typemap;
use iron::method;
use iron::middleware::{AroundMiddleware, Handler};
use iron::prelude::*;
use iron::status;
use protobuf;
use protobuf::Message;
use ring::hmac;
use ring::hmac::SigningKey;
use ring::signature;
use ring::signature::Ed25519KeyPair;
use rustc_serialize::base64::{ToBase64, FromBase64, STANDARD};
use untrusted;
use urlencoded::{UrlEncodedQuery, UrlEncodedBody};

use serial::CsrfTokenTransport;

fn datetime_to_bytes(date: DateTime<UTC>) -> Vec<u8> {
    // TODO no unsafe
    unsafe { mem::transmute::<DateTime<UTC>, [u8; 12]>(date) }.to_vec()
}

fn bytes_to_datetime(bytes: &[u8]) -> DateTime<UTC> {
    if bytes.len() != 12 { panic!() } // TODO
    let mut arr = [0u8; 12];
    for (b, a) in bytes.iter().zip(arr.iter_mut()) {
        *a = *b
    }
    // TODO no unsafe
    unsafe { mem::transmute::<[u8; 12], DateTime<UTC>>(arr) }
}

/// HTTP header that `iron_csrf` uses to identify the CSRF token
header! { (XCsrfToken, "X-CSRF-Token") => [String] }

struct CsrfCookie {
    // TODO padding
    expires: DateTime<UTC>,
    nonce: Vec<u8>,
}

impl CsrfCookie {
    fn new(expires: DateTime<UTC>, nonce: Vec<u8>) -> Self {
        CsrfCookie {
            expires: expires,
            nonce: nonce,
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
    expires: DateTime<UTC>,
    signature: Vec<u8>,
}

impl CsrfToken {
    fn new(expires: DateTime<UTC>, signature: Vec<u8>) -> Self {
        CsrfToken {
            expires: expires,
            signature: signature,
        }
    }

    pub fn b64_string(&self) -> String {
        let mut transport = CsrfTokenTransport::new();
        transport.set_body(datetime_to_bytes(self.expires));
        transport.set_signature(self.signature.clone());

        let bytes = transport.write_to_bytes().unwrap(); // TODO unwrap is evil
        bytes.to_base64(STANDARD)
    }

    pub fn parse_b64(string: &str) -> Option<Self> {
        let bytes = string.as_bytes().from_base64().unwrap(); // TODO unwrap
        let mut transport = protobuf::core::parse_from_bytes::<CsrfTokenTransport>(&bytes).unwrap(); // TODO unwrap

        let dt_bytes = transport.take_body();
        let dt = bytes_to_datetime(&dt_bytes);

        let token = CsrfToken {
            expires: dt,
            signature: transport.take_signature(),
        };
        Some(token)
    }
}

pub trait CsrfProtection: Sized + Send + Sync {
    fn sign_bytes(&self, bytes: &[u8]) -> Vec<u8>;
    fn validate_token(&self, token: &CsrfToken) -> Result<bool, String>;

    fn generate_token(&self, ttl_seconds: i64) -> CsrfToken {
        let expires = UTC::now() + Duration::seconds(ttl_seconds);
        let expires_bytes = datetime_to_bytes(expires);
        let msg = expires_bytes.as_ref();
        let sig = self.sign_bytes(msg);
        CsrfToken::new(expires, sig)
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

    fn validate_token(&self, token: &CsrfToken) -> Result<bool, String> {
        let expires_bytes = datetime_to_bytes(token.expires);
        let msg = untrusted::Input::from(expires_bytes.as_ref());
        let sig = untrusted::Input::from(&token.signature);
        let valid_sig = signature::verify(&signature::ED25519,
                                          untrusted::Input::from(&self.pub_key),
                                          msg,
                                          sig)
            .is_ok();
        Ok(valid_sig && UTC::now() < token.expires)
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

    fn validate_token(&self, token: &CsrfToken) -> Result<bool, String> {
        let expires_bytes = datetime_to_bytes(token.expires);
        let msg = expires_bytes.as_ref();
        let valid_sig = hmac::verify_with_own_key(&self.key, msg, &token.signature).is_ok();
        let not_expired = UTC::now() < token.expires;
        Ok(valid_sig && not_expired)
    }
}

#[derive(Debug)]
enum CsrfError {
    TokenValidationError,
    TokenInvalid,
    TokenMissing,
}

impl Error for CsrfError {
    fn description(&self) -> &str {
        "TODO"
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
                match self.extract_csrf_token(&mut request) {
                    None => Err(IronError::new(CsrfError::TokenMissing, status::Forbidden)),
                    Some(token) => {
                        match self.protect.validate_token(&token) {
                            Ok(true) => Ok(()),
                            Ok(false) => {
                                Err(IronError::new(CsrfError::TokenInvalid, status::Forbidden))
                            }
                            Err(_) => {
                                Err(IronError::new(CsrfError::TokenValidationError,
                                                   status::InternalServerError))
                            }
                        }
                    }
                }
            }
            _ => Ok(()),
        }
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
            .and_then(|token_str| CsrfToken::parse_b64(token_str));

        // TODO remove token from form

        token
    }

    fn extract_csrf_token_from_query(&self, mut request: &mut Request) -> Option<CsrfToken> {
        let token = request.get_ref::<UrlEncodedQuery>()
            .ok()
            .and_then(|query| query.get("csrf-token"))
            .and_then(|v| v.first())
            .and_then(|token_str| CsrfToken::parse_b64(token_str));

        // TODO remove token from query

        token
    }

    fn extract_csrf_token_from_headers(&self, mut request: &mut Request) -> Option<CsrfToken> {
        let token = request.headers
            .get::<XCsrfToken>()
            .and_then(|token_str| CsrfToken::parse_b64(token_str));

        let _ = request.headers.remove::<XCsrfToken>();

        token
    }
}

impl<P: CsrfProtection + Sized + 'static, H: Handler> Handler for CsrfHandler<P, H> {
    fn handle(&self, mut request: &mut Request) -> IronResult<Response> {
        // before
        try!(self.validate_request(request));
        let token = self.protect.generate_token(self.config.ttl_seconds);
        let _ = request.extensions.insert::<CsrfToken>(token);

        // main
        let response = self.handler.handle(&mut request)?;

        // after
        // TODO 

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
    fn test_datetime_serde() {
        let dt = UTC.ymd(2017, 1, 2).and_hms(3, 4, 5);
        let bytes = datetime_to_bytes(dt);
        let dt2 = bytes_to_datetime(&bytes);
        assert_eq!(dt, dt2);
    }

    #[test]
    fn test_csrf_token_serde() {
        let dt = UTC.ymd(2017, 1, 2).and_hms(3, 4, 5);
        let token = CsrfToken::new(dt, b"fake signature".to_vec());
        let parsed = CsrfToken::parse_b64(&token.b64_string()).unwrap();
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
        let token = protect.generate_token(300);
        assert!(protect.validate_token(&token).unwrap());

        // check modified token doesn't validate
        let mut token = protect.generate_token(300);
        token.expires = token.expires + Duration::seconds(1);
        assert!(!protect.validate_token(&token).unwrap());

        // check modified signature doesn't validate
        let mut token = protect.generate_token(300);
        token.signature[0] = token.signature[0] ^ 0x07;
        assert!(!protect.validate_token(&token).unwrap());

        // check the token is invalid with ttl = -1 for tokens that are never valid
        let token = protect.generate_token(-1);
        assert!(!protect.validate_token(&token).unwrap());
    }

    #[test]
    fn test_hmac_csrf_protection() {
        let rng = SystemRandom::new();
        let key = SigningKey::generate(&digest::SHA512, &rng).unwrap();
        let protect = HmacCsrfProtection::new(key);

        // check token validates
        let token = protect.generate_token(300);
        assert!(protect.validate_token(&token).unwrap());

        // check modified token doesn't validate
        let mut token = protect.generate_token(300);
        token.expires = token.expires + Duration::seconds(1);
        assert!(!protect.validate_token(&token).unwrap());

        // check modified signature doesn't validate
        let mut token = protect.generate_token(300);
        token.signature[0] = token.signature[0] ^ 0x07;
        assert!(!protect.validate_token(&token).unwrap());

        // check the token is invalid with ttl = -1 for tokens that are never valid
        let token = protect.generate_token(-1);
        assert!(!protect.validate_token(&token).unwrap());
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

        // TODO test chain
    }

    // TODO test form extraction
    // TODO test query extraction
    // TODO test headers extraction
}
