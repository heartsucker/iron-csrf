use std::str;
use std::mem;

use chrono::Duration;
use chrono::prelude::*;
use ring::hmac;
use ring::hmac::SigningKey;
use ring::signature;
use ring::signature::Ed25519KeyPair;
use rustc_serialize::json;
use rustc_serialize::base64::{ToBase64, FromBase64, STANDARD};

use untrusted;

fn datetime_bytes(date: DateTime<UTC>) -> [u8; 12] {
    unsafe { mem::transmute::<DateTime<UTC>, [u8; 12]>(date) }
}

#[derive(Eq, PartialEq, Debug, RustcEncodable, RustcDecodable)]
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
        json::encode(&self).unwrap().as_bytes().to_base64(STANDARD) // TODO unwrap is evil
    }

    pub fn parse_b64(string: &str) -> Option<Self> {
        string.as_bytes()
            .from_base64()
            .ok()
            .and_then(|s| str::from_utf8(&s).ok().map(|s| s.to_string()))
            .and_then(|s| json::decode(&s.as_str()).ok())
    }
}

pub trait CsrfProtection: Send + Sync {
    fn generate_token(&self) -> Result<CsrfToken, String>;
    fn validate_token(&self, token: &CsrfToken) -> Result<bool, String>;
}

pub struct Ed25519CsrfProtection {
    key_pair: Ed25519KeyPair,
    pub_key: Vec<u8>,
    ttl_seconds: i64,
}

impl Ed25519CsrfProtection {
    pub fn new(key_pair: Ed25519KeyPair, pub_key: Vec<u8>, ttl_seconds: Option<i64>) -> Self {
        Ed25519CsrfProtection {
            key_pair: key_pair,
            pub_key: pub_key,
            ttl_seconds: ttl_seconds.unwrap_or(3_600_000),
        }
    }
}

impl CsrfProtection for Ed25519CsrfProtection {
    fn generate_token(&self) -> Result<CsrfToken, String> {
        let expires = UTC::now() + Duration::seconds(self.ttl_seconds);
        let expires_bytes = datetime_bytes(expires);
        let msg = expires_bytes.as_ref();
        let sig = Vec::from(self.key_pair.sign(msg).as_slice());
        Ok(CsrfToken::new(expires, sig))
    }

    fn validate_token(&self, token: &CsrfToken) -> Result<bool, String> {
        let expires_bytes = datetime_bytes(token.expires);
        let msg = untrusted::Input::from(expires_bytes.as_ref());
        let sig = untrusted::Input::from(token.signature.as_slice());
        let valid_sig = signature::verify(&signature::ED25519,
                                          untrusted::Input::from(self.pub_key.as_slice()),
                                          msg,
                                          sig)
            .is_ok();
        Ok(valid_sig && UTC::now() < token.expires)
    }
}

pub struct HmacCsrfProtection {
    key: SigningKey,
    ttl_seconds: i64,
}

impl HmacCsrfProtection {
    pub fn new(key: SigningKey, ttl_seconds: Option<i64>) -> Self {
        HmacCsrfProtection {
            key: key,
            ttl_seconds: ttl_seconds.unwrap_or(3_600_000),
        }
    }
}

impl CsrfProtection for HmacCsrfProtection {
    fn generate_token(&self) -> Result<CsrfToken, String> {
        let expires = UTC::now() + Duration::seconds(self.ttl_seconds);
        let expires_bytes = datetime_bytes(expires);
        let msg = expires_bytes.as_ref();
        let sig = hmac::sign(&self.key, msg);
        Ok(CsrfToken::new(expires, Vec::from(sig.as_ref())))
    }

    fn validate_token(&self, token: &CsrfToken) -> Result<bool, String> {
        let expires_bytes = datetime_bytes(token.expires);
        let msg = expires_bytes.as_ref();
        let sig = token.signature.as_slice();
        let valid_sig = hmac::verify_with_own_key(&self.key, msg, sig).is_ok();
        Ok(valid_sig && UTC::now() < token.expires)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::digest;
    use ring::rand::SystemRandom;

    #[test]
    fn test_csrf_token_serde() {
        let token = CsrfToken::new(UTC::now(), b"fake signature".to_vec());
        let parsed = CsrfToken::parse_b64(token.b64_string().as_str()).unwrap();
        assert_eq!(token, parsed)
    }

    #[test]
    fn test_ed25519_csrf_protection() {
        let rng = SystemRandom::new();
        let (_, key_bytes) = Ed25519KeyPair::generate_serializable(&rng).unwrap();
        let key_pair = Ed25519KeyPair::from_bytes(&key_bytes.private_key, &key_bytes.public_key)
            .unwrap();
        let protect = Ed25519CsrfProtection::new(key_pair, key_bytes.public_key.to_vec(), None);

        // check token validates
        let token = protect.generate_token().unwrap();
        assert!(protect.validate_token(&token).unwrap());

        // check modified token doesn't validate
        let mut token = protect.generate_token().unwrap();
        token.expires = token.expires + Duration::seconds(1);
        assert!(!protect.validate_token(&token).unwrap());

        // check modified signature doesn't validate
        let mut token = protect.generate_token().unwrap();
        token.signature[0] = token.signature[0] ^ 0x07;
        assert!(!protect.validate_token(&token).unwrap());

        // create a new protection with ttl = -1 for tokens that are never valid
        let key_pair = Ed25519KeyPair::from_bytes(&key_bytes.private_key, &key_bytes.public_key)
            .unwrap();
        let protect = Ed25519CsrfProtection::new(key_pair, key_bytes.public_key.to_vec(), Some(-1));

        // check the token is invalid
        let token = protect.generate_token().unwrap();
        assert!(!protect.validate_token(&token).unwrap());
    }

    #[test]
    fn test_hmac_csrf_protection() {
        let rng = SystemRandom::new();
        let key = SigningKey::generate(&digest::SHA512, &rng).unwrap();
        let protect = HmacCsrfProtection::new(key, None);

        // check token validates
        let token = protect.generate_token().unwrap();
        assert!(protect.validate_token(&token).unwrap());

        // check modified token doesn't validate
        let mut token = protect.generate_token().unwrap();
        token.expires = token.expires + Duration::seconds(1);
        assert!(!protect.validate_token(&token).unwrap());

        // check modified signature doesn't validate
        let mut token = protect.generate_token().unwrap();
        token.signature[0] = token.signature[0] ^ 0x07;
        assert!(!protect.validate_token(&token).unwrap());

        // create a new protection with ttl = -1 for tokens that are never valid
        let key = SigningKey::generate(&digest::SHA512, &rng).unwrap();
        let protect = HmacCsrfProtection::new(key, Some(-1));

        // check the token is invalid
        let token = protect.generate_token().unwrap();
        assert!(!protect.validate_token(&token).unwrap());
    }
}
