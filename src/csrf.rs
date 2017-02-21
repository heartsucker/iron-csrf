use std::str;
use std::mem;

use chrono::Duration;
use chrono::prelude::*;
use protobuf;
use protobuf::Message;
use ring::hmac;
use ring::hmac::SigningKey;
use ring::signature;
use ring::signature::Ed25519KeyPair;
use rustc_serialize::base64::{ToBase64, FromBase64, STANDARD};
use untrusted;

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

pub trait CsrfProtection: Send + Sync {
    fn generate_token(&self, ttl_seconds: i64) -> Result<CsrfToken, String>;
    fn validate_token(&self, token: &CsrfToken) -> Result<bool, String>;
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
    fn generate_token(&self, ttl_seconds: i64) -> Result<CsrfToken, String> {
        let expires = UTC::now() + Duration::seconds(ttl_seconds);
        let expires_bytes = datetime_to_bytes(expires);
        let msg = expires_bytes.as_ref();
        let sig = Vec::from(self.key_pair.sign(msg).as_slice());
        Ok(CsrfToken::new(expires, sig))
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
    fn generate_token(&self, ttl_seconds: i64) -> Result<CsrfToken, String> {
        let expires = UTC::now() + Duration::seconds(ttl_seconds);
        let expires_bytes = datetime_to_bytes(expires);
        let msg = expires_bytes.as_ref();
        let sig = hmac::sign(&self.key, msg);
        Ok(CsrfToken::new(expires, Vec::from(sig.as_ref())))
    }

    fn validate_token(&self, token: &CsrfToken) -> Result<bool, String> {
        let expires_bytes = datetime_to_bytes(token.expires);
        let msg = expires_bytes.as_ref();
        let valid_sig = hmac::verify_with_own_key(&self.key, msg, &token.signature).is_ok();
        let not_expired = UTC::now() < token.expires;
        Ok(valid_sig && not_expired)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::digest;
    use ring::rand::SystemRandom;

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
        let token = protect.generate_token(300).unwrap();
        assert!(protect.validate_token(&token).unwrap());

        // check modified token doesn't validate
        let mut token = protect.generate_token(300).unwrap();
        token.expires = token.expires + Duration::seconds(1);
        assert!(!protect.validate_token(&token).unwrap());

        // check modified signature doesn't validate
        let mut token = protect.generate_token(300).unwrap();
        token.signature[0] = token.signature[0] ^ 0x07;
        assert!(!protect.validate_token(&token).unwrap());

        // check the token is invalid with ttl = -1 for tokens that are never valid
        let token = protect.generate_token(-1).unwrap();
        assert!(!protect.validate_token(&token).unwrap());
    }

    #[test]
    fn test_hmac_csrf_protection() {
        let rng = SystemRandom::new();
        let key = SigningKey::generate(&digest::SHA512, &rng).unwrap();
        let protect = HmacCsrfProtection::new(key);

        // check token validates
        let token = protect.generate_token(300).unwrap();
        assert!(protect.validate_token(&token).unwrap());

        // check modified token doesn't validate
        let mut token = protect.generate_token(300).unwrap();
        token.expires = token.expires + Duration::seconds(1);
        assert!(!protect.validate_token(&token).unwrap());

        // check modified signature doesn't validate
        let mut token = protect.generate_token(300).unwrap();
        token.signature[0] = token.signature[0] ^ 0x07;
        assert!(!protect.validate_token(&token).unwrap());

        // check the token is invalid with ttl = -1 for tokens that are never valid
        let token = protect.generate_token(-1).unwrap();
        assert!(!protect.validate_token(&token).unwrap());
    }
}
