use std::str;

use ring::signature;
use ring::signature::Ed25519KeyPair;
use rustc_serialize::json;
use rustc_serialize::base64::{ToBase64, FromBase64, STANDARD};

use untrusted;

#[derive(Eq, PartialEq, Hash, Clone, Debug, RustcEncodable, RustcDecodable)]
pub struct CsrfToken {
    message: Vec<u8>,
    signature: Vec<u8>,
}

unsafe impl Sync for CsrfToken {}
unsafe impl Send for CsrfToken {}

impl CsrfToken {
    fn new(message: Vec<u8>, signature: Vec<u8>) -> Self {
        CsrfToken {
            message: message,
            signature: signature,
        }
    }

    pub fn b64_string(&self) -> String {
        json::encode(&self).unwrap().as_bytes().to_base64(STANDARD) // TODO unwrap is evil
    }

    pub fn parse_b64(string: &str) -> Option<Self> {
        string.as_bytes().from_base64().ok()
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
    fn generate_token(&self) -> Result<CsrfToken, String> {
        let msg = String::from("TODO").into_bytes(); // TODO use a timestamp & nonce
        // TODO encrypt message
		let sig = Vec::from(self.key_pair.sign(msg.as_slice()).as_slice());
		Ok(CsrfToken::new(msg, sig))
    }
    
    fn validate_token(&self, token: &CsrfToken) -> Result<bool, String> {
		let msg = untrusted::Input::from(token.message.as_slice());
		let sig = untrusted::Input::from(token.signature.as_slice());
		Ok(signature::verify(&signature::ED25519,
							 untrusted::Input::from(self.pub_key.as_slice()),
                             msg, sig).is_ok())
	}
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::rand::SystemRandom;

    #[test]
    fn test_csrf_token_serde() {
        let token = CsrfToken::new(b"some message".to_vec(), b"the signature".to_vec());
        let parsed = CsrfToken::parse_b64(token.b64_string().as_str()).unwrap();
        assert_eq!(token, parsed)
    }

    #[test]
    fn test_ed25519_csrf_protection() {
        let rng = SystemRandom::new();
        let (_, key_bytes) = Ed25519KeyPair::generate_serializable(&rng).unwrap();
        let key_pair = Ed25519KeyPair::from_bytes(&key_bytes.private_key, &key_bytes.public_key).unwrap();
        let protect = Ed25519CsrfProtection::new(key_pair, key_bytes.public_key.to_vec());

        // check token validates
        let token = protect.generate_token().unwrap();
        assert!(protect.validate_token(&token).unwrap());

        // check modified token doesn't validate
        let mut token = protect.generate_token().unwrap();
        token.message[0] = token.message[0] ^ 0x07;
        assert!(!protect.validate_token(&token).unwrap());

        // check modified signature doesn't validate
        let mut token = protect.generate_token().unwrap();
        token.signature[0] = token.signature[0] ^ 0x07;
        assert!(!protect.validate_token(&token).unwrap());
    }
}
