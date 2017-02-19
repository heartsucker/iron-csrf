use std::error::Error;
use std::fmt;

use iron::typemap;
use iron::method;
use iron::middleware::BeforeMiddleware;
use iron::prelude::*;
use iron::status;
use urlencoded::{UrlEncodedQuery, UrlEncodedBody};

use csrf::{CsrfProtection, CsrfToken};

pub struct CsrfProtectionMiddleware<T: CsrfProtection> {
    protect: T,
    // TODO add ttl
}

impl <T: CsrfProtection> CsrfProtectionMiddleware<T> {
    pub fn new(protect: T) -> Self {
        CsrfProtectionMiddleware {
            protect: protect,
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
                            Ok(false) => Err(IronError::new(CsrfError::TokenInvalid, status::Forbidden)),
                            Err(_) => Err(IronError::new(CsrfError::TokenValidationError, status::InternalServerError)),
                        }
                    },
                }
            },
            _ => Ok(()),
        }
    }

    fn extract_csrf_token(&self, mut request: &mut Request) -> Option<CsrfToken> {
        // TODO headers X-CSRF-Token        
        // TODO form field csrf-token
        let f_token = self.extract_csrf_token_from_form(&mut request);
        let q_token = self.extract_csrf_token_from_query(&mut request);

        f_token.or(q_token)
    }

    fn extract_csrf_token_from_form(&self, mut request: &mut Request) -> Option<CsrfToken> {
        request.get_ref::<UrlEncodedBody>().ok()
            .and_then(|form| form.get("csrf-token"))
            .and_then(|v| v.first())
            .and_then(|token_str| CsrfToken::parse_b64(token_str))
        // TODO remove token from form 
    }

    fn extract_csrf_token_from_query(&self, mut request: &mut Request) -> Option<CsrfToken> {
        request.get_ref::<UrlEncodedQuery>().ok()
            .and_then(|query| query.get("x-csrf-token"))
            .and_then(|v| v.first())
            .and_then(|token_str| CsrfToken::parse_b64(token_str))
        // TODO remove token from query
    }
}

#[derive(Debug)]
enum CsrfError {
    TokenValidationError,
    TokenInvalid,
    TokenMissing,
    TokenGenerationError,
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

impl <T: CsrfProtection + 'static>BeforeMiddleware for CsrfProtectionMiddleware<T> {
    fn before(&self, request: &mut Request) -> IronResult<()> {
        try!(self.validate_request(request));

        match self.protect.generate_token() {
            Ok(token) => {
                let _ = request.extensions.insert::<CsrfToken>(token);
                Ok(())
            },
            Err(_) => Err(IronError::new(CsrfError::TokenGenerationError, status::InternalServerError)),
        }
    }

    fn catch(&self, _: &mut Request, _: IronError) -> IronResult<()> {
        Ok(()) // TODO
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::rand::SystemRandom;
    use ring::signature::Ed25519KeyPair;
    use csrf::Ed25519CsrfProtection;

    #[test]
    fn test_ed25519_middleware() {
        let rng = SystemRandom::new();
        let (_, key_bytes) = Ed25519KeyPair::generate_serializable(&rng).unwrap();
        let key_pair = Ed25519KeyPair::from_bytes(&key_bytes.private_key, &key_bytes.public_key).unwrap();
        let protect = Ed25519CsrfProtection::new(key_pair, key_bytes.public_key.to_vec());
        let _ = CsrfProtectionMiddleware::new(protect);
        // TODO more
    }
}
