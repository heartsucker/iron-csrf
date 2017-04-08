//! Module containing the core functionality for CSRF protection.

use std::collections::HashSet;
use std::str;

use chrono::Duration;
use cookie::Cookie;
use csrf::{CSRF_COOKIE_NAME, CSRF_FORM_FIELD, CSRF_HEADER, CSRF_QUERY_STRING, CsrfToken,
           CsrfProtection, CsrfError};
use iron::headers::{SetCookie, Cookie as IronCookie};
use iron::method;
use iron::middleware::{AroundMiddleware, Handler};
use iron::prelude::*;
use iron::status;
use rustc_serialize::base64::FromBase64;
use urlencoded::{UrlEncodedQuery, UrlEncodedBody};


fn iron_error(err: CsrfError) -> IronError {
    IronError {
        response: Response::with((status::Forbidden, format!("{}", err))),
        error: Box::new(err),
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

/// The configuation used to initialize `CsrfProtectionMiddleware`.
pub struct CsrfConfig {
    // TODO make this an Option
    ttl_seconds: i64,
    protected_methods: HashSet<method::Method>,
    secure_cookie: bool,
}

impl CsrfConfig {
    /// Create a new builder that is initialized with the default configuration.
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

impl<P: CsrfProtection + 'static, H: Handler> Handler for CsrfHandler<P, H> {
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
            .generate_token_pair(token_opt.map(|t| t.token().to_vec()),
                                 self.config.ttl_seconds)
            .map_err(iron_error)?;
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
pub struct CsrfProtectionMiddleware<P: CsrfProtection> {
    protect: P,
    config: CsrfConfig,
}

impl<P: CsrfProtection> CsrfProtectionMiddleware<P> {
    pub fn new(protect: P, config: CsrfConfig) -> Self {
        CsrfProtectionMiddleware {
            protect: protect,
            config: config,
        }
    }
}

impl<P: CsrfProtection + 'static> AroundMiddleware for CsrfProtectionMiddleware<P> {
    fn around(self, handler: Box<Handler>) -> Box<Handler> {
        Box::new(CsrfHandler::new(self.protect, self.config, handler))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use csrf::AesGcmCsrfProtection;
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
        let protect = AesGcmCsrfProtection::from_password(password);
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

    fn get_middleware() -> CsrfProtectionMiddleware<AesGcmCsrfProtection> {
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

            assert_eq!(form_data.get(TEST_QUERY_PARAM),
                       Some(&vec![TEST_QUERY_VALUE.to_string()]));
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

            assert_eq!(form_data.get(TEST_QUERY_PARAM),
                       Some(&vec![TEST_QUERY_VALUE.to_string()]));
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
        let body = format!("{}={}&{}={}",
                           CSRF_QUERY_STRING,
                           csrf_token.b64_url_string(),
                           TEST_QUERY_PARAM,
                           TEST_QUERY_VALUE);
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
        assert!(set_cookie.0
            .iter()
            .find(|c| c.contains(TEST_COOKIE_NAME) && c.contains(TEST_COOKIE_VALUE))
            .is_some())
    }

    // TODO test that verifies protected_method feature/configuration

}
