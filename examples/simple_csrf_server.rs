extern crate iron;
extern crate iron_csrf;

use iron::AroundMiddleware;
use iron::headers::ContentType;
use iron::method;
use iron::prelude::*;
use iron::status;

use iron_csrf::{CsrfToken, CsrfProtectionMiddleware, CsrfConfig, ChaCha20Poly1305CsrfProtection};

fn main() {
    // generate some crypto keys
    // TODO

    // initialize the CSRF protection
    let password = b"very-very-secret";
    let protect = ChaCha20Poly1305CsrfProtection::from_password(password).unwrap();
    let config = CsrfConfig::default();
    let middleware = CsrfProtectionMiddleware::new(protect, config);

    let handler = middleware.around(Box::new(index));

    // awwwww yissssssss
    Iron::new(handler).http("localhost:8080").unwrap();
}


fn index(request: &mut Request) -> IronResult<Response> {
    let mut response = match request.method {
        method::Post => Response::with((status::Ok, include_str!("./post.html"))),
        _ => {
            let token = request.extensions.get::<CsrfToken>().unwrap();

            // in the real world, one would use something like handlebars
            // instead of this hackiness
            let html = include_str!("./get.html")
                .replace("CSRF_TOKEN", token.b64_string().as_str());

            Response::with((status::Ok, html))
        }
    };

    response.headers.set(ContentType::html());

    Ok(response)
}
