extern crate iron;
extern crate iron_csrf;
extern crate ring;

use iron::headers::ContentType;
use iron::method;
use iron::prelude::*;
use iron::status;
use ring::rand::SystemRandom;
use ring::signature::Ed25519KeyPair;

use iron_csrf::middleware::CsrfProtectionMiddleware;
use iron_csrf::csrf::{Ed25519CsrfProtection, CsrfToken};

fn main() {
    // generate some crypto keys
    let rng = SystemRandom::new();
    let (_, key_bytes) = Ed25519KeyPair::generate_serializable(&rng).unwrap();
    let key_pair = Ed25519KeyPair::from_bytes(&key_bytes.private_key,
                                              &key_bytes.public_key).unwrap();

    // initialize the CSRF protection
    let protect = Ed25519CsrfProtection::new(key_pair,
                                             key_bytes.public_key.to_vec());
    let middleware = CsrfProtectionMiddleware::new(protect);

    // build the middleware chain
    let mut chain = Chain::new(index); 
    chain.link_before(middleware);

    // awwwww yissssssss
    Iron::new(chain).http("localhost:8080").unwrap();
}


fn index(request: &mut Request) -> IronResult<Response> {
    let mut response = match request.method {
        method::Post => {
            Response::with((status::Ok, include_str!("./post.html")))
        }
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
