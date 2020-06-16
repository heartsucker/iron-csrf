use iron::AroundMiddleware;
use iron::headers::ContentType;
use iron::method;
use iron::prelude::*;
use iron::status;

use csrf::{CsrfToken, AesGcmCsrfProtection};
use iron_csrf::{CsrfProtectionMiddleware, CsrfConfig};

use simplelog::{CombinedLogger, LevelFilter, TermLogger, TerminalMode};

fn main() {
    CombinedLogger::init(vec![
        TermLogger::new(LevelFilter::Debug, simplelog::Config::default(), TerminalMode::Stdout),
    ])
    .unwrap();

    // initialize the CSRF protection
    let key = *b"01234567012345670123456701234567";
    let protect = AesGcmCsrfProtection::from_key(key);
    let config = CsrfConfig::default();
    let middleware = CsrfProtectionMiddleware::new(protect, config);

    // wrap the routes
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
            let html =
                include_str!("./get.html").replace("CSRF_TOKEN", token.b64_url_string().as_str());

            Response::with((status::Ok, html))
        }
    };

    response.headers.set(ContentType::html());

    Ok(response)
}
