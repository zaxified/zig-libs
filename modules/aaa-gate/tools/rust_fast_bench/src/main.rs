// SPDX-License-Identifier: MIT

// Rust side of the "fastest in the field" part of the aaa-gate benchmark
// (modules/aaa-gate/tools/bench.zig; `go_bench/` is the labstack/echo
// reference, `go_fast_bench/` the Go contenders). Same request bytes
// (`<work dir>/<workload>.wire`), same layer: a tower `Service` stack
// (tower-http 0.7.1 `ValidateRequestHeaderLayer` around a trivial inner
// service), requests parsed once outside the timed region (a `http::Request`
// per wire), no sockets, response rendered (status line, headers, body) into a
// buffer.
//
//	rust_fast_bench <work dir> <workload>
//
// tower-http ships no key gate: its `bearer`/`basic` built-ins (deprecated since
// 0.6.7, "too basic to be useful") compare ONE fixed header value with `==`
// (HeaderValue equality = memcmp, early exit, secret kept in memory). So:
//
//   <w>          VERDICT: `ValidateRequestHeaderLayer::custom` with a hand-written
//                validator that gives aaa-gate's guarantee (like for like, owner
//                decision 2026-10-17): SHA-256 digests only, the presented value
//                hashed and compared against EVERY digest with `subtle`, no early
//                exit. The extraction (strip "Bearer ", "Basic " + base64, header,
//                query) is this program's code: the layer is the framework, the
//                gate is ours-in-Rust, so these rows measure what an idiomatic
//                Rust gate costs, not a product.
//   <w>_builtin  INFORMATION ONLY: tower-http's own `bearer`/`basic`/
//                `has_header_value` built-ins. They hold ONE token, so three
//                services (one per configured key) are built and request i goes to
//                service i % 3 (it keeps the status sums equal; no real deployment
//                is wired like this). Not a like-for-like guarantee (no digests,
//                `==` compare).
//   <w>_plain    the same stack without the validator (the twin the Zig side
//                subtracts; it pays the same Request clone).
//
// Output: `name<TAB>ns/op<TAB>count`; one op = every request (64) once; count =
// sum of status codes. Timing as in go_bench: double the batch until it takes
// over 100 ms, then best of five.
#![allow(deprecated)]

use base64::Engine as _;
use http::{header, HeaderName, HeaderValue, Method, Request, Response, StatusCode};
use sha2::{Digest, Sha256};
use std::future::{ready, Future, Ready};
use std::hint::black_box;
use std::pin::pin;
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};
use subtle::ConstantTimeEq;
use tower_http::auth::require_authorization::{Basic, Bearer};
use tower_http::validate_request::{RequiredHeaderValue, ValidateRequestHeader, ValidateRequestHeaderLayer};
use tower_layer::Layer;
use tower_service::Service;

type Body = Vec<u8>;

const KEYS: [&str; 3] = [
    "tok-alpha-0123456789abcdef",
    "tok-bravo-0123456789abcdef",
    "tok-charlie-0123456789abcd",
];

fn sha(b: &[u8]) -> [u8; 32] {
    Sha256::digest(b).into()
}

/// Compare against every digest, no early exit.
fn digest_match(set: &[[u8; 32]], d: &[u8; 32]) -> bool {
    let mut found = 0u8;
    for s in set {
        found |= s.ct_eq(d).unwrap_u8();
    }
    found == 1
}

fn deny(www: Option<&'static str>) -> Response<Body> {
    let mut r = Response::new(b"Unauthorized\n".to_vec());
    *r.status_mut() = StatusCode::UNAUTHORIZED;
    r.headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static("text/plain; charset=utf-8"));
    if let Some(w) = www {
        r.headers_mut().insert(header::WWW_AUTHENTICATE, HeaderValue::from_static(w));
    }
    r
}

#[derive(Clone, Copy, PartialEq)]
enum Kind {
    Bearer,
    ApiHeader,
    ApiQuery,
    Basic,
}

/// The verdict validator (digests only, every digest compared).
#[derive(Clone)]
struct Hashed {
    kind: Kind,
    digests: Vec<[u8; 32]>,
}

impl Hashed {
    fn new(kind: Kind) -> Self {
        let digests = match kind {
            Kind::Basic => (0..3).map(|i| sha(format!("user-{}:{}", i, KEYS[i]).as_bytes())).collect(),
            _ => KEYS.iter().map(|k| sha(k.as_bytes())).collect(),
        };
        Hashed { kind, digests }
    }
}

impl<B> tower_http::validate_request::ValidateRequest<B> for Hashed {
    type ResponseBody = Body;
    fn validate(&mut self, req: &mut Request<B>) -> Result<(), Response<Body>> {
        let (presented, www): (Option<Vec<u8>>, &'static str) = match self.kind {
            Kind::Bearer => (
                req.headers()
                    .get(header::AUTHORIZATION)
                    .and_then(|v| v.as_bytes().strip_prefix(b"Bearer "))
                    .map(|t| t.to_vec()),
                "Bearer",
            ),
            Kind::ApiHeader => (
                req.headers().get("x-api-key").map(|v| v.as_bytes().to_vec()),
                "ApiKey",
            ),
            Kind::ApiQuery => (
                req.uri().query().and_then(|q| {
                    q.split('&')
                        .find_map(|p| p.strip_prefix("api_key="))
                        .map(|v| v.as_bytes().to_vec())
                }),
                "ApiKey",
            ),
            Kind::Basic => (
                req.headers()
                    .get(header::AUTHORIZATION)
                    .and_then(|v| v.as_bytes().strip_prefix(b"Basic "))
                    .and_then(|b| base64::engine::general_purpose::STANDARD.decode(b).ok()),
                "Basic",
            ),
        };
        match presented {
            Some(p) if !p.is_empty() && digest_match(&self.digests, &sha(&p)) => Ok(()),
            _ => Err(deny(Some(www))),
        }
    }
}

#[derive(Clone)]
struct Inner;
impl<B> Service<Request<B>> for Inner {
    type Response = Response<Body>;
    type Error = std::convert::Infallible;
    type Future = Ready<Result<Response<Body>, Self::Error>>;
    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }
    fn call(&mut self, _: Request<B>) -> Self::Future {
        let mut r = Response::new(b"ok".to_vec());
        r.headers_mut()
            .insert(header::CONTENT_TYPE, HeaderValue::from_static("text/plain; charset=utf-8"));
        ready(Ok(r))
    }
}

/// What a server would put on the wire.
fn render(r: &Response<Body>, out: &mut Vec<u8>) {
    out.clear();
    out.extend_from_slice(b"HTTP/1.1 ");
    out.extend_from_slice(r.status().as_str().as_bytes());
    out.push(b' ');
    out.extend_from_slice(r.status().canonical_reason().unwrap_or("").as_bytes());
    out.extend_from_slice(b"\r\n");
    for (k, v) in r.headers() {
        out.extend_from_slice(k.as_str().as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(v.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"content-length: ");
    out.extend_from_slice(r.body().len().to_string().as_bytes());
    out.extend_from_slice(b"\r\n\r\n");
    out.extend_from_slice(r.body());
}

fn parse_wire(w: &[u8]) -> Request<()> {
    let s = std::str::from_utf8(w).unwrap();
    let mut lines = s.split("\r\n");
    let first = lines.next().unwrap();
    let mut it = first.split(' ');
    let method = Method::from_bytes(it.next().unwrap().as_bytes()).unwrap();
    let target = it.next().unwrap();
    let mut b = Request::builder().method(method).uri(target);
    for l in lines {
        if l.is_empty() {
            break;
        }
        let (k, v) = l.split_once(": ").unwrap();
        b = b.header(HeaderName::from_bytes(k.as_bytes()).unwrap(), HeaderValue::from_str(v).unwrap());
    }
    b.body(()).unwrap()
}

fn time_it(mut f: impl FnMut() -> u64) -> (f64, u64) {
    let mut n = 1u64;
    loop {
        let t = Instant::now();
        for _ in 0..n {
            black_box(f());
        }
        if t.elapsed() > Duration::from_millis(100) {
            break;
        }
        n *= 2;
    }
    let mut best = Duration::MAX;
    let mut count = 0;
    for _ in 0..5 {
        let t = Instant::now();
        for _ in 0..n {
            count = f();
        }
        best = best.min(t.elapsed());
    }
    (best.as_nanos() as f64 / n as f64, count)
}

fn poll_once<F: Future>(f: F) -> F::Output {
    let mut cx = Context::from_waker(Waker::noop());
    let mut f = pin!(f);
    match f.as_mut().poll(&mut cx) {
        Poll::Ready(v) => v,
        Poll::Pending => panic!("pending"),
    }
}

fn run<S>(mut svcs: Vec<S>, reqs: &[Request<()>]) -> (f64, u64)
where
    S: Service<Request<()>, Response = Response<Body>>,
    S::Error: std::fmt::Debug,
{
    let mut out = Vec::with_capacity(1024);
    let n = svcs.len();
    time_it(|| {
        let mut sum = 0u64;
        for (i, req) in reqs.iter().enumerate() {
            let r = req.clone();
            let s = &mut svcs[i % n];
            let res = poll_once(s.call(r)).unwrap();
            render(&res, &mut out);
            sum += res.status().as_u16() as u64;
        }
        sum
    })
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    if a.len() != 3 {
        eprintln!("usage: rust_fast_bench <work dir> <workload>");
        std::process::exit(2);
    }
    let (dir, name) = (&a[1], &a[2]);
    let bytes = std::fs::read(format!("{dir}/{}.wire", name.trim_end_matches("_builtin"))).unwrap();
    let reqs: Vec<Request<()>> = bytes
        .split(|b| *b == 0)
        .filter(|l| !l.is_empty())
        .map(parse_wire)
        .collect();
    let plain = name.ends_with("_plain");
    let builtin = name.ends_with("_builtin");
    let base = name.trim_end_matches("_plain").trim_end_matches("_builtin");
    let kind = match base {
        "bearer_ok" | "bearer_denied" | "no_credential" => Kind::Bearer,
        "api_key_header_ok" => Kind::ApiHeader,
        "api_key_query_ok" => Kind::ApiQuery,
        "basic_ok" | "basic_denied" => Kind::Basic,
        _ => {
            eprintln!("unknown workload {name}");
            std::process::exit(2);
        }
    };
    let (ns, count) = if plain {
        run(vec![Inner], &reqs)
    } else if builtin {
        match kind {
            Kind::Bearer => run(
                KEYS.iter()
                    .map(|k| ValidateRequestHeaderLayer::<Bearer<Body>>::bearer(k).layer(Inner))
                    .collect::<Vec<ValidateRequestHeader<Inner, _>>>(),
                &reqs,
            ),
            Kind::Basic => run(
                (0..3)
                    .map(|i| ValidateRequestHeaderLayer::<Basic<Body>>::basic(&format!("user-{i}"), KEYS[i]).layer(Inner))
                    .collect::<Vec<ValidateRequestHeader<Inner, _>>>(),
                &reqs,
            ),
            Kind::ApiHeader => run(
                KEYS.iter()
                    .map(|k| {
                        ValidateRequestHeaderLayer::<RequiredHeaderValue<Body>>::has_header_value("x-api-key", k)
                            .unwrap()
                            .layer(Inner)
                    })
                    .collect::<Vec<_>>(),
                &reqs,
            ),
            Kind::ApiQuery => {
                println!("{name}\tunsupported\t0");
                std::process::exit(3);
            }
        }
    } else {
        run(vec![ValidateRequestHeaderLayer::custom(Hashed::new(kind)).layer(Inner)], &reqs)
    };
    println!("{name}\t{ns:.1}\t{count}");
}
