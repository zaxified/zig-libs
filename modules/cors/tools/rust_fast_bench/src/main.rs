// SPDX-License-Identifier: MIT

// "Fastest in the field" side of `zig build bench-cors`
// (modules/cors/tools/bench.zig): times tower-http 0.7.1's `CorsLayer` over the
// request bytes the Zig program writes into the directory given as the first
// argument, for the one workload named by the second and the contender named
// by the third (only "tower-http" today). Prints one line, tab-separated: name,
// ns/op, count and, for `preflight`, a fourth field `canon` (see below). A
// workload the contender cannot do prints `name<TAB>unsupported` and exits 3
// (the Zig side drops the row for it).
//
//   plain       the trivial service, no CORS layer
//   preflight   OPTIONS from a listed origin, ACRM PUT + ACRH
//   actual      GET from a listed origin
//   disallowed  GET from an origin on no list
//   wildcard    UNSUPPORTED: AllowOrigin has exact lists, `*`, mirror and a
//               predicate closure; a subdomain pattern would be our own
//               matcher inside the closure, timing our code, not the library.
//
// Policy: the four listed origins (AllowOrigin::list), methods GET/POST/PUT,
// allowed headers Content-Type/Authorization/X-Requested-With, max-age 600, no
// credentials. Each op is httparse + building an http::Request, then the layer
// wrapped around a trivial service polled to completion (a no-op waker: the
// futures are immediately ready), then the status line, headers and body
// rendered into a reused buffer. count = the sum of the status codes + one per
// response carrying an Access-Control-Allow-Origin header.
//
// What differs from the reference (rs/cors), stated so the rows are not read
// as more than they are:
//   - tower-http treats EVERY OPTIONS request as a preflight, answers it
//     itself with status 200 (not 204: the status is not configurable) and
//     does not check Access-Control-Request-Method / -Headers against the
//     allowed lists (it sends the configured lists). It also sends the CORS
//     headers for an unlisted origin's preflight. The workloads only send
//     preflights that every implementation grants, so the counts agree except
//     for that status: `canon` is the count with a preflight's 200 read as 204,
//     computed in an untimed pass, and is what the Zig side compares.
//   - the layer does less validation than ours (origin pattern labels, request
//     method and headers), so a faster time here is not like-for-like work.
//
// Timing matches the Zig side: double the batch until it takes over 100 ms,
// then keep the best of five.

use http::header::{HeaderName, HeaderValue, ACCESS_CONTROL_ALLOW_ORIGIN, ACCESS_CONTROL_REQUEST_METHOD, AUTHORIZATION, CONTENT_TYPE};
use http::{Method, Request, Response, Uri};
use std::convert::Infallible;
use std::future::{ready, Future, Ready};
use std::hint::black_box;
use std::pin::pin;
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_layer::Layer;
use tower_service::Service;

fn time_it(mut f: impl FnMut() -> u64) -> (f64, u64) {
    let mut n: u64 = 1;
    let mut sink = 0u64;
    loop {
        let t = Instant::now();
        for _ in 0..n {
            sink = sink.wrapping_add(f());
        }
        if t.elapsed().as_millis() > 100 {
            break;
        }
        n *= 2;
    }
    let mut best = u128::MAX;
    let mut count = 0;
    for _ in 0..5 {
        let t = Instant::now();
        for _ in 0..n {
            count = f();
        }
        best = best.min(t.elapsed().as_nanos());
    }
    black_box(sink);
    (best as f64 / n as f64, count)
}

#[derive(Default)]
struct Body(&'static [u8]);

#[derive(Clone)]
struct Inner;

impl Service<Request<()>> for Inner {
    type Response = Response<Body>;
    type Error = Infallible;
    type Future = Ready<Result<Response<Body>, Infallible>>;
    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Infallible>> {
        Poll::Ready(Ok(()))
    }
    fn call(&mut self, _: Request<()>) -> Self::Future {
        ready(Ok(Response::new(Body(b"ok"))))
    }
}

fn parse(bytes: &[u8]) -> Request<()> {
    let mut hdrs = [httparse::EMPTY_HEADER; 16];
    let mut r = httparse::Request::new(&mut hdrs);
    r.parse(bytes).unwrap();
    let mut req = Request::new(());
    *req.method_mut() = Method::from_bytes(r.method.unwrap().as_bytes()).unwrap();
    *req.uri_mut() = r.path.unwrap().parse::<Uri>().unwrap();
    for h in r.headers.iter() {
        req.headers_mut().append(
            HeaderName::from_bytes(h.name.as_bytes()).unwrap(),
            HeaderValue::from_bytes(h.value).unwrap(),
        );
    }
    req
}

fn drive<S>(svc: &mut S, wires: &[Vec<u8>], out: &mut Vec<u8>, canon: bool) -> u64
where
    S: Service<Request<()>, Response = Response<Body>, Error = Infallible>,
{
    let mut cx = Context::from_waker(Waker::noop());
    let mut sum = 0u64;
    for w in wires {
        let req = parse(w);
        let preflight = req.method() == Method::OPTIONS && req.headers().contains_key(ACCESS_CONTROL_REQUEST_METHOD);
        let _ = svc.poll_ready(&mut cx);
        let fut = svc.call(req);
        let resp = match pin!(fut).poll(&mut cx) {
            Poll::Ready(Ok(r)) => r,
            _ => panic!("service did not complete"),
        };
        out.clear();
        let status = resp.status();
        out.extend_from_slice(b"HTTP/1.1 ");
        out.extend_from_slice(status.as_str().as_bytes());
        out.push(b' ');
        out.extend_from_slice(status.canonical_reason().unwrap_or("").as_bytes());
        out.extend_from_slice(b"\r\n");
        for (k, v) in resp.headers() {
            out.extend_from_slice(k.as_str().as_bytes());
            out.extend_from_slice(b": ");
            out.extend_from_slice(v.as_bytes());
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(b"\r\n");
        out.extend_from_slice(resp.body().0);
        let mut code = u64::from(status.as_u16());
        if canon && preflight && code == 200 {
            code = 204;
        }
        sum += code;
        if resp.headers().contains_key(ACCESS_CONTROL_ALLOW_ORIGIN) {
            sum += 1;
        }
    }
    black_box(&out);
    sum
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 4 {
        eprintln!("usage: cors_fast_bench <work dir> <workload> <contender>");
        std::process::exit(2);
    }
    let (dir, name, who) = (std::path::Path::new(&args[1]), args[2].as_str(), args[3].as_str());
    if who != "tower-http" {
        eprintln!("unknown contender {who}");
        std::process::exit(2);
    }
    if name == "wildcard" {
        println!("{name}\tunsupported");
        std::process::exit(3);
    }
    let raw = std::fs::read(dir.join(format!("{name}.wire"))).unwrap_or_else(|e| {
        eprintln!("{name}.wire: {e}");
        std::process::exit(1);
    });
    let trimmed: &[u8] = match raw.iter().rposition(|&b| b != 0) {
        Some(i) => &raw[..=i],
        None => &raw,
    };
    let wires: Vec<Vec<u8>> = trimmed.split(|&b| b == 0).map(<[u8]>::to_vec).collect();
    let mut out: Vec<u8> = Vec::with_capacity(1024);

    let (ns, count, canon) = if name == "plain" {
        let mut svc = Inner;
        let (ns, count) = time_it(|| drive(&mut svc, black_box(&wires), &mut out, false));
        (ns, count, None)
    } else {
        let layer = CorsLayer::new()
            .allow_origin(AllowOrigin::list([
                HeaderValue::from_static("https://app.example"),
                HeaderValue::from_static("https://admin.example"),
                HeaderValue::from_static("http://localhost:5173"),
                HeaderValue::from_static("https://portal.example"),
            ]))
            .allow_methods([Method::GET, Method::POST, Method::PUT])
            .allow_headers([CONTENT_TYPE, AUTHORIZATION, HeaderName::from_static("x-requested-with")])
            .max_age(Duration::from_secs(600));
        let mut svc = layer.layer(Inner);
        let (ns, count) = time_it(|| drive(&mut svc, black_box(&wires), &mut out, false));
        let canon = if name == "preflight" { Some(drive(&mut svc, &wires, &mut out, true)) } else { None };
        (ns, count, canon)
    };
    match canon {
        Some(c) => println!("{name}\t{ns:.1}\t{count}\t{c}"),
        None => println!("{name}\t{ns:.1}\t{count}"),
    }
}
