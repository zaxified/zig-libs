// SPDX-License-Identifier: MIT

// "Fastest in the field" side of `zig build bench-requestid`
// (modules/requestid/tools/bench.zig): times tower-http 0.7.1's
// `SetRequestIdLayer` + `PropagateRequestIdLayer` over the request bytes the Zig
// program writes into the directory given as the first argument, for the one
// workload named by the second and the contender named by the third (only
// "tower-http" today). Prints one line, tab-separated: name, ns/op, count.
//
//   plain     the trivial service, no layers
//   generate  both layers, requests without X-Request-Id
//   adopt     both layers, requests carrying X-Request-Id
//
// Each op is httparse + building an http::Request, then the layers wrapped
// around a trivial service polled to completion (a no-op waker: the futures are
// immediately ready), then the status line, headers and body rendered into a
// reused buffer. Like the Go side, the service writes the id (read from the
// request header the Set layer inserted) as the body. count = the sum of the
// status codes + one per response carrying an X-Request-Id header.
//
// What differs from our module, stated so the rows are not read as more than
// they are:
//   - two layers, not one: tower-http splits "make/adopt the id" (Set) from
//     "echo it on the response" (Propagate). Set is the OUTER one: Propagate
//     reads the request header when it is called, so it has to sit inside Set
//     to see an id Set generated.
//   - the id generator is our own `MakeRequestId` (`Counter`): 32 hex digits
//     from a fixed 64-bit prefix and an incrementing u64, the same shape as
//     ours, so the generate row is like for like (MakeRequestUuid, the
//     library's own, reads the OS RNG per id and is not used).
//   - the library does not validate an adopted id (length, charset); ours does,
//     so adopt does less work here. A header value is a refcounted `Bytes`, so
//     adopting is a clone; generating allocates one.
//   - the id is also stored in the request/response extensions (a typemap
//     insert per layer), which ours does not do.
//   - the Rust request side is httparse + `http::Request`.
//
// Timing matches the Zig side: double the batch until it takes over 100 ms,
// then keep the best of five.

use http::header::{HeaderName, HeaderValue};
use http::{Method, Request, Response, Uri};
use std::convert::Infallible;
use std::future::{ready, Future, Ready};
use std::hint::black_box;
use std::pin::pin;
use std::task::{Context, Poll, Waker};
use std::time::Instant;
use tower_http::request_id::{MakeRequestId, PropagateRequestIdLayer, RequestId, SetRequestIdLayer};
use tower_layer::Layer;
use tower_service::Service;

const X_REQUEST_ID: HeaderName = HeaderName::from_static("x-request-id");

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

/// The response body: a static string (plain) or the request id.
struct Body {
    fixed: &'static [u8],
    id: Option<HeaderValue>,
}

impl Body {
    fn bytes(&self) -> &[u8] {
        match &self.id {
            Some(v) => v.as_bytes(),
            None => self.fixed,
        }
    }
}

/// `plain`: no id, body "<none>" (as the Go handler).
#[derive(Clone)]
struct Plain;

impl Service<Request<()>> for Plain {
    type Response = Response<Body>;
    type Error = Infallible;
    type Future = Ready<Result<Response<Body>, Infallible>>;
    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Infallible>> {
        Poll::Ready(Ok(()))
    }
    fn call(&mut self, _: Request<()>) -> Self::Future {
        ready(Ok(Response::new(Body { fixed: b"<none>", id: None })))
    }
}

/// The handler behind the layers: the id the Set layer left in the request
/// header is the body (the Go handler does the same through GetReqID).
#[derive(Clone)]
struct WithId;

impl Service<Request<()>> for WithId {
    type Response = Response<Body>;
    type Error = Infallible;
    type Future = Ready<Result<Response<Body>, Infallible>>;
    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Infallible>> {
        Poll::Ready(Ok(()))
    }
    fn call(&mut self, req: Request<()>) -> Self::Future {
        let id = req.headers().get(&X_REQUEST_ID).cloned();
        ready(Ok(Response::new(Body { fixed: b"<none>", id })))
    }
}

/// 32 hex digits: a fixed 64-bit prefix, then an incrementing u64.
#[derive(Clone)]
struct Counter {
    prefix: u64,
    n: u64,
}

impl MakeRequestId for Counter {
    fn make_request_id<B>(&mut self, _: &Request<B>) -> Option<RequestId> {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        self.n = self.n.wrapping_add(1);
        let mut buf = [0u8; 32];
        for (half, v) in [self.prefix, self.n].into_iter().enumerate() {
            for i in 0..16 {
                buf[half * 16 + i] = HEX[((v >> (60 - 4 * i)) & 0xf) as usize];
            }
        }
        Some(RequestId::new(HeaderValue::from_bytes(&buf).unwrap()))
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

fn drive<S>(svc: &mut S, wires: &[Vec<u8>], out: &mut Vec<u8>) -> u64
where
    S: Service<Request<()>, Response = Response<Body>, Error = Infallible>,
{
    let mut cx = Context::from_waker(Waker::noop());
    let mut sum = 0u64;
    for w in wires {
        let req = parse(w);
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
        out.extend_from_slice(resp.body().bytes());
        sum += u64::from(status.as_u16());
        if resp.headers().contains_key(&X_REQUEST_ID) {
            sum += 1;
        }
    }
    black_box(&out);
    sum
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 4 {
        eprintln!("usage: requestid_fast_bench <work dir> <workload> <contender>");
        std::process::exit(2);
    }
    let (dir, name, who) = (std::path::Path::new(&args[1]), args[2].as_str(), args[3].as_str());
    if who != "tower-http" {
        eprintln!("unknown contender {who}");
        std::process::exit(2);
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

    let (ns, count) = if name == "plain" {
        let mut svc = Plain;
        time_it(|| drive(&mut svc, black_box(&wires), &mut out))
    } else {
        let propagate = PropagateRequestIdLayer::x_request_id().layer(WithId);
        let mut svc = SetRequestIdLayer::x_request_id(Counter { prefix: 0x5eed_1d00_c0ff_ee42, n: 0 }).layer(propagate);
        time_it(|| drive(&mut svc, black_box(&wires), &mut out))
    };
    println!("{name}\t{ns:.1}\t{count}");
}
