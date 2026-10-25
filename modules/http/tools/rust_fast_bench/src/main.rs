// SPDX-License-Identifier: MIT

// "Fastest in the field" side of `zig build bench-http`
// (modules/http/tools/bench.zig): hyper 1.11's HTTP/1.1 server connection
// (`hyper::server::conn::http1`) serving the same wire the Zig and Go sides
// read, `<work dir>/<workload>.wire` (16 keep-alive requests, the last
// `Connection: close`), over an in-memory stream: the request bytes are read
// from a slice, the response bytes appended to a Vec, no socket and no
// runtime (the connection future is polled to completion with a no-op waker;
// the stream is always ready, so it never waits). Prints one line,
// tab-separated: name, ns/op, 0 (no cycle counter on this side), count.
//
// The handlers do what the Zig side's do, and accumulate the same count: per
// request 200 + request-body bytes read + response-body bytes written + the
// length of the header looked up. hyper writes `Date` and `Content-Length`
// itself (as the real Go server would, and the Zig side does not), so this
// side carries slightly more work per response.
//
// Timing matches the Zig side: double the batch until it takes over 100 ms,
// then keep the best of five. Before timing, one op must give exactly 16
// `HTTP/1.1 200` responses.

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::rt::{Read, ReadBufCursor, Write};
use hyper::{Request, Response};
use std::convert::Infallible;
use std::future::Future;
use std::hint::black_box;
use std::io;
use std::pin::{pin, Pin};
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll, Waker};
use std::time::Instant;

static TOTAL: AtomicU64 = AtomicU64::new(0);
static LARGE: [u8; 65536] = [b'x'; 65536];
const JSON_BODY: &[u8] = b"{\"id\":42,\"name\":\"example\",\"tags\":[\"a\",\"b\",\"c\"],\"active\":true,\"score\":3.14159,\"description\":\"A short JSON document returned by the benchmark handler so that the response has a body of a realistic size.\",\"n\":1}                    ";

/// The connection's two directions: requests from a slice, responses into a Vec.
struct Mem<'a> {
    input: &'a [u8],
    output: &'a mut Vec<u8>,
}

impl Read for Mem<'_> {
    fn poll_read(mut self: Pin<&mut Self>, _: &mut Context<'_>, mut buf: ReadBufCursor<'_>) -> Poll<io::Result<()>> {
        let n = self.input.len().min(buf.remaining());
        buf.put_slice(&self.input[..n]);
        self.input = &self.input[n..];
        Poll::Ready(Ok(()))
    }
}

impl Write for Mem<'_> {
    fn poll_write(mut self: Pin<&mut Self>, _: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        self.output.extend_from_slice(buf);
        Poll::Ready(Ok(buf.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

fn block_on<F: Future>(f: F) -> F::Output {
    let mut f = pin!(f);
    let mut cx = Context::from_waker(Waker::noop());
    loop {
        if let Poll::Ready(v) = f.as_mut().poll(&mut cx) {
            return v;
        }
    }
}

fn header_len(req: &Request<Incoming>, name: &str) -> u64 {
    req.headers().get(name).map_or(0, |v| v.as_bytes().len() as u64)
}

async fn handle(workload: u8, req: Request<Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {
    let resp = match workload {
        0 => {
            TOTAL.fetch_add(header_len(&req, "user-agent") + 200 + 200, Ordering::Relaxed);
            Response::builder()
                .header("Content-Type", "application/json")
                .header("X-Request-Cost", "12")
                .header("Cache-Control", "no-store")
                .body(Full::new(Bytes::from_static(&JSON_BODY[..200])))
        }
        1 | 2 => {
            let body = req.into_body().collect().await.map(|b| b.to_bytes().len() as u64).unwrap_or(0);
            TOTAL.fetch_add(body + 200 + 2, Ordering::Relaxed);
            Response::builder().body(Full::new(Bytes::from_static(b"ok")))
        }
        3 => {
            // The Zig side writes 16 x 4 KiB with Content-Length set; here
            // one static 64 KiB body, no copy into a response buffer (in
            // hyper's favour).
            TOTAL.fetch_add(200 + 65536, Ordering::Relaxed);
            Response::builder().header("Content-Length", "65536").body(Full::new(Bytes::from_static(&LARGE)))
        }
        _ => {
            TOTAL.fetch_add(header_len(&req, "x-trace-id") + 200 + 2, Ordering::Relaxed);
            Response::builder().body(Full::new(Bytes::from_static(b"ok")))
        }
    };
    Ok(resp.unwrap())
}

/// One op: serve the whole wire on one connection into `out` (cleared
/// first, its capacity reused across ops as the Zig side's fixed buffer is).
fn serve(workload: u8, wire: &[u8], out: &mut Vec<u8>) {
    out.clear();
    let mut io = Mem { input: wire, output: out };
    {
        let svc = hyper::service::service_fn(move |req| handle(workload, req));
        // half_close: the in-memory client's input ends after the last
        // request, which hyper reads as the peer shutting its write side;
        // without it hyper drops the request still in flight at that EOF.
        let conn = hyper::server::conn::http1::Builder::new().half_close(true).serve_connection(&mut io, svc);
        block_on(conn).unwrap_or_else(|e| die(format!("serve: {e}")));
    }
}

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

fn die(msg: String) -> ! {
    eprintln!("{msg}");
    std::process::exit(1)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        die("usage: http_fast_bench <work dir> <workload>".into());
    }
    let w = args[2].as_str();
    eprintln!("hyper 1.11.0 (http1 server conn)");
    let name = w.strip_prefix("rs.").unwrap_or(w);
    let workload: u8 = match name {
        "get" => 0,
        "post" => 1,
        "chunked" => 2,
        "large" => 3,
        "headers" => 4,
        _ => die(format!("unknown workload {w}")),
    };
    let wire = std::fs::read(std::path::Path::new(&args[1]).join(format!("{name}.wire"))).unwrap_or_else(|e| die(format!("{name}.wire: {e}")));
    let mut out = Vec::with_capacity(16 * (65536 + 1024));
    serve(workload, &wire, &mut out);
    let n = out.windows(13).filter(|s| *s == b"HTTP/1.1 200 ").count();
    if n != 16 {
        die(format!("workload {name}: expected 16 responses, got {n}"));
    }
    let (ns, count) = time_it(|| {
        TOTAL.store(0, Ordering::Relaxed);
        serve(workload, &wire, &mut out);
        black_box(&out);
        TOTAL.load(Ordering::Relaxed)
    });
    println!("{w}\t{ns:.1}\t0\t{count}");
}
