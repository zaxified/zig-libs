// SPDX-License-Identifier: MIT

// The hyper side of `zig build interop-http -- --phase h1parsers`
// (modules/http/tools/h1parsers.zig): what hyper 1.11's HTTP/1.1 server
// connection (`hyper::server::conn::http1`) does with each raw request wire,
// as the Go oracle (tools/go_oracle/h1.go) records it for net/http: which
// requests reach the service, with what method, target and body, and the first
// status other than 200 the connection answered itself.
//
// Input: a file with one case per line, `<id>\t<wire as hex>`. Output, one
// line per case, tab-separated: `<id>`, the reject status (0 = none), the number of service calls,
// then per call `<method hex>`, `<target hex>`, `<body hex>` (`-` when the
// body could not be read to its end). The wire is served over an in-memory
// stream with no runtime (the connection future is polled with a no-op
// waker), as the bench side does; the input ends after the wire (half_close).
// The service answers 200 "ok" whatever the body did.

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::rt::{Read, ReadBufCursor, Write};
use hyper::{Request, Response};
use std::cell::RefCell;
use std::convert::Infallible;
use std::future::Future;
use std::io;
use std::pin::{pin, Pin};
use std::rc::Rc;
use std::task::{Context, Poll, Waker};

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

/// Polls `f` until it is ready; gives up (None) when it stays pending, which
/// an always-ready in-memory stream only does when the connection waits for
/// input that will never come.
fn block_on<F: Future>(f: F) -> Option<F::Output> {
    let mut f = pin!(f);
    let mut cx = Context::from_waker(Waker::noop());
    for _ in 0..100_000 {
        if let Poll::Ready(v) = f.as_mut().poll(&mut cx) {
            return Some(v);
        }
    }
    None
}

struct Call {
    method: String,
    target: String,
    body: Option<Vec<u8>>,
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()).collect()
}

/// The first status in `resp` that is not 200 (the service's own answer).
fn first_reject(resp: &[u8]) -> u32 {
    let mut i = 0;
    while let Some(at) = resp[i..].windows(9).position(|w| w == b"HTTP/1.1 ") {
        let p = i + at + 9;
        if p + 3 <= resp.len() {
            if let Ok(code) = std::str::from_utf8(&resp[p..p + 3]).unwrap_or("0").parse::<u32>() {
                if code != 200 {
                    return code;
                }
            }
        }
        i = p;
    }
    0
}

fn serve(wire: &[u8]) -> (u32, Vec<Call>) {
    let calls: Rc<RefCell<Vec<Call>>> = Rc::new(RefCell::new(Vec::new()));
    let mut out = Vec::new();
    let mut io = Mem { input: wire, output: &mut out };
    let errored;
    {
        let sink = calls.clone();
        let svc = hyper::service::service_fn(move |req: Request<Incoming>| {
            let sink = sink.clone();
            async move {
                let method = req.method().as_str().to_string();
                let target = req.uri().to_string();
                let body = match req.into_body().collect().await {
                    Ok(b) => Some(b.to_bytes().to_vec()),
                    Err(_) => None,
                };
                sink.borrow_mut().push(Call { method, target, body });
                Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(b"ok"))))
            }
        });
        let conn = hyper::server::conn::http1::Builder::new().half_close(true).serve_connection(&mut io, svc);
        errored = match block_on(conn) {
            Some(Ok(())) => false,
            Some(Err(_)) => true,
            None => true,
        };
    }
    // An error with no status written is the connection ending (a truncated or
    // unreadable message): no status, as the Go oracle records it.
    let _ = errored;
    let reject = first_reject(&out);
    let v = calls.borrow_mut().drain(..).collect();
    (reject, v)
}

fn main() {
    let path = std::env::args().nth(1).unwrap_or_else(|| {
        eprintln!("usage: h1_verdicts <cases file: id TAB hex wire per line>");
        std::process::exit(2)
    });
    eprintln!("hyper 1.11.0 (http1 server conn)");
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        eprintln!("{path}: {e}");
        std::process::exit(2)
    });
    for line in text.lines() {
        let Some((id, h)) = line.split_once('\t') else { continue };
        let (reject, calls) = serve(&unhex(h));
        let mut row = format!("{id}\t{reject}\t{}", calls.len());
        for c in &calls {
            row.push_str(&format!("\t{}\t{}\t{}", hex(c.method.as_bytes()), hex(c.target.as_bytes()), c.body.as_ref().map_or("-".to_string(), |b| if b.is_empty() { "+".to_string() } else { hex(b) })));
        }
        println!("{row}");
    }
}
