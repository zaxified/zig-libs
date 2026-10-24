// SPDX-License-Identifier: MIT

// "Fastest in the field" side of `zig build bench-staticfiles`
// (modules/staticfiles/tools/bench.zig): times tower-http 0.7.1's `ServeDir`
// over the file tree (`root/`) and the request bytes (`<workload>.wire`,
// NUL-separated) the Zig program writes into the directory given as the first
// argument, for the workload named by the second and the contender named by
// the third (only "tower-http" today). Prints one line, tab-separated: name,
// ns/op, count.
//
//   small, large, cond, miss -- the request sets listed in bench.zig
//
// Each op is, per request: httparse + building an http::Request, `ServeDir`
// called as a tower `Service` in-process (no sockets), the whole response body
// collected, and the status line and headers rendered into a reused buffer.
// count = the sum of the status codes + the body bytes of every 200 / 206 --
// the Go side's definition.
//
// What differs from our module, stated so the rows are not read as more than
// they are:
//   - ServeDir is async: it runs on a tokio current-thread runtime (features
//     `rt` and `fs` only) and its file IO goes through tokio's blocking pool
//     (spawn_blocking per open / read). That is its real cost and is left in.
//   - configuration is the default: no precompression, no fallback,
//     `append_index_html_on_directories` on, no directory listing.
//   - status codes are whatever ServeDir answers, with one exception in the
//     count: its directory redirect (`/img` → `/img/`) is a 307 where Go and
//     ours answer 301 -- the same work, another code -- so a 307 counts as 301.
//     Any other difference shows up as a count mismatch in bench.zig.
//   - the Rust request side is httparse + `http::Request`.
//
// Timing matches the Zig side: double the batch until it takes over 100 ms,
// then keep the best of five.

use bytes::Bytes;
use http::header::{HeaderName, HeaderValue};
use http::{Method, Request, Uri};
use http_body_util::BodyExt;
use std::hint::black_box;
use std::time::Instant;
use tower_http::services::ServeDir;
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

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 4 {
        eprintln!("usage: staticfiles_fast_bench <work dir> <workload> <contender>");
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
    let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
    let mut svc = ServeDir::new(dir.join("root"));
    let mut out: Vec<u8> = Vec::with_capacity(1024);
    let (ns, count) = time_it(|| {
        let mut sum = 0u64;
        for w in black_box(&wires) {
            let req = parse(w);
            let (parts, body) = rt.block_on(async {
                let resp = svc.call(req).await.unwrap();
                let (parts, body) = resp.into_parts();
                let body: Bytes = body.collect().await.unwrap().to_bytes();
                (parts, body)
            });
            out.clear();
            out.extend_from_slice(b"HTTP/1.1 ");
            out.extend_from_slice(parts.status.as_str().as_bytes());
            out.push(b' ');
            out.extend_from_slice(parts.status.canonical_reason().unwrap_or("").as_bytes());
            out.extend_from_slice(b"\r\n");
            for (k, v) in &parts.headers {
                out.extend_from_slice(k.as_str().as_bytes());
                out.extend_from_slice(b": ");
                out.extend_from_slice(v.as_bytes());
                out.extend_from_slice(b"\r\n");
            }
            out.extend_from_slice(b"\r\n");
            black_box(&out);
            let status = match parts.status.as_u16() {
                307 => 301,
                s => s,
            };
            sum += u64::from(status);
            if status == 200 || status == 206 {
                sum += body.len() as u64;
            }
        }
        sum
    });
    println!("{name}\t{ns:.1}\t{count}");
}
