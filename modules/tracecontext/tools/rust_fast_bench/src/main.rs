// SPDX-License-Identifier: MIT

// "Fastest in the field" side of `zig build bench-tracecontext`
// (modules/tracecontext/tools/bench.zig): times OpenTelemetry Rust's W3C
// `TraceContextPropagator` (opentelemetry_sdk 0.33.1, `propagation` module;
// the traits and types from opentelemetry 0.33.1) over the request bytes the
// Zig program writes into the directory given as the first argument, for the
// one workload named by the second and the contender named by the third (only
// "otel-rust" today). Prints one line, tab-separated: name, ns/op, count.
//
//   plain      nothing (the HTTP-stack baseline; excluded from the verdict)
//   propagate  extract the incoming traceparent, make a child span id, inject
//              traceparent on the response
//   state      the same with a tracestate header
//   fresh      no incoming traceparent: a new trace id and span id, sampled,
//              inject
//
// Each op is httparse + building an http::Request, then the handler (the same
// steps as the Go side: Extract, child span context, Inject into the response
// header map), then the status line, headers and body rendered into a reused
// buffer. count = the sum of the status codes + per response: 1 for a 55-byte
// traceparent, 1 for a tracestate header, and (propagate/state) the byte sums
// of the trace id and the flags in the echoed traceparent -- the Go side's
// definition.
//
// What differs from our module, stated so the rows are not read as more than
// they are:
//   - ids: the SDK's RandomIdGenerator draws from the `rand` thread RNG; that
//     needs the whole tracer, so, like the Go side (math/rand/v2), ids come
//     from a small xorshift64* here (8 bytes for a span id, 16 for a trace id).
//   - the propagator's own work is what the SDK does: the traceparent is split
//     into a Vec, parsed, and the injected value is a freshly formatted String;
//     inject always calls `set("tracestate", ...)`, with "" when the state is
//     empty -- the injector below drops an empty value (as Go and ours do not
//     write an empty header) but the call and the String still happen.
//   - the response header map is an http::HeaderMap (as Go's http.Header), the
//     injector inserts a HeaderValue per field (an allocation, as Go's map).
//   - the Rust request side is httparse + `http::Request`.
//
// Timing matches the Zig side: double the batch until it takes over 100 ms,
// then keep the best of five.

use http::header::{HeaderName, HeaderValue};
use http::{HeaderMap, Method, Request, StatusCode, Uri};
use opentelemetry::propagation::{Extractor, Injector, TextMapPropagator};
use opentelemetry::trace::{SpanContext, SpanId, TraceContextExt, TraceFlags, TraceId};
use opentelemetry::Context;
use opentelemetry_sdk::propagation::TraceContextPropagator;
use std::hint::black_box;
use std::time::Instant;

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

struct Req<'a>(&'a HeaderMap);

impl Extractor for Req<'_> {
    fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).and_then(|v| v.to_str().ok())
    }
    fn keys(&self) -> Vec<&str> {
        self.0.keys().map(|k| k.as_str()).collect()
    }
}

struct Resp<'a>(&'a mut HeaderMap);

impl Injector for Resp<'_> {
    fn set(&mut self, key: &str, value: String) {
        if value.is_empty() {
            return;
        }
        self.0.insert(
            HeaderName::from_bytes(key.as_bytes()).unwrap(),
            HeaderValue::from_str(&value).unwrap(),
        );
    }
}

/// xorshift64* (the Go side draws from math/rand/v2).
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
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

fn sum_bytes(s: &[u8]) -> u64 {
    s.iter().map(|&c| u64::from(c)).sum()
}

fn drive(traced: bool, prop: &TraceContextPropagator, rng: &mut Rng, base: &Context, wires: &[Vec<u8>], out: &mut Vec<u8>, kind: u8) -> u64 {
    let mut sum = 0u64;
    for w in wires {
        let req = parse(w);
        let mut resp_headers = HeaderMap::new();
        if traced {
            let ctx = prop.extract_with_context(base, &Req(req.headers()));
            let sid = SpanId::from_bytes(rng.next().to_le_bytes());
            let parent = ctx.span();
            let psc = parent.span_context();
            let sc = if psc.is_valid() {
                SpanContext::new(psc.trace_id(), sid, psc.trace_flags(), false, psc.trace_state().clone())
            } else {
                let mut tid = [0u8; 16];
                tid[..8].copy_from_slice(&rng.next().to_le_bytes());
                tid[8..].copy_from_slice(&rng.next().to_le_bytes());
                SpanContext::new(TraceId::from_bytes(tid), sid, TraceFlags::SAMPLED, false, Default::default())
            };
            let ctx = ctx.with_remote_span_context(sc);
            prop.inject_context(&ctx, &mut Resp(&mut resp_headers));
        }
        let status = StatusCode::OK;
        out.clear();
        out.extend_from_slice(b"HTTP/1.1 ");
        out.extend_from_slice(status.as_str().as_bytes());
        out.push(b' ');
        out.extend_from_slice(status.canonical_reason().unwrap_or("").as_bytes());
        out.extend_from_slice(b"\r\n");
        for (k, v) in &resp_headers {
            out.extend_from_slice(k.as_str().as_bytes());
            out.extend_from_slice(b": ");
            out.extend_from_slice(v.as_bytes());
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(b"\r\nok");
        sum += u64::from(status.as_u16());
        if let Some(tp) = resp_headers.get("traceparent") {
            let tp = tp.as_bytes();
            if tp.len() == 55 {
                sum += 1;
                if kind == 1 {
                    sum += sum_bytes(&tp[3..35]) + sum_bytes(&tp[53..55]);
                }
            }
        }
        if resp_headers.contains_key("tracestate") {
            sum += 1;
        }
    }
    black_box(&out);
    sum
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 4 {
        eprintln!("usage: tracecontext_fast_bench <work dir> <workload> <contender>");
        std::process::exit(2);
    }
    let (dir, name, who) = (std::path::Path::new(&args[1]), args[2].as_str(), args[3].as_str());
    if who != "otel-rust" {
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
    let prop = TraceContextPropagator::new();
    let base = Context::new();
    let mut rng = Rng(0x7ace_c0de_5eed_1d01);
    let traced = name != "plain";
    // propagate and state add the echoed id/flags to the count
    let kind = if name == "propagate" || name == "state" { 1 } else { 0 };
    let (ns, count) = time_it(|| drive(traced, &prop, &mut rng, &base, black_box(&wires), &mut out, kind));
    println!("{name}\t{ns:.1}\t{count}");
}
