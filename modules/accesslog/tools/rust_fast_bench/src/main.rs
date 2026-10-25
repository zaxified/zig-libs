// SPDX-License-Identifier: MIT

// Fastest-in-the-field side of `zig build bench-accesslog`
// (modules/accesslog/tools/bench.zig): writes the reference row's JSON Lines
// access-log records with serde_json (pinned by Cargo.lock) through its public
// API -- a hand-written `Serialize` (no derive macro, so no proc-macro crates
// to build) into a reused `Vec`, absent fields as null. Reads the entries that
// program writes into the directory given as the only argument. Prints:
// workload, ns/op, bytes -- tab-separated. Timing as the other sides: double
// the batch until it takes over 100 ms, keep the best of five.
// `BENCH_DUMP=1` writes the lines to stderr.

use std::hint::black_box;
use std::io::Write as _;
use std::time::{Duration, Instant};

use serde_core::ser::{Serialize, SerializeStruct, Serializer};

struct Entry {
    ts: i64,
    remote_addr: Option<String>,
    method: String,
    target: String,
    protocol: String,
    status: u16,
    request_bytes: Option<u64>,
    response_bytes: Option<u64>,
    latency_ns: Option<u64>,
    user_agent: Option<String>,
    referer: Option<String>,
    request_id: Option<String>,
    trace_id: Option<String>,
    span_id: Option<String>,
}

impl Serialize for Entry {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut st = s.serialize_struct("Entry", 14)?;
        st.serialize_field("ts", &self.ts)?;
        st.serialize_field("remote_addr", &self.remote_addr)?;
        st.serialize_field("method", &self.method)?;
        st.serialize_field("target", &self.target)?;
        st.serialize_field("protocol", &self.protocol)?;
        st.serialize_field("status", &self.status)?;
        st.serialize_field("request_bytes", &self.request_bytes)?;
        st.serialize_field("response_bytes", &self.response_bytes)?;
        st.serialize_field("latency_ns", &self.latency_ns)?;
        st.serialize_field("user_agent", &self.user_agent)?;
        st.serialize_field("referer", &self.referer)?;
        st.serialize_field("request_id", &self.request_id)?;
        st.serialize_field("trace_id", &self.trace_id)?;
        st.serialize_field("span_id", &self.span_id)?;
        st.end()
    }
}

fn time_it(mut f: impl FnMut() -> usize) -> (f64, usize) {
    let mut n: u64 = 1;
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
            count = black_box(f());
        }
        best = best.min(t.elapsed());
    }
    (best.as_nanos() as f64 / n as f64, count)
}

const ABSENT: &str = "\x01";

fn opt_s(s: &str) -> Option<String> {
    (s != ABSENT).then(|| s.to_owned())
}

fn opt_u(s: &str) -> Option<u64> {
    (s != ABSENT).then(|| s.parse().unwrap())
}

fn main() {
    let dir = std::env::args().nth(1).expect("usage: rust_fast_bench <work dir>");
    let text = std::fs::read_to_string(format!("{dir}/entries.tsv")).expect("read entries");
    let es: Vec<Entry> = text
        .trim_end_matches('\n')
        .split('\n')
        .map(|l| {
            let f: Vec<&str> = l.split('\t').collect();
            Entry {
                ts: f[0].parse().unwrap(),
                remote_addr: opt_s(f[1]),
                method: f[2].to_owned(),
                target: f[3].to_owned(),
                protocol: f[4].to_owned(),
                status: f[5].parse().unwrap(),
                request_bytes: opt_u(f[6]),
                response_bytes: opt_u(f[7]),
                latency_ns: opt_u(f[8]),
                user_agent: opt_s(f[9]),
                referer: opt_s(f[10]),
                request_id: opt_s(f[11]),
                trace_id: opt_s(f[12]),
                span_id: opt_s(f[13]),
            }
        })
        .collect();
    let mut buf: Vec<u8> = Vec::with_capacity(1 << 16);
    let mut f = || {
        buf.clear();
        for e in &es {
            serde_json::to_writer(&mut buf, e).unwrap();
            buf.push(b'\n');
        }
        buf.len()
    };
    let (ns, count) = time_it(&mut f);
    println!("json_encoding\t{ns:.1}\t{count}");
    if std::env::var_os("BENCH_DUMP").is_some() {
        f();
        std::io::stderr().write_all(&buf).unwrap();
    }
}
