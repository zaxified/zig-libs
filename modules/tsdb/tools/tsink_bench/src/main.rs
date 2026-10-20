// SPDX-License-Identifier: MIT
//
// The reference side of `zig build bench-tsdb` (modules/tsdb/tools/bench.zig):
// tsink 0.10.2 (h2337/tsink, embedded Rust TSDB), WAL sync mode PerAppend.
//
//   tsink_bench <work dir> <workload>
//
// Prints `name \t ns/op \t count` on stdout, the banner on stderr. Same timing
// method as the Zig side: double the batch until it takes over 100 ms, then
// the best of five batches, per op. The data model, generators, expected
// values and the checksum are the mirror image of bench.zig -- keep both in
// step (the header of bench.zig describes the workloads).
//
// `count` of the append workloads is the number of samples written; of the
// read workloads FNV-1a/64 over the returned (ts, value bits), summed over
// series, plus the sample count (wrapping). The query store is built, closed,
// reopened and verified against the generator before anything is timed.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tsink::{
    DataPoint, Label, MetricSeries, Row, SeriesMatcher, SeriesSelection, Storage, StorageBuilder,
    TimestampPrecision, WalSyncMode,
};

const N_SERIES: u64 = 1000;
const N_SCRAPES: u64 = 200;
const SCRAPE_BASE: i64 = 1_792_000_000_000;
const SCRAPE_STEP: i64 = 15_000;
const BULK_SAMPLES: u64 = 200_000;
const BULK_BATCH: u64 = 1000;
const BULK_BASE: i64 = 1_790_000_000_000;
const BULK_STEP: i64 = 1000;
const W3_SERIES: u64 = 100;
const W3_WIN_FROM: u64 = 90;
const W3_WIN_TO: u64 = 110;

fn series_name(i: u64) -> String {
    format!("m{}", i % 10)
}
fn series_labels(i: u64) -> Vec<Label> {
    vec![
        Label::new("host", format!("h{}", (i / 10) % 10)),
        Label::new("region", format!("r{}", i % 7)),
        Label::new("inst", format!("i{i}")),
    ]
}
fn w1_ts(k: u64) -> i64 {
    SCRAPE_BASE + (k as i64) * SCRAPE_STEP
}
fn w1_val(i: u64, k: u64) -> f64 {
    ((i * 7919 + k * 31) % 1000) as f64 / 8.0
}
fn w2_ts(k: u64) -> i64 {
    BULK_BASE + (k as i64) * BULK_STEP
}
fn w2_val(k: u64) -> f64 {
    ((k * 7919) % 4001) as f64 / 8.0
}
fn w2_labels() -> Vec<Label> {
    vec![
        Label::new("host", "h0"),
        Label::new("region", "r0"),
        Label::new("inst", "i0"),
    ]
}

// FNV-1a/64 over (ts LE, value bits LE), seeded with the series index.
struct Fnv(u64);
impl Fnv {
    fn new(idx: u64) -> Fnv {
        let mut f = Fnv(0xcbf29ce484222325);
        f.bytes(&idx.to_le_bytes());
        f
    }
    fn bytes(&mut self, b: &[u8]) {
        for x in b {
            self.0 ^= *x as u64;
            self.0 = self.0.wrapping_mul(0x100000001b3);
        }
    }
    fn sample(&mut self, ts: i64, v: f64) {
        self.bytes(&(ts as u64).to_le_bytes());
        self.bytes(&v.to_bits().to_le_bytes());
    }
}
/// Accumulates (hash sum, sample count) over series.
#[derive(Default)]
struct Acc {
    sum: u64,
    n: u64,
}
impl Acc {
    fn series(&mut self, idx: u64, pts: &[DataPoint]) {
        let mut f = Fnv::new(idx);
        for p in pts {
            f.sample(p.timestamp, p.value.as_f64().expect("f64 value"));
        }
        self.sum = self.sum.wrapping_add(f.0);
        self.n += pts.len() as u64;
    }
    fn count(&self) -> u64 {
        self.sum.wrapping_add(self.n)
    }
}

fn open(dir: &Path) -> Arc<dyn Storage> {
    StorageBuilder::new()
        .with_data_path(dir)
        .with_timestamp_precision(TimestampPrecision::Milliseconds)
        .with_wal_sync_mode(WalSyncMode::PerAppend)
        // The default retention is 14 days; keep the synthetic 2026 timestamps
        // far inside it whatever today's date is.
        .with_retention(Duration::from_secs(3650 * 24 * 3600))
        .build()
        .expect("open tsink")
}

fn select(s: &Arc<dyn Storage>, name: &str, labels: &[Label], from: i64, to: i64) -> Vec<DataPoint> {
    match s.select(name, labels, from, to) {
        Ok(p) => p,
        Err(tsink::TsinkError::NoDataPoints { .. }) => Vec::new(),
        Err(e) => panic!("select {name}: {e:?}"),
    }
}

/// W1: 1000 series x 3 labels, one insert_rows (= one durable WAL commit)
/// per scrape. Returns samples written.
fn build_w1(s: &Arc<dyn Storage>, meta: &[(String, Vec<Label>)]) -> u64 {
    let mut n = 0;
    for k in 0..N_SCRAPES {
        let rows: Vec<Row> = meta
            .iter()
            .enumerate()
            .map(|(i, (name, labels))| {
                Row::with_labels(name.as_str(), labels.clone(), DataPoint::new(w1_ts(k), w1_val(i as u64, k)))
            })
            .collect();
        s.insert_rows(&rows).expect("insert_rows");
        n += rows.len() as u64;
    }
    n
}

/// W2: one series, 200k samples, 1000 per insert_rows.
fn build_w2(s: &Arc<dyn Storage>) -> u64 {
    let labels = w2_labels();
    let mut n = 0;
    for b in 0..BULK_SAMPLES / BULK_BATCH {
        let rows: Vec<Row> = (b * BULK_BATCH..(b + 1) * BULK_BATCH)
            .map(|k| Row::with_labels("bulk", labels.clone(), DataPoint::new(w2_ts(k), w2_val(k))))
            .collect();
        s.insert_rows(&rows).expect("insert_rows");
        n += rows.len() as u64;
    }
    n
}

fn fresh(dir: &Path) -> PathBuf {
    let _ = std::fs::remove_dir_all(dir);
    std::fs::create_dir_all(dir).expect("mkdir");
    dir.to_path_buf()
}

fn dir_bytes(dir: &Path) -> u64 {
    let mut total = 0;
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            let m = e.metadata().expect("stat");
            total += if m.is_dir() { dir_bytes(&e.path()) } else { m.len() };
        }
    }
    total
}

fn meta() -> Vec<(String, Vec<Label>)> {
    (0..N_SERIES).map(|i| (series_name(i), series_labels(i))).collect()
}

// ── the query store ──────────────────────────────────────────────────────────

fn w3_full(s: &Arc<dyn Storage>) -> u64 {
    let mut acc = Acc::default();
    for i in 0..W3_SERIES {
        let pts = select(s, &series_name(i), &series_labels(i), 0, i64::MAX);
        acc.series(i, &pts);
    }
    acc.count()
}

fn w3_window(s: &Arc<dyn Storage>) -> u64 {
    let mut acc = Acc::default();
    for i in 0..W3_SERIES {
        let pts = select(s, &series_name(i), &series_labels(i), w1_ts(W3_WIN_FROM), w1_ts(W3_WIN_TO));
        acc.series(i, &pts);
    }
    acc.count()
}

/// `{__name__="m7", host="h3"}` then the full range of every match.
fn w4_matcher(s: &Arc<dyn Storage>) -> u64 {
    let sel = SeriesSelection::new()
        .with_metric("m7")
        .with_matcher(SeriesMatcher::equal("host", "h3"));
    let found: Vec<MetricSeries> = s.select_series(&sel).expect("select_series");
    let mut acc = Acc::default();
    for ms in &found {
        let inst = ms.labels.iter().find(|l| l.name == "inst").expect("inst label");
        let idx: u64 = inst.value[1..].parse().expect("inst index");
        let pts = select(s, &ms.name, &ms.labels, 0, i64::MAX);
        acc.series(idx, &pts);
    }
    acc.count()
}

/// Expected (hash, count) for series `i` of W1 over scrapes [from, to).
fn expect_w1(i: u64, from: u64, to: u64) -> Acc {
    let mut f = Fnv::new(i);
    for k in from..to {
        f.sample(w1_ts(k), w1_val(i, k));
    }
    Acc { sum: f.0, n: to - from }
}

fn verify_w1(s: &Arc<dyn Storage>) {
    for i in 0..N_SERIES {
        let pts = select(s, &series_name(i), &series_labels(i), 0, i64::MAX);
        let mut got = Acc::default();
        got.series(i, &pts);
        let want = expect_w1(i, 0, N_SCRAPES);
        assert!(got.sum == want.sum && got.n == want.n, "tsink lost data in series {i}: {} of {}", got.n, want.n);
    }
}

fn timed<F: FnMut() -> u64>(mut once: F) -> (f64, u64) {
    let mut n: u64 = 1;
    loop {
        let t = Instant::now();
        for _ in 0..n {
            std::hint::black_box(once());
        }
        if t.elapsed().as_nanos() > 100_000_000 {
            break;
        }
        n *= 2;
    }
    let mut best = u128::MAX;
    let mut count = 0;
    for _ in 0..5 {
        let t = Instant::now();
        for _ in 0..n {
            count = once();
        }
        best = best.min(t.elapsed().as_nanos());
    }
    (best as f64 / n as f64, count)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        eprintln!("usage: tsink_bench <work dir> <w1_scrape|w2_bulk|w2_check|w3_range_full|w3_range_window|w4_matcher|size_w1>");
        std::process::exit(2);
    }
    let work = Path::new(&args[1]).join("tsink");
    let name = args[2].as_str();
    let dir = work.join(name);
    eprintln!("tsink 0.10.2 (h2337/tsink), WalSyncMode::PerAppend, Milliseconds");
    let m = meta();

    let (ns, count) = match name {
        "w1_scrape" => timed(|| {
            let s = open(&fresh(&dir));
            let n = build_w1(&s, &m);
            s.close().expect("close");
            n
        }),
        "w2_bulk" => timed(|| {
            let s = open(&fresh(&dir));
            let n = build_w2(&s);
            s.close().expect("close");
            n
        }),
        // Info: build W2, close, reopen, read everything back.
        "w2_check" => timed(|| {
            let s = open(&fresh(&dir));
            build_w2(&s);
            s.close().expect("close");
            let s = open(&dir);
            let pts = select(&s, "bulk", &w2_labels(), 0, i64::MAX);
            let mut want = Fnv::new(0);
            for k in 0..BULK_SAMPLES {
                want.sample(w2_ts(k), w2_val(k));
            }
            let mut acc = Acc::default();
            acc.series(0, &pts);
            assert!(acc.n == BULK_SAMPLES && acc.sum == want.0, "tsink lost data in W2: {} of {}", acc.n, BULK_SAMPLES);
            s.close().expect("close");
            acc.count()
        }),
        "w3_range_full" | "w3_range_window" | "w4_matcher" => {
            let s = open(&fresh(&dir));
            build_w1(&s, &m);
            s.close().expect("close");
            let s = open(&dir);
            verify_w1(&s);
            let r = match name {
                "w3_range_full" => timed(|| w3_full(&s)),
                "w3_range_window" => timed(|| w3_window(&s)),
                _ => timed(|| w4_matcher(&s)),
            };
            s.close().expect("close");
            r
        }
        // Info: bytes on disk after W1 (after close, WAL included).
        "size_w1" => {
            let s = open(&fresh(&dir));
            let n = build_w1(&s, &m);
            s.close().expect("close");
            let bytes = dir_bytes(&dir);
            eprintln!("size_w1: {bytes} bytes for {n} samples");
            (0.0, bytes)
        }
        _ => {
            eprintln!("unknown workload {name}");
            std::process::exit(2);
        }
    };
    let _ = std::fs::remove_dir_all(&dir);
    println!("{name}\t{ns}\t{count}");
}
