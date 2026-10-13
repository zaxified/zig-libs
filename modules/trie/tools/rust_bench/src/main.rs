// SPDX-License-Identifier: MIT

// Reference side of `zig build bench-trie` (modules/trie/tools/bench.zig):
// times BurntSushi/fst 0.4.7 (pinned in Cargo.toml) through its public API on
// the SAME deterministic key set and queries the Zig program generates
// (splitmix64, seed 0x74726965; the draw order below is mirrored there
// exactly). `trie_bench <row>` prints one line, tab separated:
//
//	row, ns per op, count, sum
//
// One op is the whole row (all 100 000 lookups, all 1 000 prefixes, ...).
// count and sum are the row's result checksum, compared by the Zig program.
//
//	build          build the index from the sorted pairs (MapBuilder::memory)
//	lookup_hit     Map::get of 100 000 present keys
//	lookup_miss    Map::get of 100 000 absent keys
//	prefix_iter    1 000 prefixes: search(Str.starts_with()), count + sum
//	range_iter     1 000 ranges [k_i, k_j): range().ge().lt(), count + sum
//	search_subseq  100 Subsequence queries (3 letters), count + sum
//	union_2        union of the even and the odd positions as two maps
//	load           Map::new over the borrowed bytes (informational)
//	size           count = index bytes (no timing)
//
// Timing matches the Zig side: double the batch until one batch takes over
// 100 ms, then keep the best of five.

use fst::automaton::{Automaton, Str, Subsequence};
use fst::map::OpBuilder;
use fst::{IntoStreamer, Map, MapBuilder, Streamer};
use std::hint::black_box;
use std::time::{Duration, Instant};

const SEED: u64 = 0x7472_6965;
const N_KEYS: usize = 1_000_000;
const N_HIT: usize = 100_000;
const N_MISS: usize = 100_000;
const N_PREFIX: usize = 1_000;
const N_RANGE: usize = 1_000;
const N_SUBSEQ: usize = 100;

struct SplitMix(u64);

impl SplitMix {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
}

type Row = (u64, u64); // (count, sum)

struct Data {
    keys: Vec<Vec<u8>>,
    hits: Vec<usize>,
    misses: Vec<Vec<u8>>,
    prefixes: Vec<String>,
    ranges: Vec<(usize, usize)>,
    subseqs: Vec<String>,
}

fn gen() -> Data {
    let mut rng = SplitMix(SEED);
    let mut keys: Vec<Vec<u8>> = Vec::with_capacity(N_KEYS);
    for _ in 0..N_KEYS {
        let r = rng.next();
        let mut k = Vec::with_capacity(16);
        k.push(b'w');
        for j in 0..8 {
            k.push(b'a' + (((r >> (8 * j)) & 0xff) % 26) as u8);
        }
        k.push(b'/');
        k.extend_from_slice((rng.next() % 10_000).to_string().as_bytes());
        keys.push(k);
    }
    keys.sort();
    keys.dedup();
    let n = keys.len() as u64;

    let hits = (0..N_HIT).map(|_| (rng.next() % n) as usize).collect();
    let mut misses = Vec::with_capacity(N_MISS);
    while misses.len() < N_MISS {
        let mut k = keys[(rng.next() % n) as usize].clone();
        *k.last_mut().unwrap() += 1;
        if keys.binary_search(&k).is_err() {
            misses.push(k);
        }
    }
    let prefixes = (0..N_PREFIX)
        .map(|_| {
            let k = &keys[(rng.next() % n) as usize];
            String::from_utf8(k[..3].to_vec()).unwrap()
        })
        .collect();
    let ranges = (0..N_RANGE)
        .map(|_| {
            let i = (rng.next() % n) as usize;
            let span = (rng.next() % 1000) as usize + 1;
            (i, (i + span).min(keys.len() - 1))
        })
        .collect();
    let subseqs = (0..N_SUBSEQ)
        .map(|_| {
            let mut s = String::new();
            for _ in 0..3 {
                s.push((b'a' + (rng.next() % 26) as u8) as char);
            }
            s
        })
        .collect();
    Data { keys, hits, misses, prefixes, ranges, subseqs }
}

fn build(keys: &[&Vec<u8>], first: usize, step: usize) -> Vec<u8> {
    let mut b = MapBuilder::memory();
    let mut i = first;
    while i < keys.len() {
        b.insert(keys[i], i as u64).unwrap();
        i += step;
    }
    b.into_inner().unwrap()
}

fn time_it(mut f: impl FnMut() -> Row) -> (f64, Row) {
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
    let mut row = (0, 0);
    for _ in 0..5 {
        let t = Instant::now();
        for _ in 0..n {
            row = black_box(f());
        }
        best = best.min(t.elapsed());
    }
    (best.as_nanos() as f64 / n as f64, row)
}

fn main() {
    let name = std::env::args().nth(1).expect("row name");
    let d = gen();
    let refs: Vec<&Vec<u8>> = d.keys.iter().collect();
    let bytes = build(&refs, 0, 1);
    let map = Map::new(bytes.as_slice()).unwrap();

    let (ns, (count, sum)) = match name.as_str() {
        "build" => time_it(|| {
            let v = build(&refs, 0, 1);
            black_box(&v);
            (d.keys.len() as u64, 0)
        }),
        "lookup_hit" => time_it(|| {
            let (mut c, mut s) = (0u64, 0u64);
            for &i in &d.hits {
                if let Some(v) = map.get(&d.keys[i]) {
                    c += 1;
                    s += v;
                }
            }
            (c, s)
        }),
        "lookup_miss" => time_it(|| {
            let mut c = 0u64;
            for k in &d.misses {
                if map.get(k).is_none() {
                    c += 1;
                }
            }
            (c, 0)
        }),
        "prefix_iter" => time_it(|| {
            let (mut c, mut s) = (0u64, 0u64);
            for p in &d.prefixes {
                let mut st = map.search(Str::new(p).starts_with()).into_stream();
                while let Some((_k, v)) = st.next() {
                    c += 1;
                    s += v;
                }
            }
            (c, s)
        }),
        "range_iter" => time_it(|| {
            let (mut c, mut s) = (0u64, 0u64);
            for &(i, j) in &d.ranges {
                let mut st = map.range().ge(&d.keys[i]).lt(&d.keys[j]).into_stream();
                while let Some((_k, v)) = st.next() {
                    c += 1;
                    s += v;
                }
            }
            (c, s)
        }),
        "search_subseq" => time_it(|| {
            let (mut c, mut s) = (0u64, 0u64);
            for q in &d.subseqs {
                let mut st = map.search(Subsequence::new(q)).into_stream();
                while let Some((_k, v)) = st.next() {
                    c += 1;
                    s += v;
                }
            }
            (c, s)
        }),
        "union_2" => {
            let even = build(&refs, 0, 2);
            let odd = build(&refs, 1, 2);
            let (m0, m1) = (Map::new(even.as_slice()).unwrap(), Map::new(odd.as_slice()).unwrap());
            time_it(|| {
                let (mut c, mut s) = (0u64, 0u64);
                let mut u = OpBuilder::new().add(&m0).add(&m1).union();
                while let Some((_k, vs)) = u.next() {
                    c += 1;
                    for v in vs {
                        s += v.value;
                    }
                }
                (c, s)
            })
        }
        "load" => time_it(|| {
            let m = Map::new(black_box(bytes.as_slice())).unwrap();
            (m.len() as u64, 0)
        }),
        "size" => (0.0, (bytes.len() as u64, 0)),
        other => {
            eprintln!("unknown row {other}");
            std::process::exit(2);
        }
    };
    println!("{name}\t{ns}\t{count}\t{sum}");
}
