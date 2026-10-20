// SPDX-License-Identifier: MIT

// Candidate side of `zig build bench-decimal` (modules/decimal/tools/bench.zig):
// rust_decimal 1.42.1 (MIT; 96-bit mantissa, scale <= 28), the fastest fixed-size
// decimal in the field, against the fixed `Decimal` (i128 @ 1e12) only.
//
//   rust_bench <dir> <workload>   one line on stdout: name \t ns \t count
//   rust_bench <dir> check        writes sample_rust_<w>.txt (the first 1000
//                                 canonical results of every workload) and prints
//                                 `count \t <w> \t <hash>` per workload
//
// Same inputs, workloads, timing method and count as `mpdec_bench/driver.c`
// (read its header): ns per op where one op is the whole workload, double the
// batch until it takes over 100 ms, best of five; operands parsed before the
// clock starts; results consumed in place (`black_box` of the mantissa), never
// stored; the count (sum of FNV-1a-64 over the canonical result texts) is
// computed untimed. No BigDecimal counterpart exists here: the `big*`
// workloads are mpdec-only.
//
// Rounding: `round_dp_with_strategy` -- MidpointAwayFromZero after the 12-place
// multiplication, MidpointNearestEven for the 2-place multiplication and the
// division. rust_decimal's `/` rounds its own quotient to <= 28 significant
// digits first (a second rounding the other sides do not do).

use rust_decimal::{Decimal, RoundingStrategy};
use std::fmt::Write as _;
use std::fs;
use std::hint::black_box;
use std::io::Write as _;
use std::str::FromStr;
use std::time::Instant;

const N_DEC: usize = 100_000;
const CHAIN_LEN: usize = 100;

#[derive(Clone, Copy, PartialEq)]
enum Kind {
    ParseMoney,
    AddsubChain,
    Mul12,
    Mul2,
    Divround12,
    TostrMoney,
    TostrQ12,
}

const WORKS: [(&str, Kind); 7] = [
    ("parse_money", Kind::ParseMoney),
    ("addsub_chain", Kind::AddsubChain),
    ("mul12", Kind::Mul12),
    ("mul2", Kind::Mul2),
    ("divround12", Kind::Divround12),
    ("tostr_money", Kind::TostrMoney),
    ("tostr_q12", Kind::TostrQ12),
];

struct Data {
    money_s: Vec<String>,
    money: Vec<Decimal>,
    rate: Vec<Decimal>,
    quo: Vec<Decimal>,
}

fn lines(dir: &str, file: &str) -> Vec<String> {
    let path = format!("{dir}/{file}");
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}")).lines().map(String::from).collect()
}

fn parse_all(v: &[String]) -> Vec<Decimal> {
    v.iter().map(|s| Decimal::from_str(s).unwrap()).collect()
}

fn mid(strategy: RoundingStrategy, d: Decimal, dp: u32) -> Decimal {
    d.round_dp_with_strategy(dp, strategy)
}

const AWAY: RoundingStrategy = RoundingStrategy::MidpointAwayFromZero;
const EVEN: RoundingStrategy = RoundingStrategy::MidpointNearestEven;

#[inline(always)]
fn mix(d: Decimal) -> u64 {
    (d.mantissa() as u64) ^ ((d.scale() as u64) << 56)
}

#[inline(always)]
fn op(k: Kind, x: &Data, i: usize) -> Decimal {
    let n = x.money.len();
    match k {
        Kind::ParseMoney => Decimal::from_str(&x.money_s[i]).unwrap(),
        Kind::AddsubChain => {
            let mut acc = Decimal::ZERO;
            for j in 0..CHAIN_LEN {
                let m = x.money[i * CHAIN_LEN + j];
                acc = if j & 1 == 1 { acc - m } else { acc + m };
            }
            acc
        }
        Kind::Mul12 => mid(AWAY, x.rate[i] * x.rate[(i + 1) % n], 12),
        Kind::Mul2 => mid(EVEN, x.money[i] * x.rate[i], 2),
        Kind::Divround12 => mid(EVEN, x.money[i] / x.money[(i + 1) % n], 12),
        Kind::TostrMoney | Kind::TostrQ12 => unreachable!(),
    }
}

fn run(k: Kind, x: &Data, buf: &mut String) -> u64 {
    let mut s: u64 = 0;
    match k {
        Kind::ParseMoney => (0..x.money.len()).for_each(|i| s = s.wrapping_add(mix(op(Kind::ParseMoney, x, i)))),
        Kind::AddsubChain => (0..N_DEC / CHAIN_LEN).for_each(|i| s = s.wrapping_add(mix(op(Kind::AddsubChain, x, i)))),
        Kind::Mul12 => (0..x.money.len()).for_each(|i| s = s.wrapping_add(mix(op(Kind::Mul12, x, i)))),
        Kind::Mul2 => (0..x.money.len()).for_each(|i| s = s.wrapping_add(mix(op(Kind::Mul2, x, i)))),
        Kind::Divround12 => (0..x.money.len()).for_each(|i| s = s.wrapping_add(mix(op(Kind::Divround12, x, i)))),
        Kind::TostrMoney | Kind::TostrQ12 => {
            let src = if k == Kind::TostrMoney { &x.money } else { &x.quo };
            for d in src {
                buf.clear();
                write!(buf, "{d}").unwrap();
                s = s.wrapping_add(buf.len() as u64 + *buf.as_bytes().last().unwrap() as u64);
            }
        }
    }
    s
}

fn fnv1a(s: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for &b in s {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

// Trailing fractional zeros and a dangling dot stripped; "-0" -> "0".
fn canon(s: &str) -> &str {
    let mut t = s;
    if t.contains('.') {
        t = t.trim_end_matches('0');
        t = t.strip_suffix('.').unwrap_or(t);
    }
    if t == "-0" {
        t = "0";
    }
    t
}

fn check(k: Kind, x: &Data, sample: &mut Vec<u8>) -> u64 {
    let nres = if k == Kind::AddsubChain { N_DEC / CHAIN_LEN } else { x.money.len() };
    let mut sum: u64 = 0;
    for i in 0..nres {
        let d = match k {
            Kind::TostrMoney => x.money[i],
            Kind::TostrQ12 => x.quo[i],
            _ => op(k, x, i),
        };
        let text = d.to_string();
        let c = canon(&text);
        sum = sum.wrapping_add(fnv1a(c.as_bytes()));
        if i < 1000 {
            sample.extend_from_slice(c.as_bytes());
            sample.push(b'\n');
        }
    }
    sum
}

fn time_it(k: Kind, x: &Data) -> f64 {
    let mut buf = String::new();
    let mut n: u64 = 1;
    loop {
        let t = Instant::now();
        for _ in 0..n {
            black_box(run(k, black_box(x), &mut buf));
        }
        if t.elapsed().as_nanos() > 100_000_000 {
            break;
        }
        n *= 2;
    }
    let mut best = f64::MAX;
    for _ in 0..5 {
        let t = Instant::now();
        for _ in 0..n {
            black_box(run(k, black_box(x), &mut buf));
        }
        best = best.min(t.elapsed().as_nanos() as f64 / n as f64);
    }
    best
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        eprintln!("usage: rust_bench <dir> <workload|check>");
        std::process::exit(2);
    }
    let dir = &args[1];
    let money_s = lines(dir, "money.txt");
    let money = parse_all(&money_s);
    let rate = parse_all(&lines(dir, "rate.txt"));
    assert_eq!(money.len(), N_DEC);
    // The quotients tostr_q12 formats: money[i] / money[i+1] at 12 places.
    let quo: Vec<Decimal> = (0..money.len()).map(|i| mid(EVEN, money[i] / money[(i + 1) % money.len()], 12)).collect();
    let x = Data { money_s, money, rate, quo };
    eprintln!("rust_decimal 1.42.1 (MIT, default features off), rust_bench driver");

    if args[2] == "check" {
        for (name, k) in WORKS {
            let mut sample = Vec::new();
            let h = check(k, &x, &mut sample);
            fs::write(format!("{dir}/sample_rust_{name}.txt"), &sample).unwrap();
            println!("count\t{name}\t{h}");
        }
        std::io::stdout().flush().unwrap();
        return;
    }
    for (name, k) in WORKS {
        if args[2] != name {
            continue;
        }
        let ns = time_it(k, &x);
        let h = check(k, &x, &mut Vec::new());
        println!("{name}\t{ns:.3}\t{h}");
        return;
    }
    eprintln!("unknown workload {}", args[2]);
    std::process::exit(2);
}
