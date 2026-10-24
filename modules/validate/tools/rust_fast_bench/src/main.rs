// SPDX-License-Identifier: MIT

// "Fastest in the field" side of `zig build bench-validate`
// (modules/validate/tools/bench.zig): times jprochazk/garde 0.23.0 and
// Keats/validator 0.21.0 over the JSON bodies the Zig program writes into the
// directory given as the first argument, for the one workload named by the
// second (decode_small, valid_small, decode_nested, valid_nested,
// decode_invalid, invalid, decode_formats, formats) and the contender named by
// the third ("garde" or "validator"). Prints one line, tab-separated: name,
// ns/op, count.
//
// One op = every body of the workload once: serde_json::from_slice into a
// #[derive(Deserialize)] struct, then (unless decode_*) the crate's
// `validate()`. count = per body 1 if it validated, else the number of failed
// rules (decode_*: 1 per decoded body) -- the Go side's definition. The rules
// are the ones go_bench/main.go tags (and tools/bench.zig declares).
//
// Rule equivalence, stated so the rows are not read as more than they are:
//   - email: each crate's own email rule (garde: regex-based parser; validator:
//     user-part regex + domain check + IDNA fallback); semantics differ from
//     ours and from Go's `email` in corner cases, the bench bodies are plain.
//   - uuid4: neither crate has a uuid rule; a hand-written custom function
//     (36 bytes, hyphens at 8/13/18/23, hex digits, version nibble '4',
//     variant 8/9/a/b) is used in both.
//   - http_url: each crate's `url` rule (url::Url::parse) PLUS a custom rule
//     requiring an http:// or https:// prefix (the crates accept any scheme).
//     That is two rules on one field; on valid bodies both pass.
//   - length: garde counts bytes, validator counts chars; bodies are ASCII.
//   - "required": a missing field is a serde_json error here (the bodies
//     always carry every field, so it never fires); Zig/Go treat it likewise.
//   - invalid: both contenders report exactly 3 errors (name length, email,
//     age range), one rule failing per field.
//
// Timing matches the Zig side: double the batch until it takes over 100 ms,
// then keep the best of five.

use serde::Deserialize;
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

fn is_uuid4(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() != 36 {
        return false;
    }
    for (i, &c) in b.iter().enumerate() {
        let ok = match i {
            8 | 13 | 18 | 23 => c == b'-',
            14 => c == b'4',
            19 => matches!(c, b'8' | b'9' | b'a' | b'b' | b'A' | b'B'),
            _ => c.is_ascii_hexdigit(),
        };
        if !ok {
            return false;
        }
    }
    true
}

fn is_http(s: &str) -> bool {
    let b = s.as_bytes();
    let starts = |p: &[u8]| b.len() >= p.len() && b[..p.len()].eq_ignore_ascii_case(p);
    starts(b"http://") || starts(b"https://")
}

mod g {
    use super::*;

    fn uuid4(v: &str, _: &()) -> garde::Result {
        if super::is_uuid4(v) { Ok(()) } else { Err(garde::Error::new("not a uuid4")) }
    }
    fn http(v: &str, _: &()) -> garde::Result {
        if super::is_http(v) { Ok(()) } else { Err(garde::Error::new("not http(s)")) }
    }

    #[derive(Deserialize, garde::Validate)]
    pub struct Signup {
        #[garde(length(min = 2, max = 64))]
        pub name: String,
        #[garde(email)]
        pub email: String,
        #[garde(range(min = 0, max = 150))]
        pub age: i32,
        #[garde(length(min = 8, max = 72))]
        pub password: String,
    }

    #[derive(Deserialize, garde::Validate)]
    pub struct Owner {
        #[garde(length(min = 2, max = 64))]
        pub name: String,
        #[garde(email)]
        pub email: String,
    }

    #[derive(Deserialize, garde::Validate)]
    pub struct Item {
        #[garde(length(min = 3, max = 20))]
        pub sku: String,
        #[garde(range(min = 1, max = 1000))]
        pub qty: u16,
        #[garde(range(min = 0.0))]
        pub price: f64,
    }

    #[derive(Deserialize, garde::Validate)]
    pub struct Order {
        #[garde(length(min = 1))]
        pub id: String,
        #[garde(dive)]
        pub owner: Owner,
        #[garde(length(min = 1, max = 100), dive)]
        pub items: Vec<Item>,
    }

    #[derive(Deserialize, garde::Validate)]
    pub struct Links {
        #[garde(email)]
        pub email: String,
        #[garde(custom(uuid4))]
        pub id: String,
        #[garde(url, custom(http))]
        pub url: String,
    }
}

mod v {
    use super::*;
    use validator::{Validate as _, ValidationError, ValidationErrors, ValidationErrorsKind};

    fn uuid4(s: &str) -> Result<(), ValidationError> {
        if super::is_uuid4(s) { Ok(()) } else { Err(ValidationError::new("uuid4")) }
    }
    fn http(s: &str) -> Result<(), ValidationError> {
        if super::is_http(s) { Ok(()) } else { Err(ValidationError::new("http_url")) }
    }

    pub fn count(e: &ValidationErrors) -> u64 {
        e.errors()
            .values()
            .map(|k| match k {
                ValidationErrorsKind::Field(v) => v.len() as u64,
                ValidationErrorsKind::Struct(s) => count(s),
                ValidationErrorsKind::List(m) => m.values().map(|s| count(s)).sum(),
            })
            .sum()
    }

    #[derive(Deserialize, serde::Serialize, validator::Validate)]
    pub struct Signup {
        #[validate(length(min = 2, max = 64))]
        pub name: String,
        #[validate(email)]
        pub email: String,
        #[validate(range(min = 0, max = 150))]
        pub age: i32,
        #[validate(length(min = 8, max = 72))]
        pub password: String,
    }

    #[derive(Deserialize, serde::Serialize, validator::Validate)]
    pub struct Owner {
        #[validate(length(min = 2, max = 64))]
        pub name: String,
        #[validate(email)]
        pub email: String,
    }

    #[derive(Deserialize, serde::Serialize, validator::Validate)]
    pub struct Item {
        #[validate(length(min = 3, max = 20))]
        pub sku: String,
        #[validate(range(min = 1, max = 1000))]
        pub qty: u16,
        #[validate(range(min = 0.0))]
        pub price: f64,
    }

    #[derive(Deserialize, serde::Serialize, validator::Validate)]
    pub struct Order {
        #[validate(length(min = 1))]
        pub id: String,
        #[validate(nested)]
        pub owner: Owner,
        #[validate(length(min = 1, max = 100), nested)]
        pub items: Vec<Item>,
    }

    #[derive(Deserialize, serde::Serialize, validator::Validate)]
    pub struct Links {
        #[validate(email)]
        pub email: String,
        #[validate(custom(function = "uuid4"))]
        pub id: String,
        #[validate(url, custom(function = "http"))]
        pub url: String,
    }
}

/// One op: decode every body into T, then (when `check`) validate it with `val`,
/// which returns the number of failed rules.
fn run<T: for<'de> Deserialize<'de>>(bodies: &[Vec<u8>], check: bool, val: impl Fn(&T) -> u64) -> u64 {
    let mut sum = 0;
    for b in bodies {
        let t: T = serde_json::from_slice(b).expect("decode");
        if !check {
            black_box(&t);
            sum += 1;
            continue;
        }
        let n = val(&t);
        sum += if n == 0 { 1 } else { n };
    }
    sum
}

fn gv<T: garde::Validate<Context = ()>>(t: &T) -> u64 {
    match t.validate() {
        Ok(()) => 0,
        Err(r) => r.iter().count() as u64,
    }
}

fn vv<T: validator::Validate>(t: &T) -> u64 {
    match t.validate() {
        Ok(()) => 0,
        Err(e) => v::count(&e),
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 4 {
        eprintln!("usage: validate_fast_bench <work dir> <workload> <contender>");
        std::process::exit(2);
    }
    let (dir, name, who) = (std::path::Path::new(&args[1]), args[2].as_str(), args[3].as_str());
    let check = !name.starts_with("decode_");
    let shape = name.trim_start_matches("decode_").trim_start_matches("valid_");
    let raw = std::fs::read(dir.join(format!("{shape}.json"))).unwrap_or_else(|e| {
        eprintln!("{shape}.json: {e}");
        std::process::exit(1);
    });
    let trimmed: &[u8] = match raw.iter().rposition(|&b| b != 0) {
        Some(i) => &raw[..=i],
        None => &raw,
    };
    let bodies: Vec<Vec<u8>> = trimmed.split(|&b| b == 0).map(<[u8]>::to_vec).collect();
    let bodies = black_box(&bodies[..]);

    let mut f: Box<dyn FnMut() -> u64 + '_> = match (who, shape) {
        ("garde", "small" | "invalid") => Box::new(move || run::<g::Signup>(bodies, check, gv)),
        ("garde", "nested") => Box::new(move || run::<g::Order>(bodies, check, gv)),
        ("garde", "formats") => Box::new(move || run::<g::Links>(bodies, check, gv)),
        ("validator", "small" | "invalid") => Box::new(move || run::<v::Signup>(bodies, check, vv)),
        ("validator", "nested") => Box::new(move || run::<v::Order>(bodies, check, vv)),
        ("validator", "formats") => Box::new(move || run::<v::Links>(bodies, check, vv)),
        _ => {
            eprintln!("unknown workload {name} / contender {who}");
            std::process::exit(2);
        }
    };
    f(); // warm up (regex statics, allocator)
    let (ns, count) = time_it(|| f());
    println!("{name}\t{ns:.1}\t{count}");
}
