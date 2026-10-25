// SPDX-License-Identifier: MIT

// Fastest-in-the-field side of `zig build bench-datefmt`
// (modules/datefmt/tools/bench.zig): times the Rust date crates (pinned by
// Cargo.lock) through their public APIs on the timestamps and strings the Zig
// program writes into the directory given as the first argument, for one
// contender (second argument) and one task (third). Prints one line: task,
// ns/op, result count (tab-separated); a task the contender has no API for
// prints `n/a`. One op = every input once. Each formatted string is a fresh
// `String` (the Zig side allocates its output too). Timing as the other
// sides: double the batch until it takes over 100 ms, keep the best of five.
//
//   fmt_imf             IMF-fixdate text      httpdate fmt_http_date, chrono
//                       (precompiled items), jiff rfc2822 print_timestamp_rfc9110
//   fmt_rfc3339         `YYYY-MM-DDThh:mm:ssZ` humantime format_rfc3339_seconds,
//                       chrono to_rfc3339_opts(Secs, Z), jiff temporal printer
//   fmt_tokens          the same text through a strftime engine: chrono
//                       (precompiled items), jiff strtime
//   parse_imf           IMF-fixdate -> Unix s httpdate parse_http_date, chrono
//                       parse_from_rfc2822, jiff rfc2822 parse_timestamp
//   parse_tokens        the same through a strftime parser: chrono
//                       NaiveDateTime::parse_from_str, jiff strtime::parse
//   parse_rfc3339       `...Z` -> Unix s      humantime parse_rfc3339, chrono
//                       parse_from_rfc3339, jiff temporal parse_timestamp
//   parse_rfc3339_frac  9 fraction digits + `+02:00` -> s + ns: chrono, jiff
//                       (humantime takes `Z` only)
//
// Result counts are the Zig side's: the sum of the output bytes, or the
// wrapping sum of the parsed Unix seconds (plus nanoseconds).

use std::hint::black_box;
use std::time::{Duration, Instant, UNIX_EPOCH};

use chrono::format::{Item, StrftimeItems};
use chrono::{DateTime, NaiveDateTime, SecondsFormat, Utc};

const IMF_FMT: &str = "%a, %d %b %Y %H:%M:%S GMT";
const RFC_FMT: &str = "%Y-%m-%dT%H:%M:%SZ";

fn time_it(mut f: impl FnMut() -> u64) -> (f64, u64) {
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

fn lines(dir: &str, name: &str) -> Vec<String> {
    let s = std::fs::read_to_string(format!("{dir}/{name}")).expect("read input");
    s.lines().map(str::to_owned).collect()
}

fn sum(s: &str) -> u64 {
    s.bytes().map(u64::from).sum()
}

/// `--probe`: one input per stdin line; prints, tab-separated, the line and
/// each crate's verdict (`ok:<unix s>` or `err`) for IMF-fixdate (httpdate,
/// chrono rfc2822, jiff rfc2822) and RFC 3339 (humantime, chrono, jiff).
fn probe() {
    use std::io::BufRead as _;
    let rfc2822p = jiff::fmt::rfc2822::DateTimeParser::new();
    let temporalp = jiff::fmt::temporal::DateTimeParser::new();
    let v = |r: Option<i64>| r.map_or("err".to_owned(), |s| format!("ok:{s}"));
    for line in std::io::stdin().lock().lines() {
        let s = line.unwrap();
        let hd = httpdate::parse_http_date(&s).ok().map(|t| t.duration_since(UNIX_EPOCH).map_or(-1, |d| d.as_secs() as i64));
        let c2 = DateTime::parse_from_rfc2822(&s).ok().map(|t| t.timestamp());
        let j2 = rfc2822p.parse_timestamp(&s).ok().map(|t| t.as_second());
        let ht = humantime::parse_rfc3339(&s).ok().map(|t| t.duration_since(UNIX_EPOCH).map_or(-1, |d| d.as_secs() as i64));
        let c3 = DateTime::parse_from_rfc3339(&s).ok().map(|t| t.timestamp());
        let j3 = temporalp.parse_timestamp(&s).ok().map(|t| t.as_second());
        println!("{s}\thttpdate={}\tchrono2822={}\tjiff2822={}\thumantime={}\tchrono3339={}\tjiff3339={}", v(hd), v(c2), v(j2), v(ht), v(c3), v(j3));
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() == 2 && args[1] == "--probe" {
        return probe();
    }
    if args.len() != 4 {
        eprintln!("usage: rust_fast_bench <work dir> <contender> <task>");
        std::process::exit(2);
    }
    let (dir, who, task) = (args[1].as_str(), args[2].as_str(), args[3].as_str());
    let unix: Vec<i64> = lines(dir, "unix.txt").iter().map(|l| l.parse().unwrap()).collect();
    let imf = lines(dir, "imf.txt");
    let rfc = lines(dir, "rfc.txt");
    let rfcns = lines(dir, "rfcns.txt");

    let sys: Vec<_> = unix.iter().map(|&u| UNIX_EPOCH + Duration::from_secs(u as u64)).collect();
    let chr: Vec<DateTime<Utc>> = unix.iter().map(|&u| DateTime::from_timestamp(u, 0).unwrap()).collect();
    let jts: Vec<jiff::Timestamp> = unix.iter().map(|&u| jiff::Timestamp::from_second(u).unwrap()).collect();
    let imf_items: Vec<Item<'static>> = StrftimeItems::new(IMF_FMT).parse_to_owned().unwrap();
    let rfc_items: Vec<Item<'static>> = StrftimeItems::new(RFC_FMT).parse_to_owned().unwrap();
    let rfc2822 = jiff::fmt::rfc2822::DateTimePrinter::new();
    let rfc2822p = jiff::fmt::rfc2822::DateTimeParser::new();
    let temporal = jiff::fmt::temporal::DateTimePrinter::new();
    let temporalp = jiff::fmt::temporal::DateTimeParser::new();

    let mut f: Box<dyn FnMut() -> u64> = match (task, who) {
        ("fmt_imf", "httpdate") => Box::new(|| sys.iter().map(|&t| sum(&httpdate::fmt_http_date(t))).sum()),
        ("fmt_imf", "chrono") => Box::new(|| chr.iter().map(|t| sum(&t.format_with_items(imf_items.iter()).to_string())).sum()),
        ("fmt_imf", "jiff") => Box::new(|| {
            jts.iter()
                .map(|t| {
                    let mut s = String::new();
                    rfc2822.print_timestamp_rfc9110(t, &mut s).unwrap();
                    sum(&s)
                })
                .sum()
        }),
        ("fmt_rfc3339", "humantime") => Box::new(|| sys.iter().map(|&t| sum(&humantime::format_rfc3339_seconds(t).to_string())).sum()),
        ("fmt_rfc3339", "chrono") => Box::new(|| chr.iter().map(|t| sum(&t.to_rfc3339_opts(SecondsFormat::Secs, true))).sum()),
        ("fmt_rfc3339", "jiff") => Box::new(|| {
            jts.iter()
                .map(|t| {
                    let mut s = String::new();
                    temporal.print_timestamp(t, &mut s).unwrap();
                    sum(&s)
                })
                .sum()
        }),
        ("fmt_tokens", "chrono") => Box::new(|| chr.iter().map(|t| sum(&t.format_with_items(rfc_items.iter()).to_string())).sum()),
        ("fmt_tokens", "jiff") => Box::new(|| jts.iter().map(|&t| sum(&jiff::fmt::strtime::format(RFC_FMT, t).unwrap())).sum()),
        ("parse_imf", "httpdate") => Box::new(|| {
            imf.iter()
                .map(|s| httpdate::parse_http_date(s).unwrap().duration_since(UNIX_EPOCH).unwrap().as_secs())
                .fold(0u64, u64::wrapping_add)
        }),
        ("parse_imf", "chrono") => Box::new(|| {
            imf.iter()
                .map(|s| DateTime::parse_from_rfc2822(s).unwrap().timestamp() as u64)
                .fold(0u64, u64::wrapping_add)
        }),
        ("parse_imf", "jiff") => Box::new(|| {
            imf.iter()
                .map(|s| rfc2822p.parse_timestamp(s).unwrap().as_second() as u64)
                .fold(0u64, u64::wrapping_add)
        }),
        ("parse_tokens", "chrono") => Box::new(|| {
            imf.iter()
                .map(|s| NaiveDateTime::parse_from_str(s, IMF_FMT).unwrap().and_utc().timestamp() as u64)
                .fold(0u64, u64::wrapping_add)
        }),
        ("parse_tokens", "jiff") => Box::new(|| {
            imf.iter()
                .map(|s| jiff::fmt::strtime::parse(IMF_FMT, s).unwrap().to_datetime().unwrap().to_zoned(jiff::tz::TimeZone::UTC).unwrap().timestamp().as_second() as u64)
                .fold(0u64, u64::wrapping_add)
        }),
        ("parse_rfc3339", "humantime") => Box::new(|| {
            rfc.iter()
                .map(|s| humantime::parse_rfc3339(s).unwrap().duration_since(UNIX_EPOCH).unwrap().as_secs())
                .fold(0u64, u64::wrapping_add)
        }),
        ("parse_rfc3339", "chrono") => Box::new(|| {
            rfc.iter()
                .map(|s| DateTime::parse_from_rfc3339(s).unwrap().timestamp() as u64)
                .fold(0u64, u64::wrapping_add)
        }),
        ("parse_rfc3339", "jiff") => Box::new(|| {
            rfc.iter()
                .map(|s| temporalp.parse_timestamp(s).unwrap().as_second() as u64)
                .fold(0u64, u64::wrapping_add)
        }),
        ("parse_rfc3339_frac", "chrono") => Box::new(|| {
            rfcns.iter()
                .map(|s| {
                    let t = DateTime::parse_from_rfc3339(s).unwrap();
                    (t.timestamp() as u64).wrapping_add(u64::from(t.timestamp_subsec_nanos()))
                })
                .fold(0u64, u64::wrapping_add)
        }),
        ("parse_rfc3339_frac", "jiff") => Box::new(|| {
            rfcns.iter()
                .map(|s| {
                    let t = temporalp.parse_timestamp(s).unwrap();
                    (t.as_second() as u64).wrapping_add(t.subsec_nanosecond() as u64)
                })
                .fold(0u64, u64::wrapping_add)
        }),
        _ => {
            println!("{task}\tn/a\t0");
            return;
        }
    };
    let (ns, count) = time_it(&mut f);
    println!("{task}\t{ns:.1}\t{count}");
}
