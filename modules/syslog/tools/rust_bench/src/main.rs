// SPDX-License-Identifier: MIT

// Rust side of `zig build bench-syslog` (modules/syslog/tools/bench.zig): the
// `syslog` 7.0.0, `syslog_rfc5424` 0.10.0 and `syslog_loose` 0.23.0 crates over the
// corpus the Zig program writes into the directory given as the first argument,
// for the one workload named by the second. Prints one line: name, ns/op, count
// (tab-separated). One op = all 64 messages. See bench.zig for what each workload
// pairs.
//
// Timing matches the Zig side: double the batch until it takes over 100 ms, then
// keep the best of five.

use std::collections::BTreeMap;
use std::hint::black_box;
use std::os::unix::net::UnixDatagram;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use syslog::{Facility, Formatter3164, Formatter5424, LogFormat, Severity};
use syslog_loose::{parse_message as loose_parse, ProcId as LooseProcId, Variant};
use syslog_rfc5424::message::ProcId;
use syslog_rfc5424::parse_message as rfc_parse;

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

fn read_lines(dir: &str, file: &str) -> Vec<String> {
    let path: PathBuf = [dir, file].iter().collect();
    let b = std::fs::read(path).unwrap();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        let n = (b[i] as usize) << 8 | b[i + 1] as usize;
        out.push(String::from_utf8(b[i + 2..i + 2 + n].to_vec()).unwrap());
        i += 2 + n;
    }
    out
}

fn decimal_len(mut n: i32) -> u64 {
    let mut l = 1;
    while n >= 10 {
        n /= 10;
        l += 1;
    }
    l
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let (dir, name) = (args[1].as_str(), args[2].as_str());
    let (ns, count) = match name {
        "fmt_5424" | "fmt_5424_sd" => {
            eprintln!("Rust syslog 7.0.0 Formatter5424");
            let texts = read_lines(dir, "texts.bin");
            let fmt = Formatter5424 {
                facility: Facility::LOG_USER,
                hostname: Some("web-1.example.org".into()),
                process: "api-gateway".into(),
                pid: 4242,
            };
            let with_sd = name == "fmt_5424_sd";
            let sds: Vec<BTreeMap<String, BTreeMap<String, String>>> = (0..texts.len())
                .map(|i| {
                    let mut p = BTreeMap::new();
                    p.insert("iut".to_string(), "3".to_string());
                    p.insert("eventSource".to_string(), "App\"lica]tion\\x".to_string());
                    p.insert("eventID".to_string(), (5000 + i).to_string());
                    let mut m = BTreeMap::new();
                    if with_sd {
                        m.insert("exampleSDID@32473".to_string(), p);
                    }
                    m
                })
                .collect();
            let mut buf: Vec<u8> = Vec::with_capacity(2048);
            time_it(|| {
                let mut t = 0;
                for (i, s) in texts.iter().enumerate() {
                    buf.clear();
                    fmt.format(&mut buf, Severity::LOG_INFO, (1000 + i as u32, sds[i].clone(), s.as_str()))
                        .unwrap();
                    black_box(buf.as_ptr());
                    t += 1;
                }
                t
            })
        }
        "fmt_3164" => {
            eprintln!("Rust syslog 7.0.0 Formatter3164");
            let texts = read_lines(dir, "texts.bin");
            let fmt = Formatter3164 {
                facility: Facility::LOG_USER,
                hostname: Some("web-1.example.org".into()),
                process: "api-gateway".into(),
                pid: 4242,
            };
            let mut buf: Vec<u8> = Vec::with_capacity(2048);
            time_it(|| {
                let mut t = 0;
                for s in &texts {
                    buf.clear();
                    fmt.format(&mut buf, Severity::LOG_INFO, s.as_str()).unwrap();
                    black_box(buf.as_ptr());
                    t += 1;
                }
                t
            })
        }
        "send_unix" => {
            eprintln!("Rust syslog 7.0.0 unix_custom");
            let texts = read_lines(dir, "texts.bin");
            // Relative: a work directory under a deep worktree does not fit sun_path.
            let cwd = std::env::current_dir().unwrap();
            let abs: PathBuf = [dir, "rust.sock"].iter().collect();
            let rel = abs.strip_prefix(&cwd).unwrap_or(&abs).to_path_buf();
            let _ = std::fs::remove_file(&rel);
            let rx = UnixDatagram::bind(&rel).unwrap();
            std::thread::spawn(move || {
                let mut b = [0u8; 4096];
                while rx.recv(&mut b).is_ok() {}
            });
            let fmt = Formatter3164 {
                facility: Facility::LOG_USER,
                hostname: None,
                process: "api-gateway".into(),
                pid: 4242,
            };
            let mut logger = syslog::unix_custom(fmt, &rel).unwrap();
            time_it(|| {
                let mut t = 0;
                for s in &texts {
                    logger.info(s.as_str()).unwrap();
                    t += 1;
                }
                t
            })
        }
        "parse_5424" | "parse_5424_sd" => {
            eprintln!("Rust syslog_rfc5424 0.10.0");
            let lines = read_lines(dir, &format!("{name}.bin"));
            time_it(|| {
                let mut t: u64 = 0;
                for l in &lines {
                    let m = rfc_parse(l).unwrap();
                    t += m.hostname.as_ref().map_or(0, |s| s.len()) as u64;
                    t += m.appname.as_ref().map_or(0, |s| s.len()) as u64;
                    t += match &m.procid {
                        Some(ProcId::PID(n)) => decimal_len(*n),
                        Some(ProcId::Name(s)) => s.len() as u64,
                        None => 0,
                    };
                    t += m.msgid.as_ref().map_or(0, |s| s.len()) as u64;
                    t += m.msg.len() as u64;
                    t = t.wrapping_add(m.timestamp.unwrap_or(0) as u64);
                    for (id, ps) in m.sd.iter() {
                        t += id.len() as u64;
                        for (k, v) in ps {
                            t += (k.len() + v.len()) as u64;
                        }
                    }
                }
                t
            })
        }
        "parse_bad" => {
            eprintln!("Rust syslog_rfc5424 0.10.0");
            let lines = read_lines(dir, "parse_bad.bin");
            time_it(|| {
                let mut t: u64 = 0;
                for l in &lines {
                    if rfc_parse(l).is_err() {
                        t += 1;
                    }
                }
                t
            })
        }
        "parse_3164" => {
            eprintln!("Rust syslog_loose 0.23.0 RFC3164");
            let lines = read_lines(dir, "parse_3164.bin");
            time_it(|| {
                let mut t: u64 = 0;
                for l in &lines {
                    let m = loose_parse(l, Variant::RFC3164);
                    t += m.hostname.map_or(0, |s| s.len()) as u64;
                    t += m.appname.map_or(0, |s| s.len()) as u64;
                    t += match &m.procid {
                        Some(LooseProcId::PID(n)) => decimal_len(*n),
                        Some(LooseProcId::Name(s)) => s.len() as u64,
                        None => 0,
                    };
                    t += m.msg.len() as u64;
                }
                t
            })
        }
        "parse_loose" => {
            eprintln!("Rust syslog_loose 0.23.0 RFC5424");
            let lines = read_lines(dir, "parse_5424_sd.bin");
            time_it(|| {
                let mut t: u64 = 0;
                for l in &lines {
                    let m = loose_parse(l, Variant::RFC5424);
                    t += m.hostname.map_or(0, |s| s.len()) as u64;
                    t += m.appname.map_or(0, |s| s.len()) as u64;
                    t += match &m.procid {
                        Some(LooseProcId::PID(n)) => decimal_len(*n),
                        Some(LooseProcId::Name(s)) => s.len() as u64,
                        None => 0,
                    };
                    t += m.msgid.map_or(0, |s| s.len()) as u64;
                    t += m.msg.len() as u64;
                    t = t.wrapping_add(m.timestamp.map_or(0, |ts| ts.timestamp()) as u64);
                    for el in &m.structured_data {
                        t += el.id.len() as u64;
                        for (k, v) in el.params() {
                            t += (k.len() + v.len()) as u64;
                        }
                    }
                }
                t
            })
        }
        _ => panic!("no workload {name}"),
    };
    println!("{name}\t{ns:.1}\t{count}");
}
