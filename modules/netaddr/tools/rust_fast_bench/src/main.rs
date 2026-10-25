// SPDX-License-Identifier: MIT

// Field side of `zig build bench-netaddr` (modules/netaddr/tools/bench.zig):
// times the fastest implementations outside the reference over the inputs
// that program writes into the directory given as the only argument --
// Rust std `IpAddr` (parse, Display, Ord), the `ipnet` crate (pinned by
// Cargo.lock) for prefix containment, and glibc `inet_pton`/`inet_ntop`
// through FFI. Public APIs only. Prints one line per row: workload, contender,
// ns/op, result count -- tab-separated. Timing matches the Go and Zig sides:
// double the batch until it takes over 100 ms, keep the best of five.

use std::ffi::{c_char, c_int, c_void, CString};
use std::fmt::Write as _;
use std::hint::black_box;
use std::net::{IpAddr, Ipv6Addr};
use std::time::{Duration, Instant};

use ipnet::IpNet;

const AF_INET: c_int = 2;
const AF_INET6: c_int = 10;

extern "C" {
    fn inet_pton(af: c_int, src: *const c_char, dst: *mut c_void) -> c_int;
    fn inet_ntop(af: c_int, src: *const c_void, dst: *mut c_char, size: u32) -> *const c_char;
    fn strlen(s: *const c_char) -> usize;
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

fn lines(dir: &str, name: &str) -> Vec<String> {
    let text = std::fs::read_to_string(format!("{dir}/{name}")).expect("read input");
    text.trim_end_matches('\n').split('\n').map(str::to_owned).collect()
}

fn report(workload: &str, contender: &str, f: impl FnMut() -> usize) {
    let (ns, count) = time_it(f);
    println!("{workload}\t{contender}\t{ns:.1}\t{count}");
}

/// A `fmt::Write` over a fixed stack buffer, so Display costs no allocation.
struct Buf {
    b: [u8; 64],
    n: usize,
}
impl std::fmt::Write for Buf {
    fn write_str(&mut self, s: &str) -> std::fmt::Result {
        let end = self.n + s.len();
        self.b.get_mut(self.n..end).ok_or(std::fmt::Error)?.copy_from_slice(s.as_bytes());
        self.n = end;
        Ok(())
    }
}

fn main() {
    let dir = std::env::args().nth(1).expect("usage: rust_fast_bench <work dir>");
    let v4 = lines(&dir, "v4.txt");
    let v6text = lines(&dir, "v6.txt");
    let v6: Vec<Ipv6Addr> = v6text.iter().map(|s| s.parse().unwrap()).collect();
    let mixed: Vec<IpAddr> = lines(&dir, "mixed.txt").iter().map(|s| s.parse().unwrap()).collect();
    let pfx: Vec<IpNet> = lines(&dir, "prefixes.txt").iter().map(|s| s.parse().unwrap()).collect();
    let probes: Vec<IpAddr> = lines(&dir, "probes.txt").iter().map(|s| s.parse().unwrap()).collect();
    let v4c: Vec<CString> = v4.iter().map(|s| CString::new(s.as_str()).unwrap()).collect();
    let v6c: Vec<CString> = v6text.iter().map(|s| CString::new(s.as_str()).unwrap()).collect();

    report("parse_v4", "rust std IpAddr", || v4.iter().filter(|s| s.parse::<IpAddr>().is_ok()).count());
    report("parse_v4", "glibc inet_pton", || {
        let mut out = [0u8; 4];
        v4c.iter().filter(|s| unsafe { inet_pton(AF_INET, s.as_ptr(), out.as_mut_ptr().cast()) } == 1).count()
    });
    report("parse_v6", "rust std IpAddr", || v6text.iter().filter(|s| s.parse::<IpAddr>().is_ok()).count());
    report("parse_v6", "glibc inet_pton", || {
        let mut out = [0u8; 16];
        v6c.iter().filter(|s| unsafe { inet_pton(AF_INET6, s.as_ptr(), out.as_mut_ptr().cast()) } == 1).count()
    });
    report("format_v6", "rust std Display", || {
        let mut k = 0;
        for a in &v6 {
            let mut b = Buf { b: [0; 64], n: 0 };
            write!(b, "{a}").unwrap();
            k += black_box(&b).n;
        }
        k
    });
    report("format_v6", "glibc inet_ntop", || {
        let mut k = 0;
        let mut out = [0 as c_char; 46];
        for a in &v6 {
            let o = a.octets();
            unsafe {
                inet_ntop(AF_INET6, o.as_ptr().cast(), out.as_mut_ptr(), 46);
                k += strlen(out.as_ptr());
            }
        }
        k
    });
    report("prefix_contains", "ipnet IpNet", || pfx.iter().zip(&probes).filter(|(p, a)| p.contains(*a)).count());
    let mut scratch = mixed.clone();
    let first_v6 = |s: &[IpAddr]| s.iter().position(|a| a.is_ipv6()).unwrap_or(s.len());
    report("sort_mixed", "rust std sort_unstable", || {
        scratch.copy_from_slice(&mixed);
        scratch.sort_unstable();
        first_v6(&scratch)
    });
    report("sort_mixed", "rust std sort", || {
        scratch.copy_from_slice(&mixed);
        scratch.sort();
        first_v6(&scratch)
    });
}
