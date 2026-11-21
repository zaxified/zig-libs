// SPDX-License-Identifier: BSD-3-Clause

// tar-rs side of `zig build bench-tar` (modules/tar/tools/bench.zig): times
// tar-rs over the archives the Zig program writes into the directory given as
// the first argument, for the one workload named by the second. Prints one
// line: name, ns/op, result count (tab-separated). Same workloads, same count
// formula and same timing rule as tools/go_bench: double the batch until it
// takes over 100 ms, then keep the best of five.
use std::io::{Cursor, Read, Write};
use std::time::{Duration, Instant};

struct CountW(u64);
impl Write for CountW {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0 += b.len() as u64;
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn read_all(data: &[u8]) -> u64 {
    let data = std::hint::black_box(data);
    let mut ar = tar::Archive::new(Cursor::new(data));
    let mut buf = vec![0u8; 32 * 1024];
    let mut t: u64 = 0;
    for e in ar.entries().unwrap() {
        let mut e = e.unwrap();
        t = t.wrapping_add(e.size());
        t = t.wrapping_add(e.header().uid().unwrap());
        t = t.wrapping_add(e.header().gid().unwrap());
        t = t.wrapping_add(e.header().mtime().unwrap());
        t = t.wrapping_add(e.path_bytes().len() as u64);
        t = t.wrapping_add(e.link_name_bytes().map_or(0, |l| l.len() as u64));
        loop {
            let n = e.read(&mut buf).unwrap();
            if n == 0 {
                break;
            }
            t = t.wrapping_add(n as u64);
        }
    }
    t
}

struct Member {
    path: Vec<u8>,
    link: Option<Vec<u8>>,
    size: u64,
    mode: u32,
    uid: u64,
    gid: u64,
    mtime: u64,
    kind: tar::EntryType,
    body: Vec<u8>,
}

fn load(data: &[u8]) -> Vec<Member> {
    let mut ar = tar::Archive::new(Cursor::new(data));
    let mut out = Vec::new();
    for e in ar.entries().unwrap() {
        let mut e = e.unwrap();
        let h = e.header();
        let (mode, uid, gid, mtime, kind) = (
            h.mode().unwrap(),
            h.uid().unwrap(),
            h.gid().unwrap(),
            h.mtime().unwrap(),
            h.entry_type(),
        );
        let path = e.path_bytes().into_owned();
        let link = e.link_name_bytes().map(|l| l.into_owned());
        let size = e.size();
        let mut body = Vec::new();
        e.read_to_end(&mut body).unwrap();
        out.push(Member { path, link, size, mode, uid, gid, mtime, kind, body });
    }
    out
}

fn time_it<F: FnMut() -> u64>(mut f: F) -> (f64, u64) {
    let mut n: u64 = 1;
    let mut sink: u64 = 0;
    loop {
        let t = Instant::now();
        for _ in 0..n {
            sink = sink.wrapping_add(f());
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
            count = f();
        }
        let d = t.elapsed();
        if d < best {
            best = d;
        }
    }
    std::hint::black_box(sink);
    (best.as_nanos() as f64 / n as f64, count)
}

struct Gen<'a>(u64, &'a [u8]);
impl Read for Gen<'_> {
    fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
        let n = b.len().min(self.1.len()).min(self.0 as usize);
        b[..n].copy_from_slice(&self.1[..n]);
        self.0 -= n as u64;
        Ok(n)
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        eprintln!("usage: rust_bench DIR WORKLOAD");
        std::process::exit(1);
    }
    let (dir, name) = (&args[1], args[2].as_str());
    let read = |f: &str| std::fs::read(format!("{}/{}", dir, f)).unwrap();
    eprintln!("tar-rs 0.4.46");
    let (ns, count) = match name {
        "read_many" => {
            let d = read("many.tar");
            time_it(|| read_all(&d))
        }
        "read_pax" => {
            let d = read("pax.tar");
            time_it(|| read_all(&d))
        }
        "read_big" => {
            let d = read("big.tar");
            time_it(|| read_all(&d))
        }
        "write_many" => {
            let ms = load(&read("many.tar"));
            time_it(|| {
                let mut b = tar::Builder::new(CountW(0));
                for m in std::hint::black_box(&ms) {
                    // A header built from the fields, as the Zig and Go sides
                    // do: not the bytes read from the archive.
                    let mut h = tar::Header::new_ustar();
                    h.set_path(std::str::from_utf8(&m.path).unwrap()).unwrap();
                    if let Some(l) = &m.link {
                        h.set_link_name(std::str::from_utf8(l).unwrap()).unwrap();
                    }
                    h.set_size(m.size);
                    h.set_mode(m.mode);
                    h.set_uid(m.uid);
                    h.set_gid(m.gid);
                    h.set_mtime(m.mtime);
                    h.set_entry_type(m.kind);
                    h.set_cksum();
                    b.append(&h, &m.body[..]).unwrap();
                }
                b.into_inner().unwrap().0
            })
        }
        "write_big" => {
            let chunk = vec![0u8; 64 * 1024];
            const SIZE: u64 = 32 << 20;
            time_it(|| {
                let chunk = std::hint::black_box(&chunk);
                let mut b = tar::Builder::new(CountW(0));
                let mut h = tar::Header::new_ustar();
                h.set_path("big.bin").unwrap();
                h.set_mode(0o644);
                h.set_uid(1000);
                h.set_gid(1000);
                h.set_size(std::hint::black_box(SIZE));
                h.set_mtime(1600000000);
                h.set_entry_type(tar::EntryType::Regular);
                h.set_cksum();
                b.append(&h, Gen(SIZE, chunk)).unwrap();
                b.into_inner().unwrap().0
            })
        }
        _ => {
            eprintln!("unknown workload {}", name);
            std::process::exit(2);
        }
    };
    println!("{}\t{:.1}\t{}", name, ns, count);
}
