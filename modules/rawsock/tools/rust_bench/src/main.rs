// SPDX-License-Identifier: MIT

// Rust side of `zig build bench-rawsock` (modules/rawsock/tools/bench.zig):
// the `pcap-file` 2.0.0 crate (MIT) reads and writes the savefiles the Zig
// program wrote into the directory given as the first argument. Prints one
// line: name, ns/op, count (tab-separated). The crate has no filter language and
// no BPF machine: only the three savefile rows. The slice parsers
// (`PcapParser`, `PcapNgParser`) are the closest thing it has to our slice
// reader (no per-packet copy).
use pcap_file::pcap::{PcapHeader, PcapPacket, PcapParser, PcapWriter};
use pcap_file::pcapng::{Block, PcapNgParser};
use pcap_file::Endianness;
use std::time::{Duration, Instant};

fn read_pcap(file: &[u8]) -> u64 {
    let (mut rest, parser) = PcapParser::new(file).expect("pcap header");
    let mut sum: u64 = 0;
    while !rest.is_empty() {
        let (r, p) = parser.next_packet(rest).expect("pcap record");
        rest = r;
        sum = sum
            .wrapping_add(p.data.len() as u64)
            .wrapping_add(p.orig_len as u64)
            .wrapping_add(p.timestamp.as_micros() as u64);
    }
    sum
}

fn read_pcapng(file: &[u8]) -> u64 {
    let (mut rest, mut parser) = PcapNgParser::new(file).expect("pcapng header");
    let mut sum: u64 = 0;
    while !rest.is_empty() {
        let (r, b) = parser.next_block(rest).expect("pcapng block");
        rest = r;
        if let Block::EnhancedPacket(e) = b {
            sum = sum
                .wrapping_add(e.data.len() as u64)
                .wrapping_add(e.original_len as u64)
                .wrapping_add(e.timestamp.as_micros() as u64);
        }
    }
    sum
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        std::process::exit(2);
    }
    let dir = &args[1];
    let name = args[2].as_str();
    eprintln!("pcap-file 2.0.0");
    let read = |f: &str| std::fs::read(format!("{}/{}", dir, f)).expect("read file");

    let mut op: Box<dyn FnMut() -> u64> = match name {
        "pcap_read" => {
            let file = read("frames.pcap");
            Box::new(move || read_pcap(&file))
        }
        "pcapng_read" => {
            let file = read("frames.pcapng");
            Box::new(move || read_pcapng(&file))
        }
        "pcap_write" => {
            let file = read("frames.pcap");
            let (mut rest, parser) = PcapParser::new(&file).expect("pcap header");
            let mut frames: Vec<(Duration, u32, Vec<u8>)> = Vec::new();
            while !rest.is_empty() {
                let (r, p) = parser.next_packet(rest).expect("pcap record");
                rest = r;
                frames.push((p.timestamp, p.orig_len, p.data.to_vec()));
            }
            let mut buf: Vec<u8> = Vec::with_capacity(file.len() + 4096);
            Box::new(move || {
                buf.clear();
                let header = PcapHeader { endianness: Endianness::Little, snaplen: 262144, ..Default::default() };
                let mut w = PcapWriter::with_header(&mut buf, header).expect("header");
                for (ts, ol, d) in &frames {
                    w.write_packet(&PcapPacket::new(*ts, *ol, d)).expect("record");
                }
                drop(w);
                buf.len() as u64
            })
        }
        _ => std::process::exit(2),
    };

    let mut reps = 1u32;
    loop {
        let t = Instant::now();
        for _ in 0..reps {
            std::hint::black_box(op());
        }
        if t.elapsed() > Duration::from_millis(100) {
            break;
        }
        reps *= 2;
    }
    let mut best = Duration::from_secs(1 << 40);
    let mut count = 0u64;
    for _ in 0..5 {
        let t = Instant::now();
        for _ in 0..reps {
            count = std::hint::black_box(op());
        }
        let d = t.elapsed() / reps;
        if d < best {
            best = d;
        }
    }
    println!("{}\t{:.1}\t{}", name, best.as_nanos() as f64, count);
}
