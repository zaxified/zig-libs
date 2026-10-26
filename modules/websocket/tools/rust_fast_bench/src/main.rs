// SPDX-License-Identifier: MIT

// Rust sides of `zig build bench-websocket` (modules/websocket/tools/bench.zig):
//
//   ws_fast_bench <work dir> <workload> fastwebsockets   denoland/fastwebsockets 0.10.0
//   ws_fast_bench <work dir> <workload> tungstenite      snapview/tungstenite 0.30.0
//
// Both as a server on an in-memory stream, on the frames the Zig program
// writes into <work dir> (`<name>.wire`, `<name>.count`), the same bytes the
// Go sides read. Prints one line: name, ns/op, result count (tab-separated),
// the library and its settings on stderr (the banner).
//
//   read_*   one op = read every message of the wire file to its end
//   write_*  one op = write the messages described by `<name>.wire` (the plain
//            payloads, \x00-separated) as server frames
//
// count = messages + payload bytes delivered (read) or messages written
// (write), as on the Go and Zig sides. The stream is `Mem`: reads cycle over
// the wire forever, writes are counted and dropped (no socket in the number).
//
// Equivalence notes:
//   * Neither library implements permessage-deflate (fastwebsockets: "not
//     supported yet" in its crate docs; tungstenite dropped its deflate
//     feature), so the *_deflate workloads are refused (exit 3); the Zig side
//     does not run them and prints n/a.
//   * UTF-8: both validate text messages (fastwebsockets: simdutf8 per final
//     frame, `utf8` crate over fragments; tungstenite: std::str::from_utf8 on
//     the completed message). Like ours, unlike coder and gorilla.
//   * fastwebsockets is async. The stream is always ready, so the futures are
//     driven by a no-op-waker poll loop (`ready`) instead of a tokio runtime:
//     what is timed is the library's state machine, not a scheduler (a real
//     server polls a task once per wake-up too). FragmentCollector gives whole
//     messages, as tungstenite and the other sides do. Default settings
//     otherwise (auto close/pong, vectored writes over 1 KiB), max message
//     size 1 MiB as on the other sides.
//   * tungstenite is sync. Defaults (128 KiB read/write buffers) with
//     max_message_size 1 MiB; `send` = write + flush per message. A message
//     is an owned `Bytes`/`Utf8Bytes`, so the writes clone a prepared one (a
//     refcount increment, no allocation) where the other sides pass a slice.
//
// Timing matches the other sides: double the batch until one batch takes over
// 100 ms, then keep the best of five.

use std::future::Future;
use std::io::{self, Read, Write};
use std::pin::{pin, Pin};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

static mut SINK: usize = 0;

fn time_it(mut f: impl FnMut() -> usize) -> (f64, usize) {
    let mut n: u64 = 1;
    loop {
        let t = Instant::now();
        for _ in 0..n {
            let r = f();
            unsafe { SINK = SINK.wrapping_add(r) };
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
    (best.as_nanos() as f64 / n as f64, count)
}

/// Reads cycle over `data` forever; writes are counted and dropped.
struct Mem {
    data: Vec<u8>,
    at: usize,
    written: usize,
}

impl Mem {
    /// Volatile: the count is never read, and must not let the writes be
    /// optimised away.
    #[inline(always)]
    fn wrote(&mut self, n: usize) {
        unsafe { std::ptr::write_volatile(&mut self.written, self.written + n) };
    }

    fn fill(&mut self, out: &mut [u8]) -> usize {
        if self.at == self.data.len() {
            self.at = 0;
        }
        let n = out.len().min(self.data.len() - self.at);
        out[..n].copy_from_slice(&self.data[self.at..self.at + n]);
        self.at += n;
        n
    }
}

impl Read for Mem {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        Ok(self.fill(buf))
    }
}
impl Write for Mem {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.wrote(buf.len());
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl AsyncRead for Mem {
    fn poll_read(mut self: Pin<&mut Self>, _: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let me = &mut *self;
        if me.at == me.data.len() {
            me.at = 0;
        }
        let n = buf.remaining().min(me.data.len() - me.at);
        buf.put_slice(&me.data[me.at..me.at + n]);
        me.at += n;
        Poll::Ready(Ok(()))
    }
}
impl AsyncWrite for Mem {
    fn poll_write(mut self: Pin<&mut Self>, _: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        self.wrote(buf.len());
        Poll::Ready(Ok(buf.len()))
    }
    fn poll_write_vectored(mut self: Pin<&mut Self>, _: &mut Context<'_>, bufs: &[io::IoSlice<'_>]) -> Poll<io::Result<usize>> {
        let n: usize = bufs.iter().map(|b| b.len()).sum();
        self.wrote(n);
        Poll::Ready(Ok(n))
    }
    fn is_write_vectored(&self) -> bool {
        true
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// Drive a future whose I/O is always ready.
fn ready<F: Future>(f: F) -> F::Output {
    let mut f = pin!(f);
    let mut cx = Context::from_waker(Waker::noop());
    match f.as_mut().poll(&mut cx) {
        Poll::Ready(v) => v,
        Poll::Pending => panic!("in-memory stream returned Pending"),
    }
}

fn fastwebsockets_side(wire: Vec<u8>, name: &str, msgs: usize, payloads: Vec<Vec<u8>>) -> (f64, usize) {
    use fastwebsockets::{FragmentCollector, Frame, OpCode, Payload, Role, WebSocket};
    if name.starts_with("read_") {
        let mut ws = WebSocket::after_handshake(Mem { data: wire, at: 0, written: 0 }, Role::Server);
        ws.set_max_message_size(1 << 20);
        let mut ws = FragmentCollector::new(ws);
        time_it(|| {
            let mut sum = 0;
            for _ in 0..msgs {
                let f = ready(ws.read_frame()).unwrap();
                assert!(f.fin && matches!(f.opcode, OpCode::Text | OpCode::Binary));
                sum += f.payload.len() + 1;
            }
            sum
        })
    } else {
        let binary = name.contains("binary");
        let mut ws = WebSocket::after_handshake(Mem { data: Vec::new(), at: 0, written: 0 }, Role::Server);
        time_it(|| {
            for p in &payloads {
                let payload = Payload::Borrowed(p);
                let f = if binary { Frame::binary(payload) } else { Frame::text(payload) };
                ready(ws.write_frame(f)).unwrap();
            }
            payloads.len()
        })
    }
}

fn tungstenite_side(wire: Vec<u8>, name: &str, msgs: usize, payloads: Vec<Vec<u8>>) -> (f64, usize) {
    use tungstenite::protocol::{Role, WebSocketConfig};
    use tungstenite::{Message, Utf8Bytes, WebSocket};
    let cfg = WebSocketConfig::default().max_message_size(Some(1 << 20));
    if name.starts_with("read_") {
        let mut ws = WebSocket::from_raw_socket(Mem { data: wire, at: 0, written: 0 }, Role::Server, Some(cfg));
        time_it(|| {
            let mut sum = 0;
            for _ in 0..msgs {
                sum += match ws.read().unwrap() {
                    Message::Text(t) => t.len(),
                    Message::Binary(b) => b.len(),
                    _ => panic!("unexpected message"),
                } + 1;
            }
            sum
        })
    } else {
        let binary = name.contains("binary");
        let prepared: Vec<Message> = payloads
            .iter()
            .map(|p| if binary { Message::Binary(p.clone().into()) } else { Message::Text(Utf8Bytes::from(std::str::from_utf8(p).unwrap())) })
            .collect();
        let mut ws = WebSocket::from_raw_socket(Mem { data: Vec::new(), at: 0, written: 0 }, Role::Server, Some(cfg));
        time_it(|| {
            for m in &prepared {
                ws.send(m.clone()).unwrap();
            }
            prepared.len()
        })
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 4 {
        eprintln!("usage: ws_fast_bench <work dir> <workload> fastwebsockets|tungstenite");
        std::process::exit(2);
    }
    let (dir, name, lib) = (&args[1], &args[2], &args[3]);
    if name.ends_with("_deflate") {
        eprintln!("{lib}: no permessage-deflate support; workload {name} is n/a");
        std::process::exit(3);
    }
    let wire = std::fs::read(format!("{dir}/{name}.wire")).unwrap();
    let (msgs, payloads) = if name.starts_with("read_") {
        let meta = std::fs::read_to_string(format!("{dir}/{name}.count")).unwrap();
        (meta.trim().parse::<usize>().unwrap(), Vec::new())
    } else {
        let end = wire.iter().rposition(|&b| b != 0).map_or(0, |i| i + 1);
        (0, wire[..end].split(|&b| b == 0).map(|p| p.to_vec()).collect())
    };
    let (ns, count) = match lib.as_str() {
        "fastwebsockets" => {
            eprintln!("fastwebsockets 0.10.0 (simd), FragmentCollector, no-op-waker poll, in-memory stream");
            fastwebsockets_side(wire, name, msgs, payloads)
        }
        "tungstenite" => {
            eprintln!("tungstenite 0.30.0 (no handshake feature), sync, in-memory stream");
            tungstenite_side(wire, name, msgs, payloads)
        }
        _ => {
            eprintln!("unknown library {lib}");
            std::process::exit(2);
        }
    };
    println!("{name}\t{ns:.1}\t{count}");
}
