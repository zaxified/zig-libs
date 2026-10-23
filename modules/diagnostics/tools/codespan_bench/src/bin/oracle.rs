// SPDX-License-Identifier: MIT

// Oracle side of `zig build interop-diagnostics` (modules/diagnostics/tools/interop.zig):
// renders the random cases the Zig program wrote with codespan-reporting 0.13.1
// ("rich" style, no colour, default `Config` apart from the fields a case sets)
// through its public API, so the Zig side can compare byte for byte.
//
//   oracle <cases file> <output file>
//
// Input, one record per line, every string hex-encoded (so any byte survives):
//   case <id>
//   cfg <start_context_lines> <end_context_lines> <before_label_lines> <after_label_lines>
//   file <name hex> <text hex>
//   diag <severity: e|w|n> <code hex or -> <message hex>
//   label <p|s> <file index> <start> <end> <message hex>
//   note <message hex>
//   end
// A `label`/`note` belongs to the latest `diag`.
//
// Output: per case, per charset (ascii first, then box drawing), a line
// `<id> <charset> ok <length>` followed by that many bytes and a newline, or
// `<id> <charset> panic 0` and a newline when codespan panicked (a label off a
// char boundary, say) -- the Zig side reports those as its own category. A
// `note` diagnostic's header word is rewritten to `info` (see `render`).

use codespan_reporting::diagnostic::{Diagnostic, Label};
use codespan_reporting::files::SimpleFiles;
use codespan_reporting::term::{self, Chars, Config};
use std::fs;
use std::io::Write;
use std::panic;

fn unhex(s: &str) -> String {
    if s == "-" {
        return String::new();
    }
    let b: Vec<u8> = (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect();
    String::from_utf8(b).expect("the Zig side writes UTF-8 only")
}

#[derive(Default)]
struct Case {
    id: u64,
    ctx: [usize; 4],
    files: Vec<(String, String)>,
    diags: Vec<Diagnostic<usize>>,
}

fn render(c: &Case, chars: Chars) -> Vec<u8> {
    let mut files = SimpleFiles::new();
    for (n, t) in &c.files {
        files.add(n.clone(), t.clone());
    }
    let cfg = Config {
        chars,
        start_context_lines: c.ctx[0],
        end_context_lines: c.ctx[1],
        before_label_lines: c.ctx[2],
        after_label_lines: c.ctx[3],
        ..Config::default()
    };
    let mut out = Vec::new();
    for d in &c.diags {
        let mut one = Vec::new();
        term::emit_to_io_write(&mut one, &cfg, &files, d).unwrap();
        // The one normalisation: `diagnostics` has no `note` severity, the Zig
        // side sends `info`, whose header word is the only difference.
        if one.starts_with(b"note") {
            one[..4].copy_from_slice(b"info");
        }
        out.extend_from_slice(&one);
    }
    out
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        eprintln!("usage: oracle <cases file> <output file>");
        std::process::exit(2);
    }
    let text = fs::read_to_string(&args[1]).unwrap();
    let mut out = std::io::BufWriter::new(fs::File::create(&args[2]).unwrap());
    panic::set_hook(Box::new(|_| {}));

    let mut c = Case::default();
    for line in text.lines() {
        let f: Vec<&str> = line.split(' ').collect();
        match f[0] {
            "case" => c = Case { id: f[1].parse().unwrap(), ..Case::default() },
            "cfg" => {
                for i in 0..4 {
                    c.ctx[i] = f[i + 1].parse().unwrap();
                }
            }
            "file" => c.files.push((unhex(f[1]), unhex(f[2]))),
            "diag" => {
                let d = match f[1] {
                    "e" => Diagnostic::error(),
                    "w" => Diagnostic::warning(),
                    _ => Diagnostic::note(),
                };
                let d = if f[2] == "-" { d } else { d.with_code(unhex(f[2])) };
                c.diags.push(d.with_message(unhex(f[3])));
            }
            "label" => {
                let (fi, s, e): (usize, usize, usize) =
                    (f[2].parse().unwrap(), f[3].parse().unwrap(), f[4].parse().unwrap());
                let l = if f[1] == "p" { Label::primary(fi, s..e) } else { Label::secondary(fi, s..e) };
                let d = c.diags.pop().unwrap();
                c.diags.push(d.with_labels(vec![l.with_message(unhex(f[5]))]));
            }
            "note" => {
                let d = c.diags.pop().unwrap();
                c.diags.push(d.with_notes(vec![unhex(f[1])]));
            }
            "end" => {
                for (name, chars) in [("ascii", Chars::ascii()), ("unicode", Chars::box_drawing())] {
                    match panic::catch_unwind(panic::AssertUnwindSafe(|| render(&c, chars))) {
                        Ok(b) => {
                            writeln!(out, "{} {} ok {}", c.id, name, b.len()).unwrap();
                            out.write_all(&b).unwrap();
                            out.write_all(b"\n").unwrap();
                        }
                        Err(_) => writeln!(out, "{} {} panic 0\n", c.id, name).unwrap(),
                    }
                }
            }
            other => panic!("unknown record {other}"),
        }
    }
}
