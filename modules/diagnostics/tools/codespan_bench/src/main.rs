// SPDX-License-Identifier: MIT

// Reference side of `zig build bench-diagnostics`
// (modules/diagnostics/tools/bench.zig): times codespan-reporting 0.13.1
// ("rich" style, `Chars::ascii()`, no colour, `term::emit_to_io_write` into a
// reused `Vec<u8>`) and annotate-snippets 0.12.17 (`Renderer::plain()`, ASCII
// decor, the `String` it returns is only measured) through their public APIs,
// on the corpus and the diagnostics the Zig program wrote to the work
// directory (`big.txt`, `long.txt`, `*.spec`).
//
//   codespan_bench <dir> <workload>   one line, tab separated: name, ns per op, count
//   codespan_bench <dir> check        writes sample_cs_<w>.txt (the first 20
//                                     diagnostics of many_single and many_multi,
//                                     rendered by codespan) and prints
//                                     `count \t <w> \t <codespan> \t <annotate>` per workload
//
// Workloads are `cs_<w>` and `as_<w>`; `<w>` is many_single, many_multi,
// multiline, long_line, long_line_tw (annotate with term_width 120; codespan
// has no such option). One op renders every diagnostic of the workload. The
// count is the number of diagnostics plus the number of '^' in the output.
//
// A `.spec` line is one diagnostic: byte ranges `start end start end ...`, the
// first is the primary span, the others are secondary labels.
//
// Timing matches the Zig side: double the batch until one batch takes over
// 100 ms, then keep the best of five. Everything but the rendering (parsing,
// line starts, building the Diagnostic / Group values) happens before the clock
// starts; annotate gets the source lines the spans are on, not the whole file.

use annotate_snippets::{AnnotationKind, Group, Level, Renderer, Snippet};
use codespan_reporting::diagnostic::{Diagnostic, Label};
use codespan_reporting::files::SimpleFile;
use codespan_reporting::term::{self, Chars, Config};
use std::fs;
use std::hint::black_box;
use std::time::{Duration, Instant};

const FILE_NAME: &str = "f.txt";
const HEADER: &str = "bad value";
const PRIMARY_MSG: &str = "unexpected token";
const SECONDARY_MSG: &str = "related here";
const UNLIMITED: usize = 1 << 20;
const TW: usize = 120;

type Spans = Vec<(usize, usize)>;

fn read_spec(path: &str) -> Vec<Spans> {
    let text = fs::read_to_string(path).unwrap_or_else(|e| panic!("{path}: {e}"));
    text.lines()
        .map(|l| {
            let n: Vec<usize> = l.split_whitespace().map(|t| t.parse().unwrap()).collect();
            n.chunks(2).map(|c| (c[0], c[1])).collect()
        })
        .collect()
}

fn line_starts(src: &str) -> Vec<usize> {
    let mut v = vec![0];
    for (i, b) in src.bytes().enumerate() {
        if b == b'\n' {
            v.push(i + 1);
        }
    }
    v
}

fn line_of(starts: &[usize], off: usize) -> usize {
    starts.partition_point(|&s| s <= off) - 1
}

fn carets(s: &[u8]) -> usize {
    s.iter().filter(|&&b| b == b'^').count()
}

fn time_it<F: FnMut() -> usize>(mut f: F) -> f64 {
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
    let mut best = f64::INFINITY;
    for _ in 0..5 {
        let t = Instant::now();
        for _ in 0..n {
            black_box(f());
        }
        best = best.min(t.elapsed().as_nanos() as f64);
    }
    best / n as f64
}

struct Work {
    src: String,
    spans: Vec<Spans>,
}

fn load(dir: &str, w: &str) -> Work {
    let (srcf, specf) = match w {
        "many_single" => ("big.txt", "single.spec"),
        "many_multi" => ("big.txt", "multi.spec"),
        "multiline" => ("big.txt", "multiline.spec"),
        "long_line" | "long_line_tw" => ("long.txt", "long.spec"),
        _ => panic!("unknown workload {w}"),
    };
    Work {
        src: fs::read_to_string(format!("{dir}/{srcf}")).unwrap(),
        spans: read_spec(&format!("{dir}/{specf}")),
    }
}

fn cs_diags(spans: &[Spans]) -> Vec<Diagnostic<()>> {
    spans
        .iter()
        .map(|d| {
            let labels = d
                .iter()
                .enumerate()
                .map(|(i, &(s, e))| {
                    if i == 0 {
                        Label::primary((), s..e).with_message(PRIMARY_MSG)
                    } else {
                        Label::secondary((), s..e).with_message(SECONDARY_MSG)
                    }
                })
                .collect();
            Diagnostic::error().with_message(HEADER).with_labels(labels)
        })
        .collect()
}

fn cs_render(
    out: &mut Vec<u8>,
    cfg: &Config,
    file: &SimpleFile<&str, &str>,
    diags: &[Diagnostic<()>],
) {
    out.clear();
    for d in diags {
        term::emit_to_io_write(out, cfg, file, d).unwrap();
    }
}

/// One `Group` per diagnostic. The snippet is the text of the lines the spans
/// are on (a caller of annotate-snippets slices its source like this), spans
/// relative to it.
fn as_groups<'a>(src: &'a str, starts: &[usize], spans: &[Spans]) -> Vec<Group<'a>> {
    spans
        .iter()
        .map(|d| {
            let lo = d.iter().map(|s| s.0).min().unwrap();
            let hi = d.iter().map(|s| s.1).max().unwrap();
            let l0 = line_of(starts, lo);
            let l1 = line_of(starts, hi.saturating_sub(1).max(lo));
            let a = starts[l0];
            let b = if l1 + 1 < starts.len() { starts[l1 + 1] - 1 } else { src.len() };
            let mut sn = Snippet::source(&src[a..b]).line_start(l0 + 1).path(FILE_NAME).fold(true);
            for (i, &(s, e)) in d.iter().enumerate() {
                let kind = if i == 0 { AnnotationKind::Primary } else { AnnotationKind::Context };
                let msg = if i == 0 { PRIMARY_MSG } else { SECONDARY_MSG };
                sn = sn.annotation(kind.span(s - a..e - a).label(msg));
            }
            Level::ERROR.primary_title(HEADER).element(sn)
        })
        .collect()
}

fn as_render(r: &Renderer, groups: &[Group<'_>], mut sink: impl FnMut(&str)) {
    for g in groups {
        sink(&r.render(std::slice::from_ref(g)));
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        eprintln!("usage: codespan_bench <dir> <workload|check>");
        std::process::exit(2);
    }
    let dir = &args[1];
    let cfg = Config { chars: Chars::ascii(), ..Config::default() };
    let tw_for = |w: &str| if w == "long_line_tw" { TW } else { UNLIMITED };

    if args[2] == "check" {
        for w in ["many_single", "many_multi", "multiline", "long_line", "long_line_tw"] {
            let wk = load(dir, w);
            let starts = line_starts(&wk.src);
            let file = SimpleFile::new(FILE_NAME, wk.src.as_str());
            let diags = cs_diags(&wk.spans);
            let mut out = Vec::new();
            cs_render(&mut out, &cfg, &file, &diags);
            let cs = diags.len() + carets(&out);
            if w == "many_single" || w == "many_multi" {
                cs_render(&mut out, &cfg, &file, &diags[..20]);
                fs::write(format!("{dir}/sample_cs_{w}.txt"), &out).unwrap();
            }
            let groups = as_groups(&wk.src, &starts, &wk.spans);
            let r = Renderer::plain().term_width(tw_for(w));
            let mut n = groups.len();
            as_render(&r, &groups, |s| n += carets(s.as_bytes()));
            println!("count\t{w}\t{cs}\t{n}");
        }
        return;
    }

    let (side, w) = args[2].split_once('_').unwrap();
    let wk = load(dir, w);
    let starts = line_starts(&wk.src);
    let (ns, count) = match side {
        "cs" => {
            let file = SimpleFile::new(FILE_NAME, wk.src.as_str());
            let diags = cs_diags(&wk.spans);
            let mut out = Vec::new();
            cs_render(&mut out, &cfg, &file, &diags);
            let count = diags.len() + carets(&out);
            let ns = time_it(|| {
                cs_render(&mut out, &cfg, &file, &diags);
                black_box(&out).len()
            });
            (ns, count)
        }
        "as" => {
            let groups = as_groups(&wk.src, &starts, &wk.spans);
            let r = Renderer::plain().term_width(tw_for(w));
            let mut count = groups.len();
            as_render(&r, &groups, |s| count += carets(s.as_bytes()));
            let ns = time_it(|| {
                let mut total = 0;
                as_render(&r, &groups, |s| total += black_box(s).len());
                total
            });
            (ns, count)
        }
        _ => panic!("unknown side {side}"),
    };
    println!("{}\t{:.1}\t{}", args[2], ns, count);
    eprintln!(
        "codespan-reporting 0.13.1 (rich, Chars::ascii, emit_to_io_write) / annotate-snippets 0.12.17 (Renderer::plain, ascii)"
    );
}
