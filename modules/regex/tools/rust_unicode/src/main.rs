// SPDX-License-Identifier: MIT

// Generates `src/unicode16_tables.zig` and `src/casefold16.zig`: the Unicode
// classes and the simple case folding that Rust's `regex` 1.13.1 answers by
// (crate `regex-syntax` 0.8.11, Unicode 16.0.0), taken as a black box through
// its public API: every class is what `\p{<query>}` (or `\w \s \d`, or
// `(?i)[\x{C}]` for the fold orbit of a code point) parses to. The crate's
// private tables are never read as Rust; only the *names* it knows (the
// alias lists in `src/unicode_tables/property_names.rs` and
// `property_values.rs`, plain data) are scanned at run time, from the crate
// directory given on the command line, to know what to ask. The data are
// Unicode's; the encoding and this code are ours.
//
//   cd modules/regex/tools/rust_unicode
//   cargo build --release --offline
//   target/release/rust_unicode --crate ~/.cargo/registry/src/*/regex-syntax-0.8.11 -out ../../src
//   target/release/rust_unicode --crate ~/.cargo/registry/src/*/regex-syntax-0.8.11 -check ../../src
//
// Needs `zig` on PATH (the output goes through `zig fmt --stdin`) and, for the
// `go` flags, `<dir>/unicode_tables.zig` (the Go-generated file).
use regex_syntax::hir::{Class, Hir, HirKind};
use regex_syntax::{Parser, ParserBuilder};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::Write;
use std::process::{Command, Stdio};

type Rs = Vec<(u32, u32)>;
const MAX_CP: u32 = 0x10FFFF;

fn die(m: impl AsRef<str>) -> ! {
    eprintln!("rust_unicode: {}", m.as_ref());
    std::process::exit(2)
}

// ---- black-box access --------------------------------------------------

fn hir_ranges(h: &Hir) -> Result<Rs, String> {
    match h.kind() {
        HirKind::Class(Class::Unicode(c)) => {
            Ok(c.iter().map(|r| (r.start() as u32, r.end() as u32)).collect())
        }
        // An empty class is `Hir::fail()`, a byte class with no range.
        HirKind::Class(Class::Bytes(c)) if c.iter().next().is_none() => Ok(vec![]),
        // A one-code-point class is simplified to a literal.
        HirKind::Literal(l) => {
            let s = std::str::from_utf8(&l.0).map_err(|e| e.to_string())?;
            let mut it = s.chars();
            match (it.next(), it.next()) {
                (Some(c), None) => Ok(vec![(c as u32, c as u32)]),
                _ => Err("literal of several characters".into()),
            }
        }
        k => Err(format!("unexpected {:?}", k)),
    }
}

fn query(_unused: &mut Parser, pat: &str) -> Option<Rs> {
    // A `Parser` is single-use (it asserts on a second parse): build one per query.
    let rs = hir_ranges(&ParserBuilder::new().build().parse(pat).ok()?).ok()?;
    for w in rs.windows(2) {
        assert!(w[0].1 + 1 < w[1].0, "{pat}: ranges not canonical");
    }
    Some(rs)
}

/// regex-syntax's symbolic-name normalisation (UAX44-LM3 plus the `is`
/// prefix), re-implemented from its documented behaviour so that we can pick
/// an input that normalises to a wanted key.
fn normalize(x: &str) -> String {
    let b = x.as_bytes();
    let is = b.len() >= 2 && b[0].eq_ignore_ascii_case(&b'i') && b[1].eq_ignore_ascii_case(&b's');
    let mut out: Vec<u8> = Vec::new();
    for &c in &b[if is { 2 } else { 0 }..] {
        match c {
            b' ' | b'_' | b'-' => {}
            b'A'..=b'Z' => out.push(c + 32),
            c if c <= 0x7f => out.push(c),
            _ => {}
        }
    }
    if is && out.len() == 1 && out[0] == b'c' {
        out = b"isc".to_vec();
    }
    String::from_utf8(out).unwrap()
}

/// An input that the crate normalises to exactly `key`.
fn input_for(key: &str) -> Option<String> {
    [key.to_string(), format!("is{key}")].into_iter().find(|i| normalize(i) == key)
}

// ---- scanning the alias lists -----------------------------------------

fn pairs_in(line: &str) -> Option<(String, String)> {
    let l = line.trim();
    let l = l.strip_prefix("(\"")?.strip_suffix("\"),")?;
    let (a, b) = l.split_once("\", \"")?;
    Some((a.to_string(), b.to_string()))
}

struct Aliases {
    names: Vec<(String, String)>,                       // normalized alias -> canonical property
    values: BTreeMap<String, Vec<(String, String)>>,    // canonical property -> (alias, canonical value)
}

fn scan(crate_dir: &str) -> Aliases {
    let cargo = std::fs::read_to_string(format!("{crate_dir}/Cargo.toml")).unwrap_or_else(|e| die(e.to_string()));
    if !cargo.contains("version = \"0.8.11\"") {
        die("the crate directory is not regex-syntax 0.8.11");
    }
    let t = |f: &str| {
        std::fs::read_to_string(format!("{crate_dir}/src/unicode_tables/{f}")).unwrap_or_else(|e| die(e.to_string()))
    };
    let names: Vec<_> = t("property_names.rs").lines().filter_map(pairs_in).collect();
    let mut values: BTreeMap<String, Vec<(String, String)>> = BTreeMap::new();
    let mut cur: Option<String> = None;
    for line in t("property_values.rs").lines() {
        let l = line.trim();
        if let Some(p) = l.strip_prefix('"').and_then(|x| x.strip_suffix("\",")) {
            cur = Some(p.to_string());
        } else if let Some(pv) = pairs_in(l) {
            values.entry(cur.clone().unwrap_or_else(|| die("value before property"))).or_default().push(pv);
        }
    }
    if names.len() < 200 || values.len() != 7 {
        die(format!("alias scan found {} names, {} properties", names.len(), values.len()));
    }
    Aliases { names, values }
}

// ---- the table model ---------------------------------------------------

/// The properties `\p{prop=value}` resolves, each with the key prefix the
/// generated `names` use and the input that spells it.
const PROPS: [(&str, &str); 7] = [
    ("General_Category", "gc"),
    ("Script", "sc"),
    ("Script_Extensions", "scx"),
    ("Age", "age"),
    ("Grapheme_Cluster_Break", "gcb"),
    ("Sentence_Break", "sb"),
    ("Word_Break", "wb"),
];

struct Entry {
    rs: Rs,
    go: bool,
    pat: String, // the pattern that produced it, for the re-check
}

struct Model {
    entries: BTreeMap<String, Entry>,
    props: BTreeMap<String, &'static str>, // normalized property alias -> key prefix
    perl: [(&'static str, Rs); 3],
    skipped: usize,
}

/// The names Go's grammar accepts: `go_names.txt` beside Cargo.toml (frozen
/// from Go 1.26's `unicode` when the Go-generated tables were retired).
fn go_names(_dir: &str) -> HashSet<String> {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/go_names.txt");
    let s = std::fs::read_to_string(path).unwrap_or_else(|e| die(format!("{path}: {e}")));
    let mut out = HashSet::new();
    for l in s.lines() {
        let l = l.trim();
        if !l.is_empty() && !l.starts_with('#') {
            out.insert(l.to_string());
        }
    }
    if out.len() < 150 {
        die("too few Go names read");
    }
    out
}

fn build_model(a: &Aliases, go: &HashSet<String>) -> Model {
    let mut p = ParserBuilder::new().build();
    let mut entries = BTreeMap::new();
    let mut skipped = 0;

    // Bare names: a binary property, or (UTS#18) a general category value or a
    // script value; the crate decides, we only ask.
    let mut cands: Vec<String> = a.names.iter().map(|(n, _)| n.clone()).collect();
    for prop in ["General_Category", "Script"] {
        cands.extend(a.values[prop].iter().map(|(n, _)| n.clone()));
    }
    cands.extend(["any", "ascii", "assigned"].map(String::from));
    cands.sort();
    cands.dedup();
    for k in &cands {
        let Some(inp) = input_for(k) else { skipped += 1; continue };
        let pat = format!("\\p{{{inp}}}");
        match query(&mut p, &pat) {
            Some(rs) => {
                let g = go.contains(k) || matches!(k.as_str(), "any" | "ascii" | "assigned");
                entries.insert(k.clone(), Entry { rs, go: g, pat });
            }
            None => skipped += 1,
        }
    }

    // prop=value for the seven properties the crate resolves by value.
    for (canon, id) in PROPS {
        let mut vals: Vec<String> = a.values[canon].iter().map(|(n, _)| n.clone()).collect();
        if canon == "General_Category" {
            vals.extend(["any", "ascii", "assigned"].map(String::from));
        }
        vals.sort();
        vals.dedup();
        for v in &vals {
            let Some(vi) = input_for(v) else { skipped += 1; continue };
            let pat = format!("\\p{{{id}={vi}}}");
            match query(&mut p, &pat) {
                Some(rs) => {
                    entries.insert(format!("{id}={v}"), Entry { rs, go: false, pat });
                }
                None => skipped += 1,
            }
        }
    }

    // Every spelling of those seven properties, probed against the id's own.
    let mut props = BTreeMap::new();
    for (alias, canon) in &a.names {
        let Some((_, id)) = PROPS.iter().find(|(c, _)| c == canon) else { continue };
        let probe = a.values[canon.as_str()].first().unwrap().0.clone();
        let (Some(ai), Some(vi)) = (input_for(alias), input_for(&probe)) else { die(format!("cannot spell {alias}")) };
        let got = query(&mut p, &format!("\\p{{{ai}={vi}}}")).unwrap_or_else(|| die(format!("{alias}={probe} does not resolve")));
        let want = &entries.get(&format!("{id}={probe}")).unwrap_or_else(|| die("probe missing")).rs;
        if &got != want {
            die(format!("property alias {alias} disagrees with {id}"));
        }
        props.insert(alias.clone(), *id);
    }
    // Spellings that must NOT resolve by value (every other property).
    for (alias, canon) in &a.names {
        if PROPS.iter().any(|(c, _)| c == canon) {
            continue;
        }
        if let Some(ai) = input_for(alias) {
            if query(&mut p, &format!("\\p{{{ai}=yes}}")).is_some() || query(&mut p, &format!("\\p{{{ai}=y}}")).is_some() {
                die(format!("{alias}=yes unexpectedly resolves: the key scheme would miss it"));
            }
        }
    }

    let perl = [("perl_word", "\\w"), ("perl_space", "\\s"), ("perl_digit", "\\d")]
        .map(|(n, pat)| (n, query(&mut p, pat).unwrap_or_else(|| die(format!("{pat} does not parse")))));
    Model { entries, props, perl, skipped }
}

// ---- encoding ----------------------------------------------------------

fn varint(b: &mut Vec<u8>, mut v: u32) {
    while v >= 0x80 {
        b.push((v as u8) | 0x80);
        v >>= 7;
    }
    b.push(v as u8);
}

fn decode(data: &[u8], off: usize, size: usize, count: usize) -> Rs {
    let mut out = vec![];
    let (mut i, end, mut prev) = (off, off + size, 0u32);
    let rd = |i: &mut usize| {
        let (mut v, mut sh) = (0u32, 0);
        loop {
            let b = data[*i];
            *i += 1;
            v |= ((b & 0x7f) as u32) << sh;
            if b < 0x80 {
                return v;
            }
            sh += 7;
        }
    };
    while i < end {
        let lo = prev + rd(&mut i);
        let hi = lo + rd(&mut i);
        out.push((lo, hi));
        prev = hi + 1;
    }
    assert_eq!(i, end);
    assert_eq!(out.len(), count);
    out
}

fn zig_fmt(src: &str) -> String {
    let mut child = Command::new("zig")
        .args(["fmt", "--stdin"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| die(format!("zig fmt: {e}")));
    let mut stdin = child.stdin.take().unwrap();
    let s = src.to_string();
    let w = std::thread::spawn(move || stdin.write_all(s.as_bytes()));
    let out = child.wait_with_output().unwrap();
    w.join().unwrap().ok();
    if !out.status.success() {
        die("zig fmt --stdin failed");
    }
    String::from_utf8(out.stdout).unwrap()
}

struct Base {
    offset: usize,
    size: usize,
    count: usize,
    first: String,
}

fn gen_tables(m: &Model) -> (String, String) {
    let mut data = Vec::new();
    let mut bases: Vec<Base> = vec![];
    let mut index: HashMap<&Rs, usize> = HashMap::new();
    let place = |rs: &Rs, label: &str, data: &mut Vec<u8>, bases: &mut Vec<Base>| -> usize {
        let offset = data.len();
        let mut prev = 0;
        for &(lo, hi) in rs {
            varint(data, lo - prev);
            varint(data, hi - lo);
            prev = hi + 1;
        }
        bases.push(Base { offset, size: data.len() - offset, count: rs.len(), first: label.to_string() });
        bases.len() - 1
    };
    let mut name_base: Vec<(&String, usize)> = vec![];
    for (k, e) in &m.entries {
        let i = match index.get(&e.rs) {
            Some(&i) => i,
            None => {
                let i = place(&e.rs, k, &mut data, &mut bases);
                index.insert(&e.rs, i);
                i
            }
        };
        name_base.push((k, i));
    }
    let mut perl_idx = vec![];
    for (n, rs) in &m.perl {
        let i = match index.get(rs) {
            Some(&i) => i,
            None => {
                let i = place(rs, n, &mut data, &mut bases);
                index.insert(rs, i);
                i
            }
        };
        perl_idx.push((*n, i));
    }
    assert!(bases.len() <= u16::MAX as usize);
    assert!(bases.iter().all(|b| b.size <= u16::MAX as usize && b.count <= u16::MAX as usize));

    // Self-check 1: every name, decoded from the written encoding, equals the
    // class the crate gives when asked again; every perl class too.
    let mut p = ParserBuilder::new().build();
    for ((k, i), e) in name_base.iter().zip(m.entries.values()) {
        let b = &bases[*i];
        let got = decode(&data, b.offset, b.size, b.count);
        let fresh = query(&mut p, &e.pat).unwrap_or_else(|| die(format!("{k}: no longer resolves")));
        if got != fresh {
            die(format!("{k}: decoded table disagrees with the crate"));
        }
    }
    for ((n, i), pat) in perl_idx.iter().zip(["\\w", "\\s", "\\d"]) {
        let b = &bases[*i];
        if decode(&data, b.offset, b.size, b.count) != query(&mut p, pat).unwrap() {
            die(format!("{n}: decoded table disagrees with the crate"));
        }
    }
    // Self-check 2: per code point, membership of the decoded table (a bitmap
    // walked from the bytes) against the crate's class for every base.
    let mut seen = HashSet::new();
    for ((_, i), e) in name_base.iter().zip(m.entries.values()) {
        if !seen.insert(*i) {
            continue;
        }
        let b = &bases[*i];
        let mut mem = vec![false; MAX_CP as usize + 1];
        for (lo, hi) in decode(&data, b.offset, b.size, b.count) {
            for c in lo..=hi {
                mem[c as usize] = true;
            }
        }
        let fresh = query(&mut p, &e.pat).unwrap();
        let mut j = 0;
        for c in 0..=MAX_CP {
            while j < fresh.len() && fresh[j].1 < c {
                j += 1;
            }
            let want = j < fresh.len() && fresh[j].0 <= c;
            if mem[c as usize] != want {
                die(format!("{}: U+{c:04X} membership differs", e.pat));
            }
        }
    }

    let max_ranges = bases.iter().map(|b| b.count).max().unwrap();
    let mut s = String::new();
    s.push_str("// SPDX-License-Identifier: MIT\n");
    s.push_str("// GENERATED by modules/regex/tools/rust_unicode (regex-syntax 0.8.11, Unicode 16.0.0) -- do not hand-edit.\n");
    s.push_str(HEADER);
    s.push_str(&format!("pub const unicode_version = \"16.0.0\";\n/// The most ranges any one table has.\npub const max_ranges = {max_ranges};\n\n"));
    s.push_str("pub const data: []const u8 =\n");
    for (n, ch) in data.chunks(24).enumerate() {
        let last = (n + 1) * 24 >= data.len();
        let hex: String = ch.iter().map(|c| format!("\\x{c:02x}")).collect();
        s.push_str(&format!("    \"{hex}\"{}\n", if last { ";" } else { " ++" }));
    }
    s.push_str("\npub const bases = [_]Base{\n");
    for b in &bases {
        s.push_str(&format!(".{{ .offset = {}, .size = {}, .count = {} }}, // {}\n", b.offset, b.size, b.count, b.first));
    }
    s.push_str("};\n\n/// The bases of the Perl classes `\\w`, `\\s`, `\\d`.\n");
    for (n, i) in &perl_idx {
        s.push_str(&format!("pub const {n}: u16 = {i};\n"));
    }
    s.push_str("\n/// Property spellings that `\\p{prop=value}` resolves, sorted by normalized spelling.\npub const props = [_]Prop{\n");
    for (a, id) in &m.props {
        s.push_str(&format!(".{{ .name = \"{a}\", .id = \"{id}\" }},\n"));
    }
    s.push_str("};\n\n/// Sorted by key (byte order).\npub const names = [_]Name{\n");
    for ((k, i), e) in name_base.iter().zip(m.entries.values()) {
        s.push_str(&format!(".{{ .name = \"{k}\", .base = {i}, .go = {} }},\n", e.go));
    }
    s.push_str("};\n");

    let by_value = m.entries.keys().filter(|k| k.contains('=')).count();
    eprintln!(
        "unicode: {} bases, {} names ({} bare, {} by value), {} property spellings, {} bytes of ranges, at most {} ranges per table, {} queries unresolvable",
        bases.len(), m.entries.len(), m.entries.len() - by_value, by_value, m.props.len(), data.len(), max_ranges, m.skipped
    );
    (zig_fmt(&s), String::new())
}

const HEADER: &str = r#"//! The Unicode classes `\p{…}` and `\w \s \d` name in Rust's `regex` 1.13.1 (crate
//! `regex-syntax` 0.8.11, Unicode 16.0): general categories, scripts, script
//! extensions, binary properties, Age, Grapheme_Cluster_Break, Word_Break,
//! Sentence_Break, `Any`/`ASCII`/`Assigned` -- each taken as the crate's class
//! for the query, and checked here against it for every code point. Regenerate
//! with the command in tools/rust_unicode/src/main.rs.
//!
//! Key scheme. The parser normalizes each name as the crate does (drop an
//! `is`/`Is`/`IS`/`iS` prefix, then ASCII-lower-case, then drop ` `, `_`, `-`
//! and every non-ASCII byte; a lone `c` after an `is` prefix stays `isc`).
//!  - `\pL`, `\p{L}`, `\p{Greek}`, `\p{Alphabetic}`: one normalized name, looked
//!    up bare in `names` (a binary property, a general category value or a
//!    script value: the crate's own order, already applied here -- `sc`, `cf`,
//!    `lc` are the categories). `\pL` is the bare name "l".
//!  - `\p{prop=value}`, `\p{prop:value}`: normalize both, find the property in
//!    `props` (spellings of gc, sc, scx, age, gcb, sb, wb only; any other
//!    property, or none, is an error, as in the crate), then look up the key
//!    `<id>=<normalized value>` in `names`, e.g. `gc=lu`, `sc=greek`,
//!    `scx=grek`, `age=1.1`, `gcb=extend`. `!=` and `\P` are negation, done by
//!    the parser, not table entries.
//! Several keys share a base when their classes are equal.
//! `go` marks the bare names Go 1.26's `regexp` also accepts (general
//! categories and their aliases, the scripts Go lists, `any`, `ascii`,
//! `assigned`): the Go-syntax parser refuses the rest.

/// A stored table: `count` ranges in `data[offset..][0..size]`, each two
/// LEB128 varints -- the gap from the end of the previous range (from 0 for
/// the first), then the range's length minus one.
pub const Base = struct { offset: u32, size: u16, count: u16 };
/// A class key (see the header) and the one stored table that is its class.
pub const Name = struct { name: []const u8, base: u16, go: bool };
/// A spelling of a property that `\p{prop=value}` accepts, and the key prefix.
pub const Prop = struct { name: []const u8, id: []const u8 };

"#;

// ---- case folding ------------------------------------------------------

#[derive(Clone, Copy, PartialEq)]
struct Run {
    lo: i64,
    hi: i64,
    delta: i64,
    alt: bool,
}

impl Run {
    fn next(&self, c: i64) -> i64 {
        if self.alt {
            if (c - self.lo) % 2 == 0 { c + 1 } else { c - 1 }
        } else {
            c + self.delta
        }
    }
}

fn gen_casefold() -> String {
    let mut p = ParserBuilder::new().build();
    let n = MAX_CP as usize + 1;
    let mut fold: Vec<i64> = (0..n as i64).collect();
    let mut orbits: HashMap<u32, Vec<u32>> = HashMap::new();
    let mut max_orbit = 1;
    for c in 0..=MAX_CP {
        if (0xD800..0xE000).contains(&c) {
            continue;
        }
        let rs = query(&mut p, &format!("(?i)[\\x{{{c:X}}}]")).unwrap_or_else(|| die(format!("U+{c:04X}: fold query failed")));
        let mut o: Vec<u32> = vec![];
        for (lo, hi) in rs {
            o.extend(lo..=hi);
        }
        if !o.contains(&c) {
            die(format!("U+{c:04X} not in its own orbit"));
        }
        if o.len() > 1 {
            // Successor: the next larger member, wrapping to the smallest.
            fold[c as usize] = *o.iter().find(|&&x| x > c).unwrap_or(&o[0]) as i64;
            max_orbit = max_orbit.max(o.len());
            orbits.insert(c, o);
        }
    }
    // The orbit relation must be an equivalence (each member sees the same set).
    for (c, o) in &orbits {
        for x in o {
            if orbits.get(x) != Some(o) {
                die(format!("orbit of U+{c:04X} is not closed at U+{x:04X}"));
            }
        }
    }
    let f = |c: i64| fold[c as usize];
    let two_orbit = |c: i64| f(f(c)) == c;

    let mut runs: Vec<Run> = vec![];
    for c in 0..=MAX_CP as i64 {
        let fc = f(c);
        if fc == c {
            continue;
        }
        let d = fc - c;
        if let Some(l) = runs.last_mut() {
            if l.hi + 1 == c {
                if !l.alt && l.delta == d && !(l.lo == l.hi && d == -1) {
                    l.hi = c;
                    continue;
                }
                let off = c - l.lo;
                let pair_start = (l.alt || (l.lo == l.hi && l.delta == 1 && two_orbit(l.lo))) && off % 2 == 1;
                if pair_start && d == -1 && two_orbit(c) {
                    l.alt = true;
                    l.delta = 0;
                    l.hi = c;
                    continue;
                }
                if l.alt && off % 2 == 0 && d == 1 && two_orbit(c) && c + 1 <= MAX_CP as i64 && f(c + 1) == c {
                    l.hi = c;
                    continue;
                }
            }
        }
        runs.push(Run { lo: c, hi: c, delta: d, alt: false });
    }
    for r in &runs {
        if r.alt && (r.hi - r.lo) % 2 == 0 {
            die(format!("odd alternating run {:x}-{:x}", r.lo, r.hi));
        }
    }
    // Self-check: the runs give the crate's successor for every code point.
    let mut i = 0;
    for c in 0..=MAX_CP as i64 {
        while i < runs.len() && runs[i].hi < c {
            i += 1;
        }
        let got = if i < runs.len() && runs[i].lo <= c { runs[i].next(c) } else { c };
        if got != f(c) {
            die(format!("U+{c:04X}: runs give U+{got:04X}, the crate U+{:04X}", f(c)));
        }
    }

    let mut s = String::new();
    s.push_str("// SPDX-License-Identifier: MIT\n");
    s.push_str("// GENERATED by modules/regex/tools/rust_unicode (regex-syntax 0.8.11, Unicode 16.0.0) -- do not hand-edit.\n");
    s.push_str(r#"//! Simple case-folding orbits: the code points `(?i)` treats as one letter in
//! Rust's `regex` 1.13.1 (crate `regex-syntax` 0.8.11: the orbit the crate gives
//! `(?i)[\x{C}]`, from Unicode CaseFolding.txt, C + S entries). `next` is the
//! orbit successor (the next larger member, the smallest after the largest);
//! following it from any code point comes back to it within `max_orbit` steps.
//! Regenerate with the command in tools/rust_unicode/src/main.rs.

/// A run of consecutive code points: the successor of `cp` is `cp + delta`, or
/// for an alternating run (`alt`, upper/lower pairs side by side) `cp + 1` at an
/// even offset from `lo` and `cp - 1` at an odd one; each such pair is a whole orbit.
pub const Run = struct { lo: u21, hi: u21, delta: i32 = 0, alt: bool = false };

"#);
    s.push_str("pub const unicode_version = \"16.0.0\";\n");
    s.push_str(&format!("pub const max_orbit = {max_orbit};\n"));
    s.push_str(&format!(
        "/// The lowest and highest code point with a fold.\npub const min_fold: u21 = 0x{:X};\npub const max_fold: u21 = 0x{:X};\n\n",
        runs[0].lo, runs.last().unwrap().hi
    ));
    s.push_str("pub const runs = [_]Run{\n");
    for r in &runs {
        if r.alt {
            s.push_str(&format!(".{{ .lo = 0x{:X}, .hi = 0x{:X}, .alt = true }},\n", r.lo, r.hi));
        } else {
            s.push_str(&format!(".{{ .lo = 0x{:X}, .hi = 0x{:X}, .delta = {} }},\n", r.lo, r.hi, r.delta));
        }
    }
    s.push_str("};\n");
    eprintln!("casefold: {} runs, max orbit {}, {} folding code points", runs.len(), max_orbit, orbits.len());
    zig_fmt(&s)
}

// ---- main --------------------------------------------------------------

fn drop_generated(s: &str) -> String {
    s.lines().filter(|l| !l.starts_with("// GENERATED ")).collect::<Vec<_>>().join("\n")
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (mut crate_dir, mut out, mut check) = (None, None, None);
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let v = it.next().unwrap_or_else(|| die(format!("{a} needs a value")));
        match a.as_str() {
            "--crate" => crate_dir = Some(v.clone()),
            "-out" => out = Some(v.clone()),
            "-check" => check = Some(v.clone()),
            _ => die(format!("unknown flag {a}")),
        }
    }
    let crate_dir = crate_dir.unwrap_or_else(|| die("usage: rust_unicode --crate <regex-syntax-0.8.11 dir> (-out <dir> | -check <dir>)"));
    let dir = out.clone().or(check.clone()).unwrap_or_else(|| die("one of -out, -check is required"));
    let aliases = scan(&crate_dir);
    let model = build_model(&aliases, &go_names(&dir));
    let (tables, _) = gen_tables(&model);
    let fold = gen_casefold();
    for (file, text) in [("unicode16_tables.zig", &tables), ("casefold16.zig", &fold)] {
        let path = format!("{dir}/{file}");
        if check.is_some() {
            let old = std::fs::read_to_string(&path).unwrap_or_else(|e| die(format!("{path}: {e}")));
            if drop_generated(&old) != drop_generated(text) {
                eprintln!("{file}: DRIFT -- committed file differs from a fresh re-take");
                std::process::exit(1);
            }
            eprintln!("{file}: committed file matches a fresh re-take");
        } else {
            std::fs::write(&path, text).unwrap_or_else(|e| die(format!("{path}: {e}")));
            eprintln!("wrote {path} ({} bytes)", text.len());
        }
    }
}
