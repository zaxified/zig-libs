// SPDX-License-Identifier: MIT

// Differential oracle for the regex module: Rust's `regex` crate 1.13.1 (MIT /
// Apache-2.0), run as a black box through its public API. The patterns and
// inputs are OURS -- crafted syntax cases and seeded random expressions below;
// the crate only answers them, and the answers are written out as a Zig file
// that `src/rust_oracle_test.zig` replays hermetically. No crate source was
// used as a model for the module's grammar; the property-name samples were
// picked from the crate's own tables' names so that they are accepted names.
//
//   cd modules/regex/tools/rust_regex_oracle
//   cargo build --release --offline
//   target/release/rust_regex_oracle -out   ../../src/rust_vectors.zig
//   target/release/rust_regex_oracle -check ../../src/rust_vectors.zig
//
// std + the `regex` crate only (no other dependency, no build script); needs
// `zig` on PATH (the output goes through `zig fmt --stdin`).

mod lists;

use std::fmt::Write as _;
use std::io::Write as _;
use std::process::{Command, Stdio};

/// The Unicode version of the crate's tables (regex-syntax 0.8.11,
/// `src/unicode_tables/*.rs` header: "Unicode version: 16.0.0").
const UNICODE: &str = "16.0";

const N_RANDOM: usize = 600;
const N_BYTES_RANDOM: usize = 200;
const N_SETS_RANDOM: usize = 20;
const N_INPUTS: usize = 14;

// ---------------------------------------------------------------- PRNG

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % (n as u64)) as usize
    }
    fn pick<'a, T>(&mut self, xs: &'a [T]) -> &'a T {
        let i = self.below(xs.len());
        &xs[i]
    }
}

// ------------------------------------------------------------ the engines

enum Re {
    S(regex::Regex),
    B(regex::bytes::Regex),
}

fn st(h: &[u8]) -> &str {
    std::str::from_utf8(h).expect("str-mode inputs are valid UTF-8")
}

fn flat(n: usize, get: impl Fn(usize) -> Option<(usize, usize)>) -> Vec<i64> {
    let mut v = Vec::new();
    for i in 0..n {
        match get(i) {
            Some((s, e)) => {
                v.push(s as i64);
                v.push(e as i64);
            }
            None => {
                v.push(-1);
                v.push(-1);
            }
        }
    }
    v
}

impl Re {
    fn build(pat: &str, bytes: bool) -> Option<Re> {
        if bytes {
            regex::bytes::RegexBuilder::new(pat).build().ok().map(Re::B)
        } else {
            regex::RegexBuilder::new(pat).build().ok().map(Re::S)
        }
    }
    fn names(&self) -> Vec<String> {
        match self {
            Re::S(r) => r.capture_names().map(|n| n.unwrap_or("").to_string()).collect(),
            Re::B(r) => r.capture_names().map(|n| n.unwrap_or("").to_string()).collect(),
        }
    }
    fn is_match(&self, h: &[u8]) -> bool {
        match self {
            Re::S(r) => r.is_match(st(h)),
            Re::B(r) => r.is_match(h),
        }
    }
    fn caps(&self, h: &[u8]) -> Vec<i64> {
        match self {
            Re::S(r) => {
                let mut l = r.capture_locations();
                if r.captures_read(&mut l, st(h)).is_none() {
                    return Vec::new();
                }
                flat(l.len(), |i| l.get(i))
            }
            Re::B(r) => {
                let mut l = r.capture_locations();
                if r.captures_read(&mut l, h).is_none() {
                    return Vec::new();
                }
                flat(l.len(), |i| l.get(i))
            }
        }
    }
    fn all(&self, h: &[u8]) -> Vec<i64> {
        let mut v = Vec::new();
        match self {
            Re::S(r) => {
                for m in r.find_iter(st(h)) {
                    v.push(m.start() as i64);
                    v.push(m.end() as i64);
                }
            }
            Re::B(r) => {
                for m in r.find_iter(h) {
                    v.push(m.start() as i64);
                    v.push(m.end() as i64);
                }
            }
        }
        v
    }
    fn shortest(&self, h: &[u8]) -> i64 {
        let r = match self {
            Re::S(r) => r.shortest_match(st(h)),
            Re::B(r) => r.shortest_match(h),
        };
        r.map_or(-1, |x| x as i64)
    }
}

/// The pattern anchored at both ends. A pasted `)` would be swallowed by a
/// trailing `#` comment under `(?x)`, so a second form ends the pattern with a
/// newline; if neither compiles the caller records `full_ok = false`.
fn full_of(pat: &str, bytes: bool) -> Option<Re> {
    Re::build(&format!("\\A(?:{})\\z", pat), bytes)
        .or_else(|| Re::build(&format!("\\A(?:{}\n)\\z", pat), bytes))
}

// -------------------------------------------------------------- Zig output

fn zstr(s: &[u8]) -> String {
    let mut b = String::from("\"");
    for &c in s {
        match c {
            b'"' | b'\\' => {
                b.push('\\');
                b.push(c as char);
            }
            0x20..=0x7e => b.push(c as char),
            _ => {
                let _ = write!(b, "\\x{:02x}", c);
            }
        }
    }
    b.push('"');
    b
}

fn ints(xs: &[i64]) -> String {
    let mut b = String::from("&.{");
    for (i, x) in xs.iter().enumerate() {
        if i > 0 {
            b.push(',');
        }
        let _ = write!(b, "{}", x);
    }
    b.push('}');
    b
}

fn strs<S: AsRef<[u8]>>(xs: &[S]) -> String {
    let mut b = String::from("&.{");
    for (i, x) in xs.iter().enumerate() {
        if i > 0 {
            b.push(',');
        }
        b.push_str(&zstr(x.as_ref()));
    }
    b.push('}');
    b
}

#[derive(Clone, Copy, PartialEq)]
enum Kind {
    Crafted,
    Unicode,
    Random,
}

impl Kind {
    fn tag(self) -> &'static str {
        match self {
            Kind::Crafted => "crafted",
            Kind::Unicode => "unicode",
            Kind::Random => "random",
        }
    }
}

#[derive(Default)]
struct Stats {
    crafted: usize,
    unicode: usize,
    random: usize,
    random_ok: usize,
    bytes_crafted: usize,
    bytes_random: usize,
    bytes_ok: usize,
    sets: usize,
    sets_ok: usize,
    cases: usize,
    crafted_ok: usize,
    full_bad: usize,
}

fn emit_pattern(out: &mut String, stats: &mut Stats, pat: &str, kind: Kind, bytes: bool, inputs: &[Vec<u8>]) {
    let kind_f = format!(", .kind = .{}", kind.tag());
    let bytes_f = if bytes { ", .bytes = true" } else { "" };
    let Some(re) = Re::build(pat, bytes) else {
        let _ = writeln!(out, ".{{ .pattern = {}, .ok = false{}{} }},", zstr(pat.as_bytes()), kind_f, bytes_f);
        return;
    };
    if bytes {
        stats.bytes_ok += (kind == Kind::Crafted) as usize;
    } else {
        stats.crafted_ok += (kind != Kind::Random) as usize;
        stats.random_ok += (kind == Kind::Random) as usize;
    }
    let full = full_of(pat, bytes);
    if full.is_none() {
        stats.full_bad += 1;
    }
    let names = re.names();
    let _ = write!(
        out,
        ".{{ .pattern = {}, .ok = true{}{}, .names = {}{}, .cases = &.{{\n",
        zstr(pat.as_bytes()),
        kind_f,
        bytes_f,
        strs(&names),
        if full.is_none() { ", .full_ok = false" } else { "" }
    );
    for h in inputs {
        let f = full.as_ref().map_or(false, |f| f.is_match(h));
        let _ = writeln!(
            out,
            ".{{ .input = {}, .is_match = {}, .full = {}, .caps = {}, .all = {}, .shortest = {} }},",
            zstr(h),
            re.is_match(h),
            f,
            ints(&re.caps(h)),
            ints(&re.all(h)),
            re.shortest(h)
        );
        stats.cases += 1;
    }
    out.push_str("} },\n");
}

fn emit_set(out: &mut String, stats: &mut Stats, pats: &[String], bytes: bool, inputs: &[Vec<u8>]) {
    stats.sets += 1;
    let bytes_f = if bytes { ", .bytes = true" } else { "" };
    let head = format!(".{{ .patterns = {}", strs(pats));
    enum S {
        S(regex::RegexSet),
        B(regex::bytes::RegexSet),
    }
    let set = if bytes {
        regex::bytes::RegexSet::new(pats).ok().map(S::B)
    } else {
        regex::RegexSet::new(pats).ok().map(S::S)
    };
    let Some(set) = set else {
        let _ = writeln!(out, "{}, .ok = false{} }},", head, bytes_f);
        return;
    };
    stats.sets_ok += 1;
    let _ = writeln!(out, "{}, .ok = true{}, .cases = &.{{", head, bytes_f);
    for h in inputs {
        let (m, idx): (bool, Vec<i64>) = match &set {
            S::S(s) => (s.is_match(st(h)), s.matches(st(h)).iter().map(|i| i as i64).collect()),
            S::B(s) => (s.is_match(h), s.matches(h).iter().map(|i| i as i64).collect()),
        };
        let _ = writeln!(out, ".{{ .input = {}, .is_match = {}, .matches = {} }},", zstr(h), m, ints(&idx));
        stats.cases += 1;
    }
    out.push_str("} },\n");
}

// ----------------------------------------------------------------- inputs

fn s(x: &str) -> Vec<u8> {
    x.as_bytes().to_vec()
}

fn fixed_inputs() -> Vec<Vec<u8>> {
    [
        "", "a", "abc", "A", "a b", "a\nb", "a\r\nb", "\r\n", "é", "É", "word 123", "_", "Ω", "ж", "ǅ", "💩", "a💩b", "١٢٣", "\u{a0}",
        "\u{2028}", "k", "\u{212a}", "ß", "σς Σ", "foo.bar", "ab\n", "日本語",
    ]
    .iter()
    .map(|x| s(x))
    .collect()
}

/// A few raw byte strings, valid and invalid UTF-8.
fn fixed_bytes_inputs() -> Vec<Vec<u8>> {
    let mut v: Vec<Vec<u8>> = [
        "", "a", "abc", "A", "ab\r\n", "\n\n", "é", "aé", "💩", "1 2", "word word", "Ω", "a\nb",
    ]
    .iter()
    .map(|x| s(x))
    .collect();
    let raw: &[&[u8]] = &[
        b"\xff",
        b"a\xffb",
        b"\x80",
        b"\xc3",
        b"\xc3\xa9",
        b"\xe2\x82",
        b"\xf0\x9f\x92",
        b"\xf0\x9f\x92\xa9\xff",
        b"\xed\xa0\x80",
        b"\xc0\x80",
        b"\xf4\x90\x80\x80",
        b"\xe9",
        b"\xff\xfe",
        b"\x00",
        b"\x7f\x80",
        b"word \xffword",
        b" \xff ",
        b"\xce\xa9\xce",
        b"\xff\n\xff",
        b"a\xc3",
        b"\xa9",
        b"\x00a\xff\x00",
    ];
    for r in raw {
        v.push(r.to_vec());
    }
    v
}

const RUNES: &[&str] = &[
    "a", "b", "c", "A", "B", "1", "2", " ", "\n", "\r\n", "é", "É", "č", "Č", "ß", "ẞ", "k", "s", "_", "-", "Ω", "ω", "ж", "٣", "中", "💩", ".", "σ", "ς", "!",
];

fn rand_input(rng: &mut Rng) -> Vec<u8> {
    let mut b = Vec::new();
    for _ in 0..rng.below(9) {
        b.extend_from_slice(rng.pick(RUNES).as_bytes());
    }
    b
}

fn rand_bytes_input(rng: &mut Rng) -> Vec<u8> {
    const RAW: &[&[u8]] = &[b"\xff", b"\x80", b"\xc3", b"\xe2\x82", b"\xf0\x9f\x92", b"\xed\xa0\x80", b"\xc0\x80", b"\xe9", b"\x00"];
    let mut b = Vec::new();
    for _ in 0..rng.below(9) {
        if rng.below(4) == 0 {
            let x: &&[u8] = rng.pick(RAW);
            b.extend_from_slice(x);
        } else {
            b.extend_from_slice(rng.pick(RUNES).as_bytes());
        }
    }
    b
}

// ------------------------------------------------------ random generator

struct Gen {
    rng: Rng,
    groups: usize,
    bytes: bool,
}

const LITS: &[&str] = &["a", "b", "c", "A", "1", "é", "k", " ", "-", "\\n", "\\.", "Č", "ß", "💩", "_", "Σ", "\\r", "\\x41", "\\u{e9}", "\\U{3a9}"];
const CLASSES: &[&str] = &[
    "[ab]", "[^a]", "[a-c]", "[^a-c\\n]", "\\d", "\\w", "\\s", "\\D", "\\W", "\\S", "[[:alpha:]]", "[[:^digit:]]", "[é1]", "[a-]", "[á-ž]", "[^É]", "\\pL", "\\p{Lu}", "\\P{Ll}",
    "[\\p{Greek}\\d]", "\\p{Latin}", "\\p{sc=Cyrillic}", "\\p{scx=Greek}", "\\p{Alphabetic}", "\\p{White_Space}", "\\p{Emoji}", "[\\w&&[^\\d]]", "[a-z&&[^aeiou]]",
    "[\\p{L}--\\p{Lu}]", "[\\w~~\\d]", "[x[^xyz]]", "[\\p{Greek}&&\\p{L}]", "(?-u:\\w)", "(?-u:\\d)", "(?-u:\\s)", "[[a-c][x-z]]", "[^\\W]", "[\\pN--\\p{Nd}]",
    "[[:word:]]", "[[:punct:]]", "[\\x{10000}-\\x{10FFFF}]", "[^\\p{ASCII}]", "\\p{Any}", "\\p{Nd}", "[\\s\\S]", "[^\\s\\S]",
];
const BYTES_ATOMS: &[&str] = &[
    "(?-u:\\xFF)", "\\xFF", "(?-u:\\x80)", "[\\x80-\\xFF]", "(?-u:[\\x80-\\xFF])", "(?-u:[^a])", "(?-u:.)", "(?s-u:.)", "(?-u:\\W)", "(?-u:[^\\x00-\\x7F])", "(?-u:\\xC3)", "(?-u:\\xC3\\xA9)",
    "(?-u:[\\xC3\\xE2])", "(?-u:\\xF0\\x9F)", "(?-u:\\xED)",
];
const ASSERTS: &[&str] = &["^", "$", "\\b", "\\B", "\\A", "\\z", "\\b{start}", "\\b{end}", "\\b{start-half}", "\\b{end-half}", "\\<", "\\>"];

impl Gen {
    fn atom(&mut self, depth: usize) -> (String, bool) {
        let r = self.rng.below(100);
        if r < 26 {
            return (self.rng.pick(LITS).to_string(), false);
        }
        if r < 34 {
            return (".".to_string(), false);
        }
        if r < 50 {
            return (self.rng.pick(CLASSES).to_string(), false);
        }
        if r < 54 && self.bytes {
            return (self.rng.pick(BYTES_ATOMS).to_string(), false);
        }
        if r < 61 {
            return (self.rng.pick(ASSERTS).to_string(), false);
        }
        if r < 67 && depth < 3 {
            let flags: &[&str] = if self.bytes {
                &["i", "m", "s", "U", "R", "u", "-u", "i-s", "-i", "R-m", "iU", "sm", "-u", "-ui", "x"]
            } else {
                &["i", "m", "s", "U", "R", "u", "i-s", "-i", "R-m", "iU", "sm", "x"]
            };
            return (format!("(?{})", self.rng.pick(flags)), true);
        }
        if r < 87 && depth < 3 {
            let inner = self.alt(depth + 1);
            let g = match self.rng.below(6) {
                0 => format!("(?:{})", inner),
                1 => {
                    self.groups += 1;
                    format!("(?P<g{}>{})", self.groups, inner)
                }
                2 => {
                    self.groups += 1;
                    format!("(?<g{}>{})", self.groups, inner)
                }
                3 => format!("(?{}:{})", self.rng.pick(&["i", "s", "m", "U", "R", "-i", "i-m", "x", "u", "-u"]), inner),
                _ => format!("({})", inner),
            };
            return (g, false);
        }
        ("a".to_string(), false)
    }

    fn repeat(&mut self, atom: (String, bool)) -> String {
        if atom.1 {
            return atom.0; // a bare flag group takes no repetition
        }
        let r = self.rng.below(100);
        let mut op = match r {
            0..=59 => return atom.0,
            60..=69 => "*".to_string(),
            70..=77 => "+".to_string(),
            78..=84 => "?".to_string(),
            _ => {
                let lo = self.rng.below(3);
                match self.rng.below(4) {
                    0 => format!("{{{}}}", lo),
                    1 => format!("{{{},}}", lo),
                    2 => format!("{{{},{}}}", lo, lo + self.rng.below(3)),
                    _ => format!("{{ {} , {} }}", lo, lo + self.rng.below(3)),
                }
            }
        };
        if self.rng.below(4) == 0 {
            op.push('?');
        }
        atom.0 + &op
    }

    fn concat(&mut self, depth: usize) -> String {
        let mut b = String::new();
        for _ in 0..1 + self.rng.below(4) {
            let a = self.atom(depth);
            b.push_str(&self.repeat(a));
        }
        b
    }

    fn alt(&mut self, depth: usize) -> String {
        let mut s = self.concat(depth);
        while self.rng.below(4) == 0 {
            s.push('|');
            s.push_str(&self.concat(depth));
        }
        s
    }
}

// ----------------------------------------------------- names (group b)

const SAMPLE: &[char] = &[
    'a', 'A', '1', ' ', '_', '.', 'é', 'Ω', 'ж', '中', 'あ', '٣', '€', '😀', '\u{301}', '\u{ad}', '\u{200d}', '\u{fe0f}', '\u{3001}', '\u{640}',
    '\u{378}', '\u{ffff}', '\u{e000}', '\u{2028}', '\u{b2}', '\u{1c5}',
];

const GC: &[&str] = &[
    "L", "Lu", "Ll", "Lt", "Lm", "Lo", "LC", "M", "Mn", "Mc", "Me", "N", "Nd", "Nl", "No", "P", "Pc", "Pd", "Ps", "Pe", "Pi", "Pf", "Po", "S", "Sm", "Sc", "Sk", "So", "Z", "Zs", "Zl",
    "Zp", "C", "Cc", "Cf", "Cs", "Co", "Cn", "Letter", "Cased_Letter", "Uppercase_Letter", "Lowercase_Letter", "Titlecase_Letter", "Modifier_Letter", "Other_Letter", "Mark",
    "Combining_Mark", "Nonspacing_Mark", "Spacing_Mark", "Enclosing_Mark", "Number", "Decimal_Number", "digit", "Letter_Number", "Other_Number", "Punctuation", "punct",
    "Connector_Punctuation", "Dash_Punctuation", "Open_Punctuation", "Close_Punctuation", "Initial_Punctuation", "Final_Punctuation", "Other_Punctuation", "Symbol", "Math_Symbol",
    "Currency_Symbol", "Modifier_Symbol", "Other_Symbol", "Separator", "Space_Separator", "Line_Separator", "Paragraph_Separator", "Other", "Control", "cntrl", "Format", "Surrogate",
    "Private_Use", "Unassigned",
];

/// Scripts (all assigned in Unicode 15.0), each with a code point that is in it.
const SCRIPTS: &[(&str, char)] = &[
    ("Greek", 'Ω'), ("Latin", 'a'), ("Cyrillic", 'ж'), ("Han", '中'), ("Hiragana", 'あ'), ("Katakana", 'カ'), ("Hangul", '한'), ("Arabic", 'ب'), ("Hebrew", 'א'),
    ("Thai", 'ก'), ("Devanagari", 'अ'), ("Bengali", 'অ'), ("Tamil", 'அ'), ("Armenian", 'Ա'), ("Georgian", 'ა'), ("Ethiopic", 'አ'), ("Khmer", 'ក'), ("Lao", 'ກ'),
    ("Tibetan", 'ཀ'), ("Mongolian", 'ᠠ'), ("Cherokee", 'Ꭰ'), ("Runic", 'ᚠ'), ("Ogham", 'ᚁ'), ("Braille", '⠁'), ("Common", '1'), ("Inherited", '\u{301}'), ("Coptic", 'Ⲁ'),
    ("Gothic", '\u{10330}'), ("Deseret", '\u{10400}'), ("Linear_B", '\u{10000}'), ("Cuneiform", '\u{12000}'), ("Egyptian_Hieroglyphs", '\u{13000}'), ("Syriac", 'ܐ'),
    ("Thaana", 'ހ'), ("Sinhala", 'අ'), ("Gujarati", 'અ'), ("Gurmukhi", 'ਅ'), ("Kannada", 'ಅ'), ("Telugu", 'అ'), ("Malayalam", 'അ'), ("Myanmar", 'က'), ("Bopomofo", 'ㄅ'),
    ("Yi", '\u{a000}'), ("Tifinagh", 'ⴰ'), ("Glagolitic", 'Ⰰ'), ("Canadian_Aboriginal", 'ᐁ'), ("Old_Italic", '\u{10300}'),
];

const SCX: &[(&str, char)] = &[
    ("Greek", '\u{342}'), ("Common", '\u{3001}'), ("Inherited", '\u{951}'), ("Han", '\u{3001}'), ("Hiragana", '\u{30fc}'), ("Katakana", '\u{30fc}'), ("Arabic", '\u{640}'),
    ("Devanagari", '\u{951}'), ("Syriac", '\u{640}'), ("Latin", '\u{363}'), ("Bopomofo", '\u{3001}'),
];

const BOOLS: &[(&str, char)] = &[
    ("Alphabetic", 'a'), ("White_Space", ' '), ("Emoji", '😀'), ("Uppercase", 'A'), ("Lowercase", 'a'), ("Math", '+'), ("Dash", '-'), ("Hex_Digit", 'f'), ("ASCII_Hex_Digit", 'F'),
    ("ID_Start", 'a'), ("ID_Continue", '1'), ("XID_Start", 'é'), ("XID_Continue", '_'), ("Ideographic", '中'), ("Diacritic", '\u{301}'), ("Extender", '\u{b7}'), ("Cased", 'Ω'),
    ("Case_Ignorable", '.'), ("Quotation_Mark", '"'), ("Terminal_Punctuation", '.'), ("Soft_Dotted", 'i'), ("Regional_Indicator", '\u{1f1e6}'), ("Emoji_Presentation", '😀'),
    ("Emoji_Modifier", '\u{1f3fb}'), ("Extended_Pictographic", '😀'), ("Variation_Selector", '\u{fe0f}'), ("Join_Control", '\u{200d}'), ("Bidi_Mirrored", '('),
    ("Pattern_Syntax", '!'), ("Pattern_White_Space", '\n'), ("Noncharacter_Code_Point", '\u{fdd0}'), ("Default_Ignorable_Code_Point", '\u{ad}'), ("Grapheme_Extend", '\u{301}'),
    ("Grapheme_Base", 'a'), ("Changes_When_Lowercased", 'A'), ("Unified_Ideograph", '中'), ("Radical", '\u{2f00}'), ("Deprecated", '\u{149}'), ("Logical_Order_Exception", '\u{e40}'),
    ("Sentence_Terminal", '!'), ("Bidi_Control", '\u{200e}'), ("Emoji_Component", '#'), ("Emoji_Modifier_Base", '\u{261d}'), ("Hyphen", '-'), ("Other_Math", '^'),
    ("Changes_When_Casefolded", 'A'), ("Changes_When_Casemapped", 'a'), ("Changes_When_Titlecased", 'a'), ("Changes_When_Uppercased", 'a'), ("Prepended_Concatenation_Mark", '\u{600}'),
];

/// Alias spellings of the above (short names, loose forms).
const ALIASES: &[(&str, char)] = &[
    ("alpha", 'a'), ("space", ' '), ("wspace", '\t'), ("Upper", 'A'), ("Lower", 'a'), ("AHex", 'F'), ("Hex", 'f'), ("IDS", 'a'), ("IDC", '1'), ("XIDS", 'a'), ("XIDC", '_'), ("Ideo", '中'),
    ("Dia", '\u{301}'), ("Ext", '\u{b7}'), ("CI", '.'), ("QMark", '"'), ("Term", '.'), ("SD", 'i'), ("RI", '\u{1f1e6}'), ("EPres", '😀'), ("EMod", '\u{1f3fb}'), ("ExtPict", '😀'),
    ("VS", '\u{fe0f}'), ("Join_C", '\u{200d}'), ("Bidi_M", '('), ("Pat_Syn", '!'), ("Pat_WS", '\n'), ("NChar", '\u{fdd0}'), ("DI", '\u{ad}'), ("Gr_Ext", '\u{301}'), ("Gr_Base", 'a'),
    ("CWL", 'A'), ("UIdeo", '中'), ("LOE", '\u{e40}'), ("STerm", '!'), ("Bidi_C", '\u{200e}'), ("EComp", '#'), ("EBase", '\u{261d}'), ("CWCF", 'A'), ("CWCM", 'a'), ("CWT", 'a'),
    ("CWU", 'a'), ("PCM", '\u{600}'), ("white-space", ' '), ("White Space", ' '), ("WHITE_SPACE", ' '), ("whitespace", ' '),
];

fn name_inputs(extra: Option<char>) -> Vec<Vec<u8>> {
    let mut v: Vec<Vec<u8>> = SAMPLE.iter().map(|c| c.to_string().into_bytes()).collect();
    v.push(SAMPLE.iter().take(12).collect::<String>().into_bytes());
    if let Some(c) = extra {
        v.push(c.to_string().into_bytes());
    }
    v
}

// ------------------------------------------------------------ pattern lists

fn lines(txt: &str) -> Vec<String> {
    txt.lines().filter(|l| !l.is_empty() && !l.starts_with(";;")).map(|l| l.to_string()).collect()
}

fn mini_inputs(c: &str) -> Vec<Vec<u8>> {
    ["", "a", c, "\n", "é", "\u{7}", "\t", "ab"].iter().map(|x| s(x)).collect()
}

fn nested(open: &str, mid: &str, close: &str, n: usize) -> String {
    format!("{}{}{}", open.repeat(n), mid, close.repeat(n))
}

fn crafted_patterns() -> Vec<(String, Option<String>)> {
    // (pattern, Some(char)) = the mini input set around that char; None = fixed inputs.
    let mut v: Vec<(String, Option<String>)> = Vec::new();
    for l in lines(lists::CRAFTED_TXT) {
        v.push((l, None));
    }
    for p in lists::CRAFTED_SPECIAL {
        v.push((p.to_string(), None));
    }
    // Every ASCII byte after a backslash, and a few more.
    for c in 0x21u8..0x7f {
        let ch = (c as char).to_string();
        v.push((format!("\\{}", ch), Some(ch)));
    }
    for ch in ["é", "💩", "\u{a0}", " "] {
        v.push((format!("\\{}", ch), Some(ch.to_string())));
    }
    // Nesting depth: Rust's default limit is 250.
    for n in [1usize, 100, 249, 250, 251, 260, 1000] {
        v.push((nested("(?:", "a", ")", n), None));
        v.push((nested("(", "a", ")", n), None));
    }
    for n in [100usize, 249, 250, 251] {
        v.push((nested("[", "a", "]", n), Some("a".to_string())));
        v.push((nested("(?:a", "", ")*", n), Some("a".to_string())));
    }
    v.push((format!("{}{}", "(".repeat(300), ")".repeat(300)), None));
    v.push((format!("({}", "a|".repeat(1000)), None));
    v.push(("a|".repeat(2000) + "b", None));
    v
}

fn bytes_crafted_patterns() -> Vec<String> {
    let mut v = lines(lists::BYTES_TXT);
    for p in lists::BYTES_SPECIAL {
        v.push(p.to_string());
    }
    // Shorthands under the ways to turn Unicode off.
    for e in ["\\w", "\\W", "\\d", "\\D", "\\s", "\\S", "\\b", "\\B", ".", "[^a]", "[a-z]", "(?i)k", "\\pL", "\\xFF", "[\\xFF]"] {
        v.push(format!("(?-u){}+", e));
        v.push(format!("(?-u:{}){{2}}", e));
        v.push(format!("(?s-u){}", e));
        v.push(format!("(?-u)({})", e));
    }
    v
}

fn set_lists() -> Vec<(Vec<&'static str>, bool)> {
    let sets: Vec<Vec<&'static str>> = vec![
        vec!["a", "b"],
        vec!["a", "a"],
        vec!["a", "ab", "abc"],
        vec!["abc", "ab", "a"],
        vec!["^a", "a$"],
        vec!["^a$", "^$"],
        vec!["", "a"],
        vec!["", ""],
        vec!["a*", "b*"],
        vec!["a+", "b+", "c+"],
        vec!["^", "$"],
        vec!["\\b", "\\B"],
        vec!["\\bfoo\\b", "\\Bo\\B", "o"],
        vec!["(?i)a", "A"],
        vec!["(?i)é", "É", "é"],
        vec!["(?m)^a$", "(?m)^b$", "^b$"],
        vec!["(?m)^$", "(?m)$"],
        vec!["(?R)(?m)^$", "(?m)^$"],
        vec!["(?s).", "."],
        vec![".", "\\n"],
        vec!["\\w+", "\\d+", "\\s+"],
        vec!["\\pL", "\\p{Lu}", "\\p{Ll}", "\\p{N}"],
        vec!["\\p{Greek}", "\\p{Latin}", "\\p{Cyrillic}", "\\p{Han}"],
        vec!["[a-c]", "[b-d]", "[c-e]"],
        vec!["[a&&b]", "a"],
        vec!["(a)(b)", "(a)|(b)", "a(b)?"],
        vec!["(?P<n>a)", "(?P<n>b)"],
        vec!["a", "("],
        vec!["(", "a"],
        vec!["a", "b", "(?=c)"],
        vec!["a", "\\1"],
        vec!["a{2}", "a{2,}", "a{1,3}", "a{0}"],
        vec!["a{1001}", "a"],
        vec!["x*y*", "z*", "^$"],
        vec!["ab|cd", "ef|gh", "ab"],
        vec!["(?-u:\\w)", "(?-u:\\W)", "\\w"],
        vec!["(?x) a b ", "ab"],
        vec!["(?x)a # c", "b"],
        vec!["a.c", "a\\.c", "a.*c"],
        vec!["[[:alpha:]]", "[[:^alpha:]]", "[[:digit:]]"],
        vec!["é", "e", "\\x{e9}", "\\u{e9}"],
        vec!["💩", "\\x{1F4A9}", "."],
        vec!["\\b{start}", "\\b{end}", "\\b{start-half}", "\\b{end-half}"],
        vec!["\\<", "\\>"],
        vec!["a", "b", "c", "d", "e", "f", "g", "h"],
        vec!["^a", "^b", "^c", "^d", "$", "\\z", "\\A", ""],
        vec!["(a|b)*c", "(a*)*", "(a+)+$"],
        vec!["\\d{3}", "\\d{3}-\\d{4}", "\\d{2}"],
        vec!["foo", "foobar", "bar", "o+", "o*"],
        vec!["(?i)straße", "STRASSE", "strasse"],
        vec!["Σ", "σ", "ς", "(?i)σ"],
        vec!["k", "(?i)k", "\\x{212a}"],
        vec!["(?U)a+", "a+", "(?U)a+?"],
        vec!["\\p{Foo}", "a"],
        vec!["[z-a]", "a"],
        vec!["(?R)^a$", "(?mR)^a$"],
        vec!["a", "a", "a"],
        vec!["\\B", ""],
        vec!["(?s:.)+", "[^a]+", "[^\\n]"],
    ];
    let mut out: Vec<(Vec<&'static str>, bool)> = sets.into_iter().map(|x| (x, false)).collect();
    let bsets: Vec<Vec<&'static str>> = vec![
        vec!["(?-u:\\xFF)", "a"],
        vec!["(?-u:\\xFF)", "\\xFF"],
        vec!["(?-u).", "(?s-u)."],
        vec!["(?-u:\\W)", "\\W", "\\w"],
        vec!["\\p{L}", "(?-u:\\xFF)", ""],
        vec!["(?-u)[^a]", "a", "^$"],
        vec!["(?-u:\\xC3\\xA9)", "é", "\\xE9"],
        vec!["^", "$", "\\b", "(?-u:\\b)"],
        vec!["(?-u:\\xFF)+", "(?-u:\\x80)+", "(?-u:\\xC3)"],
        vec!["(?-u)\\p{L}", "a"],
    ];
    out.extend(bsets.into_iter().map(|x| (x, true)));
    out
}

fn set_inputs() -> Vec<Vec<u8>> {
    ["", "a", "b", "ab", "abc", "A", "a\nb", "xyz", "é", "foo bar", "123", "Ωmega", "aaa", "💩", "k", "\u{212a}", "foobar", "\r\n", "STRASSE", "σ", "555-1234"]
        .iter()
        .map(|x| s(x))
        .collect()
}

fn set_bytes_inputs() -> Vec<Vec<u8>> {
    let mut v = set_inputs();
    for r in [&b"\xff"[..], b"a\xff", b"\xc3\xa9", b"\xc3", b"\x80\x80", b"\xe9", b"\xff\xff\xff", b"word \xff"] {
        v.push(r.to_vec());
    }
    v
}

// --------------------------------------------------------------- the file

const HEADER: &str = r#"/// Rust `regex`'s answers for one input: `is_match`; `full`, a match of
/// `\A(?:re)\z` built with the same builder (see `full_ok`); `caps`, the
/// positions `captures_read` fills in, flattened (start, end) pairs with -1 for
/// a group that took no part, empty when there is no match; `all`, `find_iter`
/// flattened; `shortest`, `shortest_match` (the end, or -1).
pub const Case = struct {
    input: []const u8,
    is_match: bool,
    full: bool,
    caps: []const i32,
    all: []const i32,
    shortest: i32,
};

pub const Kind = enum { crafted, unicode, random };

/// `ok`: the crate compiles the pattern (an invalid pattern carries nothing
/// else; the error text is the crate's wording and is not recorded). `names`:
/// `capture_names` (an unnamed group, and group 0, are ""). `bytes`: built with
/// `regex::bytes::RegexBuilder` defaults (Unicode on, `utf8` as `bytes::Regex::new`),
/// inputs may be invalid UTF-8; otherwise `regex::RegexBuilder` defaults and
/// valid UTF-8 inputs. `full_ok`: false when neither `\A(?:re)\z` nor
/// `\A(?:re\n)\z` compiled, `full` is then meaningless.
pub const Pattern = struct {
    pattern: []const u8,
    ok: bool,
    kind: Kind = .crafted,
    bytes: bool = false,
    names: []const []const u8 = &.{},
    full_ok: bool = true,
    cases: []const Case = &.{},
};

/// A `RegexSet` input: `is_match` and the indices `matches()` reports.
pub const SetCase = struct {
    input: []const u8,
    is_match: bool,
    matches: []const i32,
};

/// `ok`: `RegexSet::new` accepted every member. `bytes`: `regex::bytes::RegexSet`.
pub const Set = struct {
    patterns: []const []const u8,
    ok: bool,
    bytes: bool = false,
    cases: []const SetCase = &.{},
};

"#;

fn generate(stats: &mut Stats) -> String {
    let mut b = String::new();
    let _ = writeln!(b, "// SPDX-License-Identifier: MIT");
    let _ = writeln!(
        b,
        "// GENERATED by modules/regex/tools/rust_regex_oracle (regex 1.13.1, Unicode {}) -- do not hand-edit.",
        UNICODE
    );
    b.push_str("//! Rust regex's answers to this module's own patterns and inputs, replayed by\n");
    b.push_str("//! `rust_oracle_test.zig`. Regenerate with the command in tools/rust_regex_oracle/src/main.rs.\n\n");
    b.push_str(HEADER);

    // ---- str patterns: crafted, unicode names, random
    b.push_str("pub const patterns = [_]Pattern{\n");
    let fixed = fixed_inputs();
    for (p, mini) in crafted_patterns() {
        let inputs = match &mini {
            Some(c) => mini_inputs(c),
            None => fixed.clone(),
        };
        stats.crafted += 1;
        emit_pattern(&mut b, stats, &p, Kind::Crafted, false, &inputs);
    }
    let emit_name = |b: &mut String, stats: &mut Stats, pat: String, extra: Option<char>| {
        stats.unicode += 1;
        emit_pattern(b, stats, &pat, Kind::Unicode, false, &name_inputs(extra));
    };
    for n in GC {
        emit_name(&mut b, stats, format!("\\p{{{}}}", n), None);
    }
    for n in ["L", "N", "P", "S", "Z", "M", "C"] {
        emit_name(&mut b, stats, format!("\\P{{{}}}", n), None);
    }
    for (n, c) in SCRIPTS {
        emit_name(&mut b, stats, format!("\\p{{{}}}", n), Some(*c));
        emit_name(&mut b, stats, format!("\\p{{sc={}}}", n.to_lowercase()), Some(*c));
    }
    for (n, c) in SCX {
        emit_name(&mut b, stats, format!("\\p{{scx={}}}", n), Some(*c));
        emit_name(&mut b, stats, format!("\\p{{Script_Extensions:{}}}", n), Some(*c));
    }
    for (n, c) in BOOLS {
        emit_name(&mut b, stats, format!("\\p{{{}}}", n), Some(*c));
    }
    for (n, c) in ALIASES {
        emit_name(&mut b, stats, format!("\\p{{{}}}", n), Some(*c));
    }
    for (n, c) in BOOLS.iter().take(12) {
        emit_name(&mut b, stats, format!("\\P{{{}}}", n), Some(*c));
        emit_name(&mut b, stats, format!("[\\p{{{}}}&&\\p{{L}}]", n), Some(*c));
    }
    let mut rg = Gen { rng: Rng(0x7265_6765_78_u64), groups: 0, bytes: false };
    let mut irng = Rng(0x7265_6765_78_u64 ^ 0x5a5a);
    for _ in 0..N_RANDOM {
        rg.groups = 0;
        let p = rg.alt(0);
        let inputs: Vec<Vec<u8>> = (0..N_INPUTS).map(|_| rand_input(&mut irng)).collect();
        stats.random += 1;
        emit_pattern(&mut b, stats, &p, Kind::Random, false, &inputs);
    }
    b.push_str("};\n\n");

    // ---- bytes patterns
    b.push_str("pub const bytes_patterns = [_]Pattern{\n");
    let bfixed = fixed_bytes_inputs();
    for p in bytes_crafted_patterns() {
        stats.bytes_crafted += 1;
        emit_pattern(&mut b, stats, &p, Kind::Crafted, true, &bfixed);
    }
    let mut bg = Gen { rng: Rng(0x6279_7465_73_u64), groups: 0, bytes: true };
    let mut birng = Rng(0x6279_7465_73_u64 ^ 0xa5a5);
    for _ in 0..N_BYTES_RANDOM {
        bg.groups = 0;
        let p = bg.alt(0);
        let inputs: Vec<Vec<u8>> = (0..N_INPUTS).map(|_| rand_bytes_input(&mut birng)).collect();
        stats.bytes_random += 1;
        emit_pattern(&mut b, stats, &p, Kind::Random, true, &inputs);
    }
    b.push_str("};\n\n");

    // ---- sets
    b.push_str("pub const sets = [_]Set{\n");
    let sin = set_inputs();
    let sbin = set_bytes_inputs();
    for (pats, bytes) in set_lists() {
        let pats: Vec<String> = pats.iter().map(|x| x.to_string()).collect();
        emit_set(&mut b, stats, &pats, bytes, if bytes { &sbin } else { &sin });
    }
    let mut sg = Gen { rng: Rng(0x7365_74_u64), groups: 0, bytes: false };
    for i in 0..N_SETS_RANDOM {
        let n = 2 + sg.rng.below(5);
        let bytes = i % 4 == 3;
        sg.bytes = bytes;
        let pats: Vec<String> = (0..n).map(|_| { sg.groups = 0; sg.alt(1) }).collect();
        emit_set(&mut b, stats, &pats, bytes, if bytes { &sbin } else { &sin });
    }
    b.push_str("};\n");
    b
}

fn zig_fmt(src: &str) -> String {
    let mut child = Command::new("zig")
        .args(["fmt", "--stdin"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn zig fmt --stdin (is zig on PATH?)");
    let mut stdin = child.stdin.take().unwrap();
    let data = src.as_bytes().to_vec();
    let w = std::thread::spawn(move || {
        let _ = stdin.write_all(&data);
    });
    let out = child.wait_with_output().expect("zig fmt");
    let _ = w.join();
    if !out.status.success() {
        eprintln!("zig fmt --stdin failed: {}", out.status);
        std::process::exit(2);
    }
    String::from_utf8(out.stdout).expect("zig fmt output is UTF-8")
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut out: Option<String> = None;
    let mut check: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-out" | "--out" => {
                i += 1;
                out = args.get(i).cloned();
            }
            "-check" | "--check" => {
                i += 1;
                check = args.get(i).cloned();
            }
            a => {
                eprintln!("unknown argument {}; usage: [-out FILE | -check FILE]", a);
                std::process::exit(2);
            }
        }
        i += 1;
    }

    let mut stats = Stats::default();
    let formatted = zig_fmt(&generate(&mut stats));

    if let Some(path) = check {
        let old = match std::fs::read(&path) {
            Ok(o) => String::from_utf8_lossy(&o).into_owned(),
            Err(e) => {
                eprintln!("{}: {}", path, e);
                std::process::exit(2);
            }
        };
        if old != formatted {
            let (ol, nl): (Vec<&str>, Vec<&str>) = (old.split('\n').collect(), formatted.split('\n').collect());
            for k in 0..ol.len().max(nl.len()) {
                let (x, y) = (ol.get(k).copied().unwrap_or(""), nl.get(k).copied().unwrap_or(""));
                if x != y {
                    eprintln!("DRIFT at line {}:\n  committed: {}\n  re-taken:  {}", k + 1, x, y);
                    break;
                }
            }
            std::process::exit(1);
        }
        eprintln!("rust regex oracle: committed vectors match a fresh re-take");
        return;
    }
    match out {
        Some(path) => {
            if let Err(e) = std::fs::write(&path, formatted.as_bytes()) {
                eprintln!("{}: {}", path, e);
                std::process::exit(2);
            }
        }
        None => {
            let _ = std::io::stdout().write_all(formatted.as_bytes());
        }
    }
    eprintln!(
        "str patterns: crafted+unicode {} (crafted {}, unicode {}; {} compile), random {} ({} compile); bytes patterns: crafted {} ({} compile), random {}; sets {} ({} compile); cases {}; full_ok=false patterns {}",
        stats.crafted + stats.unicode,
        stats.crafted,
        stats.unicode,
        stats.crafted_ok,
        stats.random,
        stats.random_ok,
        stats.bytes_crafted,
        stats.bytes_ok,
        stats.bytes_random,
        stats.sets,
        stats.sets_ok,
        stats.cases,
        stats.full_bad
    );
}
