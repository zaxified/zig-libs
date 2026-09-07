#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""check-fuzz-reach — a fuzz harness must consume the input bytes it is given.

WHY THIS EXISTS
---------------
`std.testing.Smith` is not a random-number generator. It is a DECODER for a
byte string, and the sequence of draws a harness makes IS that string's format.
Outside `zig build --fuzz` the test runner replays exactly two things through
it (`compiler/test_runner.zig`, `pub fn fuzz`):

    for (options.corpus) |input| { var smith: Smith = .{ .in = input }; ... }
    var smith: Smith = .{ .in = "" };            // the no-corpus smoke test

So every seed a harness carries, and every crash `--fuzz` finds and minimises
into a seed, is decoded by the draw sequence. And the ranged draws decode
badly. `Smith.valueWeightedWithHashInner` reads EIGHT bytes as a little-endian
u64 and then:

    break :int if (weightsContain(int, weights)) int else weights[0].min;

There is no scaling and no modulo. `valueRangeAtMost(u8, 0, 9)` therefore
returns 9 only when the next eight input bytes spell the u64 `9`; for every
other eight bytes it returns 0 — the range MINIMUM. `index`, `boolWeighted`,
`valueWeighted` and `value` of any type narrower than 64 bits all route through
that same function and inherit the behaviour. `bytes`/`bytesWeighted` copy the
input verbatim, `slice`/`sliceWeighted*` read a 4-byte little-endian length and
then copy verbatim, and `value` of a 64-bit-or-wider scalar has full-range
weights so `weightsContain` is always true — those four are faithful.

The consequence is that a harness whose first draw is ranged throws its corpus
away at the first statement and then runs the same fixed scenario for every
seed. `modules/netaddr` found this by hand on 2026-09-04, instrumented it, and
wrote the numbers into its own harness: three parsers of untrusted text, **1
round, 0 non-empty inputs, 0 that parsed as an address**, and still 0 non-empty
after someone hand-wrote a corpus of 12 real address literals. The same three
harnesses with a single `smith.slice(&buf)` get 9 non-empty and 2 that parse.
Nothing carried that lesson to the other 165 modules, and the audit of
2026-09-06 raised the same defect by hand in 31 more.

Three shapes worth reading, because they are the ones that recur:

  * `modules/cbor` carries a real CBOR seed corpus. `buildNested` opens with
    `smith.valueRangeAtMost(u8, 0, 4)` -> 0, takes the raw-bytes branch,
    `smith.bytes(buf)` fills 4096 bytes from the seed, and then returns
    `buf[0..smith.valueRangeAtMost(u16, 0, buf.len)]` -> `buf[0..0]`. Every
    seed decodes to the empty message.
  * `modules/dnp3` wraps the Smith in a `SmithDrawer` whose only method is
    `below(n) = smith.index(n)`. `drawRequest` builds an entire DNP3 fragment
    out of nothing but `below`, so every field is its own minimum and the
    harness has exactly one fragment in it.
  * `modules/aeskw`'s `fuzzUnwrapNoLeak` does draw real bytes into `ct_buf` —
    and then slices them with `smith.valueRangeAtMost(u16, 0, ct_buf.len)`,
    which is 0. `unwrap` is called with an empty ciphertext every time.

None of this is visible to `zig build check-fuzz`, which asks whether a
harness EXISTS. It is also invisible under `--fuzz` itself, where the draws go
to the fuzzer ABI (`fuzzer_int`) and the ranges are honoured — which is why the
defect survives: the mode that is run in CI is the blind one.

At the time this was written the collection had 474 judgeable targets in 168
modules and 416 of them collapsed. That is not a wishlist masquerading as a
gate; it is one copy-pasted idiom —

    smith.bytes(&buf);
    const len = smith.valueRangeAtMost(u16, 0, buf.len);   // always 0
    _ = decode(buf[0..len]);                               // always decode("")

— repeated 330 times. Which is why the gate takes `--advisory`: see the
burn-down note at the bottom of this header.

WHAT IT CHECKS
--------------
Two rules, both derived from the quoted `Smith` code and nothing else.

  R1 REACH   The first draw a target makes must be faithful. A collapsing first
             draw means the seed is discarded before anything is read from it.

  R2 TRUNCATION  A buffer filled by a faithful draw must not then be sliced to
             a length that came from a collapsing draw. The bytes are consumed
             from the seed and then thrown away, which reads as reach in a diff
             and is not.

To find the FIRST draw the checker inlines, in source order: functions in the
same file that are handed the Smith (`build(smith, &buf)`), and methods of a
local struct that holds one (the `SmithDrawer` case above). Three things about
that were measured on this tree rather than assumed, each because a simpler
version of this gate got them wrong:

  * Following helpers only ONE level, and only when the target itself draws
    nothing, is not enough. `modules/rescue`'s five targets open with
    `arbitraryFe(smith)`, whose body is `gl.fromU64(smith.value(u64))` —
    faithful. A one-level scan never gets there, reports the LATER
    `smith.value(u8)` as the first draw, and flags all five wrongly.
  * A method must be resolved on the type of its receiver, not by name.
    `modules/dnp3/src/outstation.zig` declares `fn below` twice: once on
    `Xorshift` (a plain PRNG, no Smith) and once on `SmithDrawer`. Taking the
    first definition reports the harness as drawing nothing at all.
  * The call site is `testing.fuzz(`, not `std.testing.fuzz(`. 252 of the 477
    call sites in this collection go through a `const testing = std.testing`
    alias; anchoring on the fully qualified spelling sees 47% of the fleet.

`value`'s verdict depends on its TYPE argument, which is why `width_of` exists:
`value(u64)` is faithful and `value(u8)` is not, and a rule that lumps them
together flags `modules/pir`'s `fuzzDomainBitsFor` — whose entire input is
`smith.value(usize)` — as unreachable.

⛔ WHAT IT CANNOT SEE
--------------------
* Whether the bytes, once they arrive, reach the parser. A harness can draw a
  perfect 4 KB and hand the decoder `buf[0..4]`; if the 4 is a literal, that is
  a judgement call about the module and this gate does not make it.
* Targets defined in another file, or handed to `testing.fuzz` as an inline
  `struct { fn run(...) }` literal. Both are counted and listed as UNJUDGED
  rather than silently passing — an unjudged target is a hole in the gate, and
  a hole that reports itself is the only kind worth having.
* `eos`/`eosWeighted`/`eosWeightedSimple`, which read ONE byte and return
  `byte != 0`. That is genuinely input-driven, so they are not collapsing, but
  a harness built only from them has one bit of reach per byte. They are
  reported as WEAK and do not fail the gate.
* `usize`/`isize` are taken to be 64 bits. On a 32-bit target `value(usize)`
  would collapse and this gate would not say so.

EXEMPTIONS
----------
A module states its own, in its own `SPEC.md` (or `README.md` when it has no
SPEC), as one line — the same shape `build.zig`'s `moduleFuzzExemption` reads
for `check-fuzz`, and for the same reason: the fact belongs in the file a
reader of that module opens, not in a repository-level table that would hold
one row per module and go stale unread.

    **Fuzz-reach exemption:** STRUCTURED via fuzzOps, fuzzHandle

    <the argument, in prose, up to the next `## ` heading>

`STRUCTURED` is the only reason word, and it means: the target draws a SHAPE —
an operation sequence, a state-machine schedule, a grammar — and has no wire
byte string it could be faithful to. It does not mean "the fix is awkward". A
target whose input IS a byte string is not exempt; the fix there is to move the
`bytes`/`slice` draw ahead of the knobs, which is a two-line edit.

An exemption naming a target that is not flagged, or that does not exist, is
itself an error. A stale waiver is how the next one gets waved through, and
this one cannot go stale unread because the gate reads it every run.

BURNING IT DOWN
---------------
`--advisory` reports and exits 0. It exists so the gate can be wired into
`scripts/test.sh` on the day it lands, printing the count on every run, instead
of waiting behind a 416-target rewrite — a gate that is not wired is a gate
that regresses. Drop the flag once the count reaches zero; until then the
number in the output is the burn-down, and `--list` is the worklist, grouped by
module. `--module <name>` narrows it to the one being fixed.
"""
import argparse
import re
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# The Smith draw vocabulary, split by what `Smith.zig` does with the input.
# ---------------------------------------------------------------------------

# Copy the input verbatim (`bytesWeightedWithHash`, `sliceWeightedWithHash`).
FAITHFUL_METHODS = {
    "bytes", "bytesWeighted", "bytesWithHash", "bytesWeightedWithHash",
    "slice", "sliceWeighted", "sliceWeightedBytes",
    "sliceWithHash", "sliceWeightedWithHash", "sliceWeightedBytesWithHash",
}
# One byte -> `byte != 0`. Input-driven, but one bit of it.
WEAK_METHODS = {"eos", "eosWeighted", "eosWeightedSimple",
                "eosWithHash", "eosWeightedWithHash", "eosWeightedSimpleWithHash"}
# Eight bytes -> u64 -> the range minimum unless it happens to land inside.
COLLAPSING_METHODS = {
    "valueRangeAtMost", "valueRangeLessThan", "valueWeighted",
    "valueRangeAtMostWithHash", "valueRangeLessThanWithHash", "valueWeightedWithHash",
    "index", "indexWithHash", "boolWeighted", "boolWeightedWithHash",
}
# `value` is the one that depends on its type argument; see `width_of`.
VALUE_METHODS = {"value", "valueWithHash"}

ALL_METHODS = FAITHFUL_METHODS | WEAK_METHODS | COLLAPSING_METHODS | VALUE_METHODS

DRAW_RE = re.compile(r"\b(\w+)\.(" + "|".join(sorted(ALL_METHODS, key=len, reverse=True)) + r")\s*\(")
CALL_RE = re.compile(r"\b(\w+)\s*\(")
KEYWORDS = {"if", "while", "for", "switch", "return", "catch", "fn", "try",
            "orelse", "defer", "errdefer", "comptime", "inline", "and", "or",
            "test", "struct", "union", "enum", "align", "callconv"}
FUZZ_RE = re.compile(r"\btesting\.fuzz\s*\(")
FN_RE = re.compile(r"\bfn\s+(\w+)\s*\(")
# `const Drawer = struct { smith: *testing.Smith, ... }` and `var d = Drawer{ .smith = smith }`.
SMITH_FIELD_RE = re.compile(r"\b(\w+)\s*:\s*\*(?:std\.)?testing\.Smith")
STRUCT_LIT_RE = re.compile(
    r"\b(?:var|const)\s+(\w+)\s*(?::[^=]*)?=\s*([.\w]*)\s*\{[^}]*\.smith\s*=")

MAX_DEPTH = 6


def width_of(type_arg: str):
    """Bit width of a `value(T)` type argument, or None when it is not a scalar.

    `Smith.valueWithHash` splits an int/float into 64-bit chunks and asks for
    each with `baselineWeights(P)`, whose single weight spans all of `P`. So a
    chunk of exactly 64 bits accepts every input word — faithful — and a
    narrower type accepts only the 1-in-2^(64-n) words that fit.
    """
    t = type_arg.strip()
    # `[N]u8` and `@Vector(N, u8)` route to `bytesWithHash`, which is verbatim.
    if re.fullmatch(r"\[\s*\d+\s*\]\s*u8", t) or re.fullmatch(r"@Vector\s*\(\s*\d+\s*,\s*u8\s*\)", t):
        return 64
    m = re.fullmatch(r"\[\s*\d+\s*\]\s*([ui]\d+|f\d+)", t)
    if m:
        t = m.group(1)
    if t in ("usize", "isize"):
        return 64  # pointer width; see the header's caveat
    m = re.fullmatch(r"[ui](\d+)", t) or re.fullmatch(r"f(\d+)", t)
    if m:
        return int(m.group(1))
    if t == "bool":
        return 1
    return None


def match_paren(src: str, open_idx: int) -> int:
    """Index just past the `)` closing the `(` at `open_idx`. Brace-aware enough
    for Zig argument lists: it tracks (), {}, [], string and char literals."""
    depth = 0
    i = open_idx
    n = len(src)
    while i < n:
        c = src[i]
        if c == '"':
            i += 1
            while i < n and src[i] != '"':
                i += 2 if src[i] == "\\" else 1
        elif c == "'":
            i += 1
            while i < n and src[i] != "'":
                i += 2 if src[i] == "\\" else 1
        elif c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return n


def split_args(arglist: str):
    """Top-level comma split of the text between a call's parentheses."""
    out, depth, cur = [], 0, []
    i = 0
    while i < len(arglist):
        c = arglist[i]
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        elif c == "," and depth == 0:
            out.append("".join(cur))
            cur = []
            i += 1
            continue
        elif c == '"':
            cur.append(c)
            i += 1
            while i < len(arglist) and arglist[i] != '"':
                cur.append(arglist[i])
                i += 1
        cur.append(arglist[i] if i < len(arglist) else "")
        i += 1
    out.append("".join(cur))
    return [a.strip() for a in out]


COMMENT_RE = re.compile(r"\"(?:\\.|[^\"\\\n])*\"|'(?:\\.|[^'\\\n])*'|//[^\n]*")


def strip_comments(src: str) -> str:
    """Blank out `//` comments, preserving offsets so line numbers survive.

    Comments MUST go before anything else looks at the text: `modules/netaddr`
    carries a warning comment that spells out `smith.bytes` followed by a
    ranged draw, and reading it as code would flag the one module in the
    collection that has already fixed this.
    """
    return COMMENT_RE.sub(
        lambda m: " " * len(m.group(0)) if m.group(0).startswith("//") else m.group(0),
        src)


class File:
    """One .zig file: its functions, and which locals carry a Smith."""

    def __init__(self, path: Path):
        self.path = path
        self.raw = path.read_text(errors="replace")
        self.src = strip_comments(self.raw)
        # Every definition of every name, in order. Not a dict keyed by name:
        # `modules/dnp3` declares `fn below` twice in one file — once on
        # `Xorshift` (a plain PRNG) and once on `SmithDrawer` (the Smith
        # wrapper) — and taking the first silently reported the harness as
        # drawing nothing, which is the exact failure this gate is about.
        self.fn_defs = {}
        for m in FN_RE.finditer(self.src):
            paren_end = match_paren(self.src, m.end() - 1)
            brace = self.src.find("{", paren_end)
            if brace < 0:
                continue
            end = match_paren(self.src, brace)
            self.fn_defs.setdefault(m.group(1), []).append(
                (brace + 1, end - 1, self.src[m.end():paren_end - 1]))
        # `const Name = struct { … }`, so a method can be resolved on the type
        # the receiver was built from rather than by name alone.
        self.structs = {}
        for m in re.finditer(r"\bconst\s+(\w+)\s*=\s*(?:packed\s+|extern\s+)?struct\b[^{]*\{",
                             self.src):
            brace = self.src.rfind("{", 0, m.end())
            self.structs.setdefault(m.group(1), (brace, match_paren(self.src, brace)))

    def line_of(self, off: int) -> int:
        return self.src.count("\n", 0, off) + 1

    def resolve(self, name: str, owner: str = None):
        """The definition of `name`, preferring one declared inside `owner`."""
        defs = self.fn_defs.get(name)
        if not defs:
            return None
        if owner and owner in self.structs:
            lo, hi = self.structs[owner]
            for d in defs:
                if lo < d[0] < hi:
                    return d
        return defs[0]

    def body(self, name: str, owner: str = None):
        d = self.resolve(name, owner)
        return self.src[d[0]:d[1]] if d else None

    def carrier_params(self, name: str, owner: str = None) -> dict:
        """Parameters of `name` that can be holding the Smith: the ones typed
        `*Smith`, the `self` of a wrapper struct, and the `anytype` ones —
        `dnp3`'s `drawRequest(d: anytype, …)` takes the wrapper struct that
        way, and a caller only reaches here because it passed a carrier in."""
        d = self.resolve(name, owner)
        if not d:
            return {}
        out = {n: None for n in SMITH_FIELD_RE.findall(d[2])}
        for m in re.finditer(r"(\w+)\s*:\s*anytype", d[2]):
            out[m.group(1)] = None
        for m in re.finditer(r"(\w+)\s*:\s*\*?(\w+)", d[2]):
            ty = m.group(2)
            if ty in self.structs and SMITH_FIELD_RE.search(
                    self.src[self.structs[ty][0]:self.structs[ty][1]]):
                out[m.group(1)] = ty
        return out


class Draw:
    __slots__ = ("kind", "method", "detail", "off", "via")

    def __init__(self, kind, method, detail, off, via):
        self.kind, self.method, self.detail, self.off, self.via = kind, method, detail, off, via

    def __str__(self):
        where = f" (in {self.via})" if self.via else ""
        return f"{self.detail}{where}"


def classify(method: str, arglist: str):
    if method in FAITHFUL_METHODS:
        return "faithful", ""
    if method in WEAK_METHODS:
        return "weak", ""
    if method in COLLAPSING_METHODS:
        return "collapsing", ""
    # `value` / `valueWithHash`
    args = split_args(arglist)
    t = args[0] if args else ""
    w = width_of(t)
    if w is None:
        return "collapsing", f"unknown type `{t}`"
    if w >= 64:
        return "faithful", ""
    return "collapsing", f"`{t}` is {w} bits, so only 1 in 2^{64 - w} input words survives"


def smith_names(body: str, base: dict) -> dict:
    """Names in this body that carry a Smith, mapped to the struct type they
    were built from (or None for a plain `*Smith`): the parameters typed
    `*Smith`, plus locals built from a struct literal with a `.smith =` field."""
    names = dict(base)
    for n in SMITH_FIELD_RE.findall(body):
        names.setdefault(n, None)
    for n, ty in STRUCT_LIT_RE.findall(body):
        names[n] = ty.strip(".") or None
    return names


def walk(f: File, body: str, carriers: set, depth: int, seen: frozenset, via: str):
    """Yield `Draw`s in source order, inlining helper calls at their call site."""
    carriers = smith_names(body, carriers)
    events = []
    for m in DRAW_RE.finditer(body):
        if m.group(1) in carriers:
            events.append((m.start(), "draw", m))
    for m in CALL_RE.finditer(body):
        name = m.group(1)
        if name in KEYWORDS:
            continue
        end = match_paren(body, m.end() - 1)
        args = body[m.end():end - 1]
        # A method ON a carrier that is not a `Smith` method is the wrapper
        # case: `d.below(n)` where `d` holds the Smith. Follow it by name.
        pre = body[:m.start()].rstrip()
        if pre.endswith("."):
            recv = re.search(r"(\w+)\.$", pre)
            if recv and recv.group(1) in carriers and name not in ALL_METHODS:
                events.append((m.start(), "call", (name, carriers[recv.group(1)])))
            continue
        # A free helper only matters if it is handed something carrying a Smith.
        owner = None
        for c, ty in carriers.items():
            if re.search(r"[&\s(,]\s*" + re.escape(c) + r"\b", " " + args):
                owner = ty
                break
        else:
            continue
        events.append((m.start(), "call", (name, owner)))
    events.sort(key=lambda e: e[0])

    for off, kind, payload in events:
        if kind == "draw":
            m = payload
            end = match_paren(body, m.end() - 1)
            arglist = body[m.end():end - 1]
            cls, why = classify(m.group(2), arglist)
            detail = f"{m.group(1)}.{m.group(2)}({arglist.strip()[:48]})"
            yield Draw(cls, m.group(2), detail + (f" — {why}" if why else ""), off, via)
        else:
            name, owner = payload
            if depth >= MAX_DEPTH or name in seen:
                continue
            sub = f.body(name, owner)
            if sub is None:
                continue
            sub_carriers = dict(carriers)
            # A callee's `anytype` parameter is typeless here; give it the type
            # of the carrier the caller passed in, or `d.below()` inside it
            # resolves by name alone — and `dnp3` has two `fn below`.
            for k, v in f.carrier_params(name, owner).items():
                if sub_carriers.get(k) is None:
                    sub_carriers[k] = v if v is not None else owner
            yield from walk(f, sub, sub_carriers, depth + 1,
                            seen | {name}, via if via else name)


# ---------------------------------------------------------------------------
# R2: bytes drawn, then truncated to a collapsing length.
# ---------------------------------------------------------------------------
LEN_BINDING_RE = re.compile(r"\b(?:const|var)\s+(\w+)\s*(?::[^=;]*)?=\s*([^;]*;)", re.S)
COLLAPSING_ALT = "|".join(sorted(COLLAPSING_METHODS, key=len, reverse=True))
COLLAPSING_CALL_RE = re.compile(r"\.(" + COLLAPSING_ALT + r")\s*\(")
# `value` of a type narrower than 64 bits is collapsing too; spelled out here
# because this rule works on text, not on the classified draw list.
NARROW_VALUE_RE = re.compile(
    r"\.value\s*\(\s*(?:bool|[ui](?:[1-9]|[1-5]\d|6[0-3])|f(?:16|32))\s*\)")
FILL_RE = re.compile(r"\.(?:bytes\w*|slice\w*)\s*\(\s*&?(\w+)")
FILL_TRUNC_RE = re.compile(
    r"\.(?:bytes\w*|slice\w*)\s*\(\s*&?(\w+)\s*\[\s*0\s*\.\.\s*(\w+)\s*\]")


def truncation_hits(body_texts):
    """`buf[0..n]` where `buf` was filled by a faithful draw and `n` came from a
    collapsing one. Both halves are required: a collapsing length is only a
    defect when there are drawn bytes for it to discard, and a collapsing count
    over a constant table is a different (and smaller) complaint.

    `modules/netaddr` had already found this by hand and wrote the measurement
    into its own harness — "1 round, 0 non-empty inputs, 0 that parsed as an
    address", and 0 non-empty even with a 12-literal corpus. Its fix, a single
    `smith.slice(&buf)`, is the one this gate recommends."""
    hits = []
    for text in body_texts:
        collapsing = set()
        for m in LEN_BINDING_RE.finditer(text):
            if COLLAPSING_CALL_RE.search(m.group(2)) or NARROW_VALUE_RE.search(m.group(2)):
                collapsing.add(m.group(1))
        filled = set(FILL_RE.findall(text))
        for buf in sorted(filled):
            for n in sorted(collapsing):
                if re.search(r"\b" + re.escape(buf) + r"\s*\[\s*0?\s*\.\.\s*" +
                             re.escape(n) + r"\s*\]", text):
                    hits.append(
                        f"`{buf}` is filled with real input bytes and then sliced by `{n}`, "
                        f"which comes from a bounded draw and is therefore the range minimum")
        # The destination form: `smith.bytes(buf[0..n])` draws n bytes, n = min.
        for buf, n in FILL_TRUNC_RE.findall(text):
            if n in collapsing:
                hits.append(
                    f"the draw into `{buf}` is bounded by `{n}`, which comes from a bounded "
                    f"draw and is therefore the range minimum, so no bytes are drawn")
        # The inline form: `buf[0..smith.valueRangeAtMost(...)]`.
        for buf in sorted(filled):
            m = re.search(r"\b" + re.escape(buf) + r"\s*\[\s*0?\s*\.\.\s*\w+\.(" +
                          COLLAPSING_ALT + r")\s*\(", text)
            if m:
                hits.append(
                    f"`{buf}` is filled with real input bytes and then sliced by an inline "
                    f"`{m.group(1)}` draw, which is the range minimum")
        # ── The two forms the literal `buf[0..n]` shape missed ──────────────
        #
        # Both were found by reading, not by the gate. `enip/fuzzFramer` carries
        # a written note that it had the identical defect and was NOT flagged,
        # because the collapsing length reached the buffer one level down. The
        # rule is not "the buffer is sliced by `n` from zero"; it is **the
        # extent of the drawn bytes is governed by a collapsing binding**, and
        # that governance has two other spellings in this tree.
        for buf in sorted(filled):
            # (a) a non-zero start: `buf[off..len]`, `parseFrame(buf[off..len])`
            #     in `websocket/fuzzParseFrameServer` and `mqtt/fuzzDecode`.
            #     `len` is 0, so the `while (off < len)` around it never runs.
            for n in sorted(collapsing):
                m = re.search(r"\b" + re.escape(buf) + r"\s*\[\s*(\w+)\s*\.\.\s*" +
                              re.escape(n) + r"\s*\]", text)
                if m and m.group(1) != "0":
                    hits.append(
                        f"`{buf}` is filled with real input bytes and then sliced as "
                        f"`{buf}[{m.group(1)}..{n}]`, and `{n}` comes from a bounded draw "
                        f"and is therefore the range minimum — an empty slice for every seed")
        # (b) the length never touches the buffer at all: it is the LOOP BOUND
        #     that decides whether the buffer is fed. `iec104` and `iec61850`'s
        #     framers, and `grpc/fuzzDeframerNeverPanics`:
        #         while (off < len) { f.feed(input[off..][0..chunk]) ... }
        #     `len` is 0, the loop body never executes, and the framer under
        #     test is handed nothing whatsoever.
        for n in sorted(collapsing):
            for m in re.finditer(r"\b(?:while|for|if)\s*\([^)]*?<=?\s*" +
                                 re.escape(n) + r"\b", text):
                tail = text[m.end():]
                fed = [b for b in sorted(filled)
                       if re.search(r"\b" + re.escape(b) + r"\s*\[", tail)]
                if fed:
                    hits.append(
                        f"`{n}` comes from a bounded draw and is therefore the range "
                        f"minimum, and it is the bound of the loop that feeds "
                        f"`{fed[0]}` — the body never executes, so no drawn byte "
                        f"ever reaches the code under test")
                    break
        # ── (c) the selector: it governs WHICH path runs, not how many bytes ──
        #
        # Found by an agent, and MEASURED rather than argued: it restored the
        # collapsed selector into an otherwise-fixed harness and the gate stayed
        # completely silent (`27 judged, 27 reach their input, 0 collapse`).
        #
        # `settinggroups.fuzzSgcb` drew `which` AFTER the byte draw and used it
        # as `sgcb_attributes[which]`. The seed is consumed by then, so `which`
        # is always 0 — every seed wrote to `NumOfSG`, which is read-only, and
        # the corpus would have measured "denied" twelve times having touched
        # nothing else. The gate listed that target for its buffer slicing only,
        # so fixing that half alone would have cleared it from the list with the
        # real hole intact.
        #
        # Neither other rule can see it: R1 inspects only the FIRST draw, and
        # every R2 form requires the collapsing binding to bound the extent of
        # drawn bytes. This one indexes a table of alternatives instead.
        if filled:
            for n in sorted(collapsing):
                m = re.search(r"\b(\w+)\s*\[\s*" + re.escape(n) + r"\s*\]", text)
                sw = re.search(r"\bswitch\s*\(\s*" + re.escape(n) + r"\s*\)", text)
                # ⚠ Not a defect when the SAME table is also iterated whole:
                # `btcp2p/fuzzDecodeMessage` picks a network magic to stamp and
                # then calls the decoder `for (nets) |n|` against all four
                # regardless, so a pinned `idx` costs no coverage. That was the
                # only instance in the tree when this rule landed, and it is a
                # false positive — kept as the rule's own lookalike control.
                iterated = m and re.search(
                    r"\bfor\s*\(\s*" + re.escape(m.group(1)) + r"\s*\)", text)
                if m and m.group(1) not in filled and not iterated:
                    hits.append(
                        f"`{n}` comes from a bounded draw and is therefore the range "
                        f"minimum, and it selects which alternative runs "
                        f"(`{m.group(1)}[{n}]`) — every seed takes the same branch")
                elif sw:
                    hits.append(
                        f"`{n}` comes from a bounded draw and is therefore the range "
                        f"minimum, and it is a `switch` discriminant — every seed "
                        f"takes the same branch")
    return sorted(set(hits))


# ---------------------------------------------------------------------------
# Module exemptions, in the shape `build.zig`'s `moduleFuzzExemption` reads.
# ---------------------------------------------------------------------------
NEEDLE = "**Fuzz-reach exemption:**"


def module_exemption(module: str):
    """(targets, error). `targets` is the set of exempt target names."""
    for name in ("SPEC.md", "README.md"):
        p = Path("modules") / module / name
        if p.exists():
            break
    else:
        return set(), None
    src = p.read_text(errors="replace")
    at = src.find(NEEDLE)
    if at < 0:
        return set(), None
    if src.find(NEEDLE, at + len(NEEDLE)) >= 0:
        return set(), f"{p}: states a fuzz-reach exemption twice"
    line = src[at + len(NEEDLE):src.find("\n", at) if src.find("\n", at) > 0 else len(src)].strip()
    if " via " not in line:
        return set(), (f"{p}: `{NEEDLE} {line}` names no targets; the form is "
                       f"`{NEEDLE} STRUCTURED via fuzzA, fuzzB`")
    reason, names = line.split(" via ", 1)
    if reason.strip() != "STRUCTURED":
        return set(), f"{p}: `{reason.strip()}` is not a reason word; the only one is STRUCTURED"
    after = src[src.find("\n", at):]
    stop = after.find("\n## ")
    if not after[:stop if stop >= 0 else len(after)].strip():
        return set(), f"{p}: the exemption states no argument for itself"
    return {n.strip().strip("`") for n in names.split(",") if n.strip()}, None


# ---------------------------------------------------------------------------


def scan():
    """(judged, unjudged, errors). Each judged entry is a dict."""
    judged, unjudged = [], []
    for p in sorted(Path("modules").rglob("*.zig")):
        # Cheap first: only ~1 file in 5 has a harness, and building the
        # function index for the rest is most of the wall time.
        if "testing.fuzz" not in p.read_text(errors="replace"):
            continue
        f = File(p)
        if not FUZZ_RE.search(f.src):
            continue
        module = p.parts[1]
        for m in FUZZ_RE.finditer(f.src):
            open_idx = m.end() - 1
            end = match_paren(f.src, open_idx)
            args = split_args(f.src[m.end():end - 1])
            line = f.line_of(m.start())
            if len(args) < 2:
                continue
            target = args[1].strip()
            if not re.fullmatch(r"[A-Za-z_][\w.]*", target):
                unjudged.append((str(p), line, "inline `struct { fn … }` target"))
                continue
            name = target.split(".")[-1]
            body = f.body(name)
            if body is None:
                unjudged.append((str(p), line, f"`{name}` is defined in another file"))
                continue
            carriers = smith_names(body, {"smith": None})
            carriers.update(f.carrier_params(name))
            draws = list(walk(f, body, carriers, 0, frozenset({name}), ""))
            bodies = [body]
            for d in draws:
                if d.via:
                    b = f.body(d.via)
                    if b is not None and b not in bodies:
                        bodies.append(b)
            judged.append({
                "path": str(p), "module": module, "line": line, "name": name,
                "draws": draws, "bodies": bodies, "file": f,
            })
    return judged, unjudged


def verdicts(judged):
    """Attach R1/R2 reasons to each judged target."""
    for t in judged:
        reasons = []
        draws = t["draws"]
        first = next((d for d in draws if d.kind != "weak"), None)
        if not draws:
            reasons.append(("R1", "the target makes no `Smith` draw at all, so the "
                                  "seed is never read"))
        elif first is None:
            pass  # only `eos` draws: weak, reported separately, not a failure
        elif first.kind == "collapsing":
            reasons.append(("R1", f"the first draw is {first}, which returns the range "
                                  f"minimum for all but 1 in 2^64 seeds"))
        if not any(r[0] == "R1" for r in reasons):
            for why in truncation_hits(t["bodies"]):
                reasons.append(("R2", why))
        t["reasons"] = reasons
        t["weak_only"] = bool(draws) and all(d.kind == "weak" for d in draws)
    return judged



# ---------------------------------------------------------------------------
# The ratchet.
#
# ⭐ WHY THIS EXISTS AND `--advisory` IS NOT ENOUGH. 356 of 474 targets collapsed
# when this gate landed, so it cannot fail the build yet — but a gate that never
# fails protects nothing, and the burn-down is being done a module at a time over
# many sessions. Without a ratchet, a module fixed in week one silently regresses
# in week three and the only signal is a count in an advisory report nobody reads.
#
# The baseline is per MODULE, not a single total. A total would let one module
# regress while another improves and still look green — the classic shape of a
# number that describes two different quantities at once.
#
# `--update-baseline` refuses to record a regression. Lowering the bar is a
# decision, not a maintenance step, and it must be made by editing the file and
# saying why in the commit.
BASELINE = Path("scripts/fuzz-reach-baseline.txt")


def read_baseline():
    if not BASELINE.exists():
        return None
    out = {}
    for line in BASELINE.read_text().splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        name, n = line.rsplit(None, 1)
        out[name] = int(n)
    return out


def write_baseline(counts, old):
    lines = [
        "# check-fuzz-reach: the per-module ceiling on collapsed fuzz targets.",
        "#",
        "# A module may not exceed its number here. Lowering a number is what the",
        "# burn-down does (`--update-baseline`); raising one is a decision that has",
        "# to be made by hand, in a commit that says why.",
        "#",
        "# Modules absent from this file must have ZERO collapsed targets.",
        "",
    ]
    for name in sorted(counts):
        if counts[name]:
            was = old.get(name) if old else None
            note = f"  # was {was}" if was is not None and was != counts[name] else ""
            lines.append(f"{name} {counts[name]}{note}")
    BASELINE.write_text("\n".join(lines) + "\n")


def main() -> int:
    ap = argparse.ArgumentParser(add_help=True, description=__doc__.split("\n")[0])
    ap.add_argument("--list", action="store_true",
                    help="print the burn-down: every flagged target, grouped by module")
    ap.add_argument("--advisory", action="store_true",
                    help="report and exit 0 (for wiring the gate before the burn-down is done)")
    ap.add_argument("--module", help="restrict to one module")
    ap.add_argument("--ratchet", action="store_true",
                    help="fail only where a module got WORSE than the committed "
                         "baseline; the burn-down's own gate")
    ap.add_argument("--update-baseline", action="store_true",
                    help="rewrite the baseline from the current counts (only ever "
                         "downwards; refuses to record a regression)")
    args = ap.parse_args()

    if not Path("modules").is_dir():
        print("check-fuzz-reach: run me from the repository root", file=sys.stderr)
        return 2

    judged, unjudged = scan()
    if args.module:
        judged = [t for t in judged if t["module"] == args.module]
        unjudged = [u for u in unjudged if Path(u[0]).parts[1] == args.module]
    verdicts(judged)

    errors = []
    exempt_by_module = {}
    for module in sorted({t["module"] for t in judged}):
        names, err = module_exemption(module)
        if err:
            errors.append(err)
        exempt_by_module[module] = names

    flagged, exempted = [], []
    for t in judged:
        if not t["reasons"]:
            continue
        (exempted if t["name"] in exempt_by_module.get(t["module"], ()) else flagged).append(t)

    # An exemption that names a target which is not flagged (or does not exist)
    # is stale, and a stale exemption is how the next one gets waved through.
    live = {(t["module"], t["name"]) for t in judged}
    flagged_names = {(t["module"], t["name"]) for t in judged if t["reasons"]}
    for module, names in exempt_by_module.items():
        for n in sorted(names):
            if (module, n) not in live:
                errors.append(f"modules/{module}: the fuzz-reach exemption names `{n}`, "
                              f"which is not a fuzz target in this module")
            elif (module, n) not in flagged_names:
                errors.append(f"modules/{module}: the fuzz-reach exemption for `{n}` is "
                              f"stale — that target reaches its input now; delete the line")

    weak = [t for t in judged if t["weak_only"]]

    counts = {}
    for t in flagged:
        counts[t["module"]] = counts.get(t["module"], 0) + 1

    if args.update_baseline:
        old = read_baseline()
        first = old is None
        old = old or {}
        # The first run records the world as it is; there is nothing to regress
        # against yet. Every run after that may only lower a ceiling.
        worse = [] if first else sorted(
            m for m, n in counts.items() if n > old.get(m, 0))
        if worse:
            print("check-fuzz-reach: refusing to record a regression in "
                  + ", ".join(f"{m} ({old.get(m, 0)} → {counts[m]})" for m in worse))
            print("Raising a ceiling is a decision. Edit "
                  f"{BASELINE} by hand and say why in the commit.")
            return 1
        write_baseline(counts, old)
        improved = sorted(m for m in old if old[m] > counts.get(m, 0))
        print(f"check-fuzz-reach: baseline updated — {len(improved)} module(s) "
              f"lowered, {sum(counts.values())} collapsed targets remain")
        for m in improved:
            print(f"  {m}: {old[m]} → {counts.get(m, 0)}")
        return 0

    if args.ratchet:
        base = read_baseline()
        if base is None:
            print(f"check-fuzz-reach: no baseline at {BASELINE}; run "
                  f"--update-baseline once to create it")
            return 1
        worse = sorted((m, base.get(m, 0), n) for m, n in counts.items()
                       if n > base.get(m, 0))
        total = sum(counts.values())
        if not worse:
            stale = sorted(m for m in base if base[m] > counts.get(m, 0))
            print(f"check-fuzz-reach: {total} collapsed targets, none above the "
                  f"baseline ({len(base)} module(s) tracked)")
            if stale:
                print(f"  {len(stale)} module(s) are now BELOW their baseline; run "
                      f"--update-baseline to lock the improvement in:")
                for m in stale:
                    print(f"    {m}: {base[m]} → {counts.get(m, 0)}")
            return 0
        print("check-fuzz-reach: collapsed fuzz targets went UP:")
        for m, was, now in worse:
            print(f"  {m}: {was} → {now}")
        print()
        print("A harness whose draw collapses replays every seed as one fixed")
        print("input. Run `./scripts/check-fuzz-reach.py --list --module <m>` to")
        print("see which target, and `modules/testkit/src/fuzz.zig` for the fix.")
        return 1

    if args.list:
        by_module = {}
        for t in flagged:
            by_module.setdefault(t["module"], []).append(t)
        for module in sorted(by_module):
            print(f"{module}  ({len(by_module[module])})")
            for t in sorted(by_module[module], key=lambda x: (x["path"], x["line"])):
                for rule, why in t["reasons"]:
                    print(f"    {t['path']}:{t['line']}  {t['name']}  [{rule}] {why}")
        print()

    n = len(judged)
    print(f"check-fuzz-reach: {n} fuzz targets judged in "
          f"{len({t['module'] for t in judged})} modules"
          f" ({len(unjudged)} could not be judged)")
    print(f"  reach their input   : {n - len(flagged) - len(exempted)}")
    print(f"  collapse (R1/R2)    : {len(flagged)} in "
          f"{len({t['module'] for t in flagged})} modules")
    if exempted:
        print(f"  exempt (STRUCTURED) : {len(exempted)} in "
              f"{len({t['module'] for t in exempted})} modules")
    if weak:
        print(f"  reach only via eos  : {len(weak)}  (one bit per input byte; not a failure)")
    for path, line, why in unjudged:
        print(f"  UNJUDGED {path}:{line}: {why}")

    if not flagged and not errors:
        return 0

    for e in errors:
        print(e)
    if errors:
        print()
        print(f"An exemption is one line in the module's own SPEC.md/README.md:")
        print(f"    {NEEDLE} STRUCTURED via fuzzA, fuzzB")
        print("followed by the argument it rests on, in prose.")
        print()

    if not args.list:
        for t in sorted(flagged, key=lambda x: (x["path"], x["line"]))[:20]:
            rule, why = t["reasons"][0]
            print(f"{t['path']}:{t['line']}: {t['name']}: [{rule}] {why}")
        if len(flagged) > 20:
            print(f"    … and {len(flagged) - 20} more; run "
                  f"`./scripts/check-fuzz-reach.py --list` for all of them")

    if flagged:
        print()
        print("A `Smith` ranged draw reads eight input bytes as a little-endian u64 and")
        print("returns the range MINIMUM unless that u64 already lies inside the range.")
        print("So a harness that opens with one — or that slices its drawn bytes to a")
        print("length that came from one — replays every seed as the same fixed input,")
        print("and a crash `--fuzz` finds cannot be reproduced from the seed it writes.")
        print()
        print("Fix, in order of preference:")
        print("  1. Draw the bytes FIRST, in ONE call: `const n = smith.slice(&buf);`")
        print("     and use `buf[0..n]`. Never `bytes` followed by a ranged length —")
        print("     `bytes` eats the rest of the seed and the length is then always 0.")
        print("     Worked example with the before/after measurement in its comment:")
        print("     modules/netaddr/src/root.zig, `fuzzParsePrefix`.")
        print("  2. If the knob must come first, draw it with `smith.value(u64)` and")
        print("     reduce it yourself (`% n`): `value` of a 64-bit type has full-range")
        print("     weights, so every input word survives.")
        print("  3. If the target draws a SHAPE and has no byte string to be faithful to,")
        print("     state it in the module's own SPEC.md/README.md, with the argument:")
        print(f"         {NEEDLE} STRUCTURED via fuzzA, fuzzB")

    return 0 if args.advisory and not errors else 1


if __name__ == "__main__":
    sys.exit(main())
