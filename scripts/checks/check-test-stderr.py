#!/usr/bin/env python3
"""check-test-stderr — a passing test must not write to stderr.

WHY THIS EXISTS
---------------
Every lane of the full matrix runs through scripts/lib/test-lib.sh, which
fails a step that exits 0 with anything on stderr ("OK-but-stderr -> treated
as FAIL"): four checkers had once reported success while complaining. The
price is that a test which narrates its success -- a "N cases replayed"
summary, a MEASURED line, a SKIP note -- passes everywhere a developer looks
(modtest merged stderr into its log until 2026-11-09; the push lane only
compiles) and turns the full CI red with every test green. That happened at
least ten times between 2026-08 and 2026-11 (six modules at once on
2026-09-10; dns SKIP, http, rsa wycheproof, df-elect + isis-sim MEASURED,
testkit stackprobe, and seven dataframe oracle replays in full CI
42636995236), each time costing a full-CI round, and each time "fixed" by a
note to remember. This makes it a checks-fast gate, so the push lane stops it.

WHAT IT CHECKS
--------------
In `modules/*/src/**/*.zig` (strings and comments blanked first), a write to
stderr -- `std.debug.print(`, `std.log.<level>(`, `std.debug.dumpHex(` --
that runs whenever its test runs:
  * in a `test` body, directly or in a loop / bare block of it (a loop body
    runs: df-elect's MEASURED line sat in `for (algorithms)`), or
  * in a function of the same file that prints that way and that a test calls
    that way (one level: rsa's wycheproof summary, bip340's stackprobe report).
Not counted, because a passing run does not reach it or it is the report of a
failure:
  * inside an `if`/`else`/`catch`/`orelse` body or a switch prong, or a loop
    whose header carries a condition (`for (xs) |x| if (c) { ... }`);
  * an `errdefer` print, or a print followed (after any further prints) by
    `return`;
  * after an earlier `continue`/`break` of an enclosing loop, a data return
    (`if (ok) return;`), or a skip that READS THE ENVIRONMENT -- an env var,
    `getenv`/`environ`, a live endpoint, `geteuid`, directly or through a
    same-file function (tfhe's `enabled()` reads TFHE_BENCH). That is how
    bench, live and opt-in tests stay off in CI.
A skip on the target, the mode or a constant (`builtin.os.tag != .linux`,
`builtin.mode == .Debug`, df-elect's `gate.fable_core_implemented`) does NOT
hide what follows: some lane of the matrix runs past it.
Verified on the files as they were before 14 past fixes: 13 flagged; clean on
the tree of 2026-11-09.

⛔ WHAT IT CANNOT SEE
--------------------
A data-dependent print that fires for an "expected" case (regex's Reader /
Longest lines, 40622c8b), stderr from a spawned process, helpers in another
file or two calls deep. `scripts/modtest` (lane mode) is the dynamic half: it
fails a green run whose build output before "Build Summary:" is not empty,
which is a passing step's stderr. Together they cover what the full lanes
enforce, before the full lanes run.
"""
import bisect
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PRINT_RE = re.compile(r'\bstd\s*\.\s*(?:debug\s*\.\s*(?:print|dumpHex)|log\s*\.\s*(?:err|warn|info|debug))\s*\(')
TEST_RE = re.compile(r'\btest\b\s*(?:"[^"\n]*"|[A-Za-z_][\w.]*)?\s*\{')
GUARD_RE = re.compile(r'\b(?:if|else|catch|orelse|and|or|while|for|switch)\b|=>')


LITERAL_RE = re.compile(r'//[^\n]*|\\\\[^\n]*|"(?:\\.|[^"\\\n])*"|\'(?:\\.|[^\'\\\n])*\'')


def _spaces(m: re.Match) -> str:
    s = m.group(0)
    if s.startswith('//'):
        return ' ' * len(s)
    keep = 2 if s.startswith('\\\\') else 1
    tail = 0 if keep == 2 else 1
    return s[:keep] + ' ' * (len(s) - keep - tail) + s[len(s) - tail:]


def blank(src: str) -> str:
    """Comments, strings and char literals blanked with spaces, offsets kept."""
    return LITERAL_RE.sub(_spaces, src)


def statement_start(text: str, pos: int, floor: int) -> int:
    """Start of the statement containing pos: after the last ; { or } at the same level."""
    k = pos - 1
    depth = 0
    while k > floor:
        ch = text[k]
        if ch in ')]':
            depth += 1
        elif ch in '([':
            if depth == 0:
                return k + 1
            depth -= 1
        elif depth == 0 and ch in ';{}':
            return k + 1
        k -= 1
    return floor


LOOP_HEADER_RE = re.compile(r'^(?:\w+\s*:\s*)?(?:inline\s+)?(?:for|while)\b')
COND_IN_HEADER_RE = re.compile(r'\b(?:if|else|catch|orelse|switch)\b|=>')
BARE_HEADER_RE = re.compile(r'^(?:\w+\s*:)?$')
BRACE_RE = re.compile(r'[{}]')
# An exit that can make the rest of a block conditional, and what kind it is.
EXIT_RE = re.compile(r'(?:\bif\b[^;{}]*\b|\borelse\s+|\bcatch\s+(?:\|\w+\|\s*)?)(?P<kind>return|continue|break)\b'
                     r'|\berror\s*\.\s*(?P<kind2>SkipZigTest)\b|\b(?P<kind3>return)\b')
# A gate that reads the environment: CI does not set it, so what follows does not run there.
ENV_GATE_RE = re.compile(r'(?i:getenv|environ|\benv\w*\s*\(|envvar|endpoint|geteuid|capabilit)|"[A-Z][A-Z0-9_]{3,}"')
# A gate on the target or the optimize mode: false in some lane of the matrix.
TARGET_GATE_RE = re.compile(r'\bbuiltin\b|\.mode\b|\bos\.tag\b|\bcpu\b|native_endian|\.arch\b|\btarget\b')
CALL_RE = re.compile(r'\b([A-Za-z_]\w*)\s*\(')
RETURN_RE = re.compile(r'\s*return\b')


def scan(path: Path):
    raw = path.read_text()
    if 'std' not in raw or 'test' not in raw:
        return []
    if 'debug.print' not in raw and 'debug.dumpHex' not in raw and 'log.' not in raw:
        return []  # cheap prefilter; the regex below decides
    text = blank(raw)
    if not PRINT_RE.search(text):
        return []
    # Brace positions and the depth just after each, for bisect lookups.
    pos, dep = [], []
    match = {}
    stack = []
    d = 0
    for bm in BRACE_RE.finditer(text):
        i = bm.start()
        if text[i] == '{':
            stack.append(i)
            d += 1
        elif stack:
            match[stack.pop()] = i
            d -= 1
        pos.append(i)
        dep.append(d)

    def depth_at(i: int) -> int:
        k = bisect.bisect_left(pos, i)  # braces strictly before i
        return dep[k - 1] if k else 0

    def enclosing(i: int) -> int:
        """The `{` of the innermost block containing offset i (-1 if none)."""
        k = bisect.bisect_left(pos, i) - 1
        closed = 0
        while k >= 0:
            if text[pos[k]] == '}':
                closed += 1
            elif closed:
                closed -= 1
            else:
                return pos[k]
            k -= 1
        return -1

    def runs_unconditionally(p: int, open_at: int, body_lo: int) -> bool:
        """Every block between the test body and p is a loop body or a bare block."""
        b = enclosing(p)
        while b > open_at:
            header = text[statement_start(text, b, body_lo):b].strip()
            is_loop = LOOP_HEADER_RE.match(header) and not COND_IN_HEADER_RE.search(header)  # not `for (x) |v| if (c) {`
            if not (is_loop or BARE_HEADER_RE.match(header)):
                return False  # an if/else/catch/orelse/switch prong, a fn or a type body
            b = enclosing(b)
        return b == open_at

    def chain(p: int, open_at: int):
        """The block openers from p's innermost block out to the test body."""
        out = []
        b = enclosing(p)
        while b >= open_at:
            out.append(b)
            if b == open_at:
                break
            b = enclosing(b)
        return out

    def statement_end(i: int) -> int:
        """Offset just past the `;` ending the statement that starts a call at i."""
        depth = 0
        k = i
        while k < len(text):
            ch = text[k]
            if ch in '([{':
                depth += 1
            elif ch in ')]}':
                depth -= 1
                if depth < 0:
                    return k
            elif ch == ';' and depth == 0:
                return k + 1
            k += 1
        return k

    def failure_path(p: int) -> bool:
        """The print (and any prints right after it) is followed by a `return`."""
        k = statement_end(p)
        while True:
            nxt = PRINT_RE.match(text, k + (len(text[k:]) - len(text[k:].lstrip())))
            if nxt:
                k = statement_end(nxt.start())
                continue
            return bool(RETURN_RE.match(text, k))

    def top_statement(e: int, block: int, body_lo: int):
        """Raw text of the statement directly inside `block` that contains offset e."""
        s = e
        while depth_at(s) > depth_at(block) + 1:
            s = enclosing(s)
        lo = statement_start(text, s, block + 1)
        return raw[lo:statement_end(lo)]

    fn_bodies = {}
    for fm in re.finditer(r'\bfn\s+([A-Za-z_]\w*)\s*\(', text):
        ob = text.find('{', fm.end())
        if ob >= 0 and ob in match:
            fn_bodies.setdefault(fm.group(1), raw[fm.start():match[ob] + 1])

    def reads_environment(stmt: str) -> bool:
        """The gate reads the environment, itself or through a function of this file
        it calls (tfhe's `enabled()` reads TFHE_BENCH; ebpf's `hasBpfCapability()` is
        `geteuid() == 0`). One level deep."""
        if ENV_GATE_RE.search(stmt):
            return True
        return any(ENV_GATE_RE.search(fn_bodies.get(c.group(1), '')) for c in CALL_RE.finditer(stmt))

    def guarded(p: int, blocks, body_lo: int) -> bool:
        """An earlier exit in p's own block chain makes p conditional.

        `continue`/`break` in an enclosing loop body, or a `return` on data
        (`if (ok) return;`): always. A `return` on the target or mode
        (`if (builtin.mode == .Debug) return;`): never, some lane runs past it. A skip
        (`error.SkipZigTest`, `testkit.skip`): only when that statement reads the
        environment -- an env var, `getenv`/`environ`, a live endpoint -- because
        that is how bench, live and opt-in tests stay off in CI. A gate on the
        target or mode (`builtin.os.tag != .linux`, `builtin.mode == .debug`) or on
        a constant (df-elect's `gate.fable_core_implemented`) is false in some lane,
        and the test prints there.
        """
        for e in EXIT_RE.finditer(text, body_lo, p):
            # The innermost block of p's chain that holds e (chain blocks nest).
            b = next((b for b in blocks if b < e.start()), None)
            if b is None:
                continue
            kind = e.group('kind') or e.group('kind2') or e.group('kind3')
            if kind in ('continue', 'break'):
                if enclosing(e.start()) == b:  # not an inner loop's own continue
                    return True
            else:
                after = text[e.end():e.end() + 80].lstrip()
                is_skip = kind == 'SkipZigTest' or re.match(r'(?i)(?:error\s*\.\s*SkipZigTest\b|[\w.]*skip\w*\s*\()', after)
                if is_skip:
                    stmt = top_statement(e.start(), b, body_lo)
                    if reads_environment(stmt):
                        return True  # a skip on the environment: off in CI
                    continue  # a skip on the target, mode or a constant: some lane runs past it
                if re.match(r'(?:;|null\b|true\b|false\b|\.[A-Za-z_]|\d)', after):
                    stmt = top_statement(e.start(), b, body_lo)
                    if TARGET_GATE_RE.search(stmt):
                        continue  # `if (builtin.mode == .Debug) return;`: other lanes run past it
                    return True  # a data-dependent early return: `if (ok) return;`
                # `return error.X`, `return err`, `return fail(...)`: the test fails there,
                # so a passing run goes on past it.
        return False

    def unconditional_at(p: int, open_at: int, after_lead: bool = True) -> bool:
        """Offset p runs whenever the block opened at open_at runs."""
        body_lo = open_at + 1
        # A loop body runs (df-elect's MEASURED line sat in `for (algorithms)`);
        # an if/else/catch/orelse/switch-prong body is a condition.
        if not runs_unconditionally(p, open_at, body_lo):
            return False
        st = statement_start(text, p, body_lo)
        lead = text[st:p]
        if GUARD_RE.search(lead) or re.search(r'\berrdefer\b', lead):
            return False
        if guarded(p, chain(p, open_at), body_lo):
            return False
        return True

    def unconditional_prints(open_at: int):
        end = match.get(open_at, len(text))
        for p in PRINT_RE.finditer(text, open_at + 1, end):
            # A print right before a `return` is the failure report of that return.
            if unconditional_at(p.start(), open_at) and not failure_path(p.start()):
                yield p.start()

    def line_of(i: int):
        line = raw.count('\n', 0, i) + 1
        return line, raw.splitlines()[line - 1].strip()

    # One level of calls: a function of this file that prints unconditionally,
    # called unconditionally by a test (rsa's wycheproof summary and bip340's
    # stackprobe report sat in helpers).
    printing_fns = {}
    for fm in re.finditer(r'\bfn\s+([A-Za-z_]\w*)\s*\([^{;]*?\{', text):
        ob = fm.end() - 1
        if ob in match:
            prints = list(unconditional_prints(ob))
            if prints:
                printing_fns.setdefault(fm.group(1), prints)

    hits = []
    seen = set()
    for m in TEST_RE.finditer(text):
        open_at = m.end() - 1
        for p in unconditional_prints(open_at):
            if p not in seen:
                seen.add(p)
                hits.append(line_of(p))
        if printing_fns:
            end = match.get(open_at, len(text))
            for c in CALL_RE.finditer(text, open_at + 1, end):
                name = c.group(1)
                if name in printing_fns and unconditional_at(c.start(), open_at):
                    for p in printing_fns[name]:
                        if p not in seen:
                            seen.add(p)
                            line, src = line_of(p)
                            hits.append((line, f"{src}  [in fn {name}, called by a test at line {line_of(c.start())[0]}]"))
    return hits


def main() -> int:
    total = 0
    # Arguments: files to scan instead of the tree (to check the checker on old revisions).
    files = [Path(a).resolve() for a in sys.argv[1:]] or sorted((ROOT / "modules").glob("*/src/**/*.zig"))
    for f in files:
        for line, src in scan(f):
            total += 1
            print(f"{f.relative_to(ROOT) if f.is_relative_to(ROOT) else f}:{line}: unconditional stderr in a test: {src[:120]}")
    if total:
        print(f"check-test-stderr: {total} unconditional stderr write(s) in tests -- every full CI lane fails a "
              f"passing test that writes to stderr (OK-but-stderr). Print only on a failure path, or assert instead.")
        return 1
    print(f"check-test-stderr: OK ({len(files)} files)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
