#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""check-changelog-entry — a module that changed substantially must say so in
its own CHANGELOG.md, in the same change-set.

THE RULE, in one sentence
-------------------------
A module owes a new dated `CHANGELOG.md` bullet whenever, under
`modules/<m>/src/`, the change-set touches a line that starts with `pub` or
moves more than 25 lines of code — where "code" excludes blank lines, comment
lines, whitespace-only differences, and everything inside a `test` block.

You can predict this gate by hand with two commands:

    git diff -w -U0 <base> -- modules/<m>/src   # what it measures
    git diff     -U0 <base> -- modules/<m>/CHANGELOG.md | grep '^+- \\*\\*20'

WHY THIS EXISTS
---------------
`zig build check-changelog` already proves every module HAS a well-formed,
dated changelog and that the root file's links resolve. It is a PRESENCE gate:
it reads the tree as it stands and never looks at a diff, so a module can have
its parser rewritten, its error set widened and a `pub fn` signature changed
while its changelog last moved six weeks ago — and the gate stays green,
because the file is still there and still well formed.

CONVENTIONS.md §8 already states the obligation this enforces: "a change to
behaviour or API is recorded newest first"; "Routine internal refactors need no
entry". §8 also explains why the obligation carries more weight here than in a
repo with a collection-wide version number — this collection deliberately has
none, and §8 says so in as many words: the per-module changelog "does not
supplement a collection version — it replaces it". A consumer of three modules
is told to answer "what changed for me" by reading three files. That promise is
only as good as the writing discipline behind it, and until now nothing
mechanical stood behind it at all.

WHY NOT A LINE THRESHOLD ALONE
------------------------------
Because it gets the two ends backwards. Widening a return type from `!void` to
`!Result` is one line and every consumer must recompile against it; renaming a
local and re-flowing a match is 200 lines and no consumer can observe it. So
the volume rule is kept — it is the only thing that catches a large behavioural
rewrite that happens to keep every signature — but it is the second of two
triggers, not the only one, and it counts a deliberately narrow kind of line.

WHAT COUNTS AS A "CODE LINE", AND WHY EACH EXCLUSION IS THERE
-------------------------------------------------------------
* **Whitespace-only differences are invisible** (`git diff -w`). A `zig fmt`
  sweep re-flows hundreds of lines and changes nothing a consumer can see. The
  repo's own pre-commit hook rests on the same property, and its self-test
  pins it: formatting is behaviour-preserving.
* **Blank and `//` comment lines do not count.** A doc-comment pass over a
  module is a doc change; §8 asks for entries about behaviour and API. (A
  doc-comment change that RENAMES a `pub` declaration still trips trigger 1,
  because the `pub` line itself moved.)
* **Lines inside a `test` block do not count.** This is the exclusion that
  matters most here and the one a generic tool would get wrong: in this
  collection tests do not live in a `test/` directory, they live in `test`
  blocks *inside* `modules/<m>/src/*.zig` — CONVENTIONS.md §7 puts them there
  on purpose ("Every test lives in the file it tests"). Counting them would
  make "added 60 lines of regression tests for a bug fixed last week" indis-
  tinguishable from "rewrote 60 lines of the parser", and the first of those
  is exactly the change most likely to be honestly entry-less. Blocks are
  found by brace-balancing from a `test` header in the file's own post-image
  (or pre-image, for removed lines), the same shape `check-skip-as-pass.py`
  uses.
* **`example/`, `README.md`, `SPEC.md`, `NOTICE` are not looked at at all.**
  Only `modules/<m>/src/` is measured. An example is a consumer, not the
  module; SPEC.md is documentation with its own gate.

WHAT SATISFIES THE OBLIGATION
-----------------------------
One added top-level bullet in `modules/<m>/CHANGELOG.md` of the form §8
mandates:

    - **YYYY-MM-DD** — what changed, for a reader who uses this module.

ADDED, not merely present — the gate reads the changelog's own diff. Appending
a paragraph to yesterday's entry does not count, and neither does re-wrapping
one: the unit §8 defines is the dated bullet, so that is the unit measured.

THE ESCAPE, AND WHY IT IS SHAPED LIKE THIS
------------------------------------------
Sometimes the trigger fires and no consumer can see anything: a 40-line
internal helper split out of a long function, a `pub` declaration that moved
between two files inside the module without changing its name or type. §8's
"Routine internal refactors need no entry" covers exactly that case and the
gate cannot tell it apart from a rewrite — nothing that reads a diff can.

So the escape is not a flag, an allow-list or a `--no-verify`: it is the
cheapest possible SATISFACTION of the rule, one dated bullet that says the
change is not visible from outside.

    - **2026-09-06** — **NO CONSUMER-VISIBLE CHANGE:** split the header
      decoder out of `parse` into `parseHeader`; identical bytes in, identical
      bytes out.

This is deliberately NOT special-cased in the code below. There is no marker to
match, no table of exempt modules, no per-run bypass file. The gate counts
added dated bullets and nothing else, so the escape cannot rot into a stale row
that exempts a module nobody remembers exempting — which is what happened to
the repo-level `FUZZ-EXEMPT.tsv` (retired 2026-08-14; its own header predicted
the wrong failure mode) and to the `**BREAKING` index in the root CHANGELOG.md
(removed the same day: "a check whose only subject is a copy is a closed loop").
A module states its own exemption in its own file, in the same place its real
entries live, and it costs one line to do it.

What keeps it visible is that this script COUNTS it. Every run prints how many
modules passed on a `NO CONSUMER-VISIBLE CHANGE` bullet and names them, so the
escape appears in the same gate output as the pass. `rg -c 'NO CONSUMER-VISIBLE
CHANGE' modules/*/CHANGELOG.md` answers "how much is this being leaned on"
across the whole collection at any time, from the tree, with no second place to
keep in sync.

WHAT IT COMPARES AGAINST
------------------------
    check-changelog-entry.py                # base HEAD, tip = working tree
    check-changelog-entry.py <BASE_REF>     # base BASE_REF, tip = working tree
    check-changelog-entry.py --staged       # base HEAD, tip = the INDEX
    check-changelog-entry.py --commit REV   # judge REV alone (REV^..REV)

**The base-ref form is the authoritative one.** It is what CI runs, over the
whole push or pull-request range, and it is the only form that judges a branch
as the unit a reader eventually sees. The other three are conveniences with a
narrower question, and each can legitimately disagree with it:

* `--staged` (the pre-commit hook) judges ONE commit. A branch that writes its
  changelog entry in commit 3 has commits 1 and 2 refused by the hook and
  accepted by CI. That is the hook being early, not the hook being right, and
  `git commit --no-verify` is the documented answer — the same answer the fmt
  hook gives.
* the default form judges uncommitted work only, which is what a developer
  running `scripts/test.sh` with no argument is asking about. Its base is
  `HEAD`, deliberately NOT the merge-base with `origin/main`: this repository
  commits to `main` and pushes in batches (64 unpushed commits at the time of
  writing), so a merge-base default would re-judge two months of finished work
  every time anyone ran the local gate, and a gate that is red for something
  you did not do is a gate people learn to pass with `--no-verify`.

A base ref that does not resolve is an ERROR, never an empty diff. `test.sh`
learned that the hard way and says so at `changed_files()`: a force-push, a
shallow clone with no merge base, or an all-zero `github.event.before` makes
`git diff` fail, and a swallowed failure reads as "nothing changed" — a gate
that checked nothing and exited 0.

⛔ WHAT IT CANNOT SEE
--------------------
* **A multi-line signature.** `zig fmt` breaks a long `pub fn` across lines;
  changing a parameter three lines down leaves the `pub fn foo(` line itself
  untouched, so trigger 1 misses it and only the 25-line volume rule can catch
  it. Anchoring on a real parse of the declaration would fix this and needs a
  Zig-side implementation, not a Python one.
* **A field added to a `pub const T = struct`.** The field line does not start
  with `pub`. Same fix, same reason it is not here.
* **Whether the entry is TRUE.** It reads that a dated bullet was added, not
  what it says. An entry reading "." passes. That is not a hole this gate can
  close — no gate can — and it is why the error message below spells out what
  the entry is for rather than only that one is required.
* **A behavioural change of two code lines with no `pub` line touched.** Below
  both triggers by construction. The threshold buys predictability at the cost
  of a floor; 25 was calibrated against this repository's own history (see
  CALIBRATION below) rather than picked.

CALIBRATION, and what the replay found
--------------------------------------
Replayed over the 120 most recent commits at the time of writing (this history
is linear — there are no merge commits to replay). Two shapes, because the two
comparison modes ask different questions:

* **Per commit** (`--commit <rev>`, the hook's question): 32 of 120 commits go
  red. 146 (commit, module) pairs touched a module's `src/` at all, so ~78 % of
  the pairs that could have tripped a trigger did not.
* **Per 10-commit window** (`--commit A..B`, the authoritative question, an
  approximation of a push range): 7 of 12 windows go red, on 16
  (window, module) pairs. The other 5 windows are green with 40 modules that
  DID trip a trigger and DID record it.

The split between those two groups is not random and it is the strongest
evidence here: **the 5 green windows are the 50 most recent commits** — the
audit campaign, which records every module it touches — and the 7 red ones are
the older performance campaign. Every one of the 16 flags was read by hand and
every one is a real omission, not a threshold artefact. Four spot-checks, each
a `pub` declaration that is in the tree today and appears in NO changelog in
the collection: `http.setHeaderStatic`, `cors.applyPreflight` (with
`applyActualStatic`, `isPreflight`, `StaticOptions`), `h1.parseContentLengthStrict`,
and `ssh.max_packets_per_direction` — the last of which is the cap that stops a
sequence number wrapping into a repeated ChaCha nonce. `modules/cors/CHANGELOG.md`
stops at 2026-08-18 and four later commits moved its public surface.

**Why 25, and how much it matters:** less than it looks. Sweeping the threshold
over the same 12 windows gives 7 red windows at 10, 15 AND 25, and 5 at both 40
and 60. So 25 sits in the middle of a plateau — the verdict does not move
across a 2.5× range of the number, which is what you want from a threshold
nobody should have to argue about. Below 25 it adds 4 more flags (all real, all
in the same red windows, so they change no verdict); at 40 it loses three real
ones — `accesslog`'s new `trace_id`/`span_id` fields (28), a `devlink` encoding
change (26), and `p256`'s field-arithmetic rewrite (35). 25 is the largest
value that keeps all three.
"""
import argparse
import re
import subprocess
import sys
from pathlib import Path

# Trigger 2's threshold: added+removed code lines under modules/<m>/src/.
# See CALIBRATION in the module docstring — this is measured against this
# repository's history, not chosen for roundness.
CODE_LINES = 25

# Trigger 1: a changed line that begins a published declaration.
PUB_RE = re.compile(r"^pub\b")

# CONVENTIONS.md §8: "The form is exactly `- **YYYY-MM-DD** — the entry text`".
# The same `20YY-MM-DD` shape `scripts/tag.sh` accepts, so there is one date
# format in this repo and not two.
ENTRY_RE = re.compile(r"^\+\s*-\s+\*\*(20\d\d-\d\d-\d\d)\*\*")

ESCAPE = "NO CONSUMER-VISIBLE CHANGE"

HUNK_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
TEST_RE = re.compile(r"^\s*test\s+[\"\w]")


def git(*args, check=True):
    p = subprocess.run(["git", *args], capture_output=True, text=True)
    if check and p.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed: {p.stderr.strip()}")
    return p.stdout


def test_block_lines(text):
    """Line numbers (1-based) inside a `test` block, brace-balanced.

    Same shape as `check-skip-as-pass.py`'s `blocks()`: walk from a line that
    opens a `test` header and follow the brace depth until it returns to zero.
    A `test` block's own header line is included — deleting the whole block is
    a test change, not an API change.
    """
    inside = set()
    lines = text.split("\n")
    i = 0
    while i < len(lines):
        if not TEST_RE.match(lines[i]):
            i += 1
            continue
        depth, started = 0, False
        j = i
        while j < len(lines):
            depth += lines[j].count("{") - lines[j].count("}")
            inside.add(j + 1)
            if lines[j].count("{"):
                started = True
            if started and depth <= 0:
                break
            j += 1
        i = j + 1
    return inside


def blob(rev, path):
    """A file's text at `rev`, or from the working tree when rev is None."""
    if rev is None:
        try:
            return Path(path).read_text(errors="replace")
        except OSError:
            return ""
    if rev == ":":  # the index
        p = subprocess.run(["git", "show", f":{path}"], capture_output=True, text=True)
    else:
        p = subprocess.run(["git", "show", f"{rev}:{path}"], capture_output=True, text=True)
    return p.stdout if p.returncode == 0 else ""


class Range:
    """One base..tip pair, and how to ask git about it.

    `tip` is None for the working tree, ":" for the index, or a revision.
    """

    def __init__(self, base, tip):
        self.base, self.tip = base, tip

    def diff(self, *extra, paths=()):
        args = ["diff", "--no-color", "-U0", *extra]
        if self.tip == ":":
            args += ["--cached", self.base]
        elif self.tip is None:
            args += [self.base]
        else:
            args += [self.base, self.tip]
        if paths:
            args += ["--", *paths]
        return git(*args)

    def untracked(self, prefix):
        """New files git has not been told about yet — invisible to `git diff`.

        `test.sh`'s `changed_files()` folds these in for the same reason: a
        brand-new module is entirely untracked, and a gate that cannot see it
        would let the largest possible change through as "nothing changed".
        Only meaningful when the tip is the working tree.
        """
        if self.tip is not None:
            return []
        out = git("ls-files", "--others", "--exclude-standard", "--", prefix)
        return [f for f in out.split("\n") if f]


def src_churn(rng, module):
    """(code lines moved, [changed pub lines]) under modules/<m>/src/."""
    prefix = f"modules/{module}/src"
    # -w: a whitespace-only difference is not a change. -U0: no context lines,
    # so every +/- line in the output is a real change and the hunk headers
    # give exact line numbers on both sides.
    text = rng.diff("-w", paths=[prefix])

    old_path = new_path = None
    old_ln = new_ln = 0
    old_tests, new_tests = set(), set()
    count, pubs = 0, []

    def consider(line, body, is_test):
        nonlocal count
        s = body.strip()
        if not s or s.startswith("//") or is_test:
            return
        count += 1
        if PUB_RE.match(s):
            pubs.append((new_path or old_path, line, s))

    for line in text.split("\n"):
        if line.startswith("--- "):
            old_path = line[4:].removeprefix("a/")
            old_tests = test_block_lines(blob(rng.base, old_path)) if old_path != "/dev/null" else set()
            continue
        if line.startswith("+++ "):
            new_path = line[4:].removeprefix("b/")
            new_tests = test_block_lines(blob(rng.tip, new_path)) if new_path != "/dev/null" else set()
            continue
        m = HUNK_RE.match(line)
        if m:
            old_ln, new_ln = int(m.group(1)), int(m.group(3))
            continue
        if line.startswith("+"):
            consider(new_ln, line[1:], new_ln in new_tests)
            new_ln += 1
        elif line.startswith("-"):
            consider(old_ln, line[1:], old_ln in old_tests)
            old_ln += 1

    for f in rng.untracked(prefix + "/"):
        if not f.endswith(".zig"):
            continue
        body = Path(f).read_text(errors="replace")
        tests = test_block_lines(body)
        for n, s in enumerate(body.split("\n"), 1):
            t = s.strip()
            if not t or t.startswith("//") or n in tests:
                continue
            count += 1
            if PUB_RE.match(t):
                pubs.append((f, n, t))

    return count, pubs


def entries_added(rng, module):
    """([dates added], [dates whose entry uses the escape])."""
    path = f"modules/{module}/CHANGELOG.md"
    text = rng.diff(paths=[path])
    if not text.strip() and path in rng.untracked(f"modules/{module}/"):
        # A new module: nothing to diff against, so the whole file is "added".
        text = "\n".join("+" + l for l in Path(path).read_text(errors="replace").split("\n"))

    dates, escaped = [], []
    lines = text.split("\n")
    for i, line in enumerate(lines):
        m = ENTRY_RE.match(line)
        if not m:
            continue
        dates.append(m.group(1))
        # The escape marker may wrap onto the entry's continuation lines, so
        # read to the next added bullet (or the end of the added run).
        j, body = i, []
        while j < len(lines) and (j == i or (lines[j].startswith("+") and not ENTRY_RE.match(lines[j]))):
            body.append(lines[j])
            j += 1
        if ESCAPE in " ".join(body):
            escaped.append(m.group(1))
    return dates, escaped


def touched_modules(rng):
    names = set()
    text = rng.diff("--name-only")
    files = [f for f in text.split("\n") if f]
    files += rng.untracked("modules/")
    for f in files:
        parts = f.split("/")
        # `_template` is not in `module_list` and `check-changelog` does not
        # ask it for anything; nor does this.
        if len(parts) > 2 and parts[0] == "modules" and parts[1] != "_template":
            names.add(parts[1])
    return sorted(names)


def resolve(rev):
    p = subprocess.run(
        ["git", "rev-parse", "--verify", "--quiet", f"{rev}^{{commit}}"],
        capture_output=True, text=True,
    )
    return p.stdout.strip() or None


def main():
    ap = argparse.ArgumentParser(add_help=True, description=__doc__.split("\n")[0])
    ap.add_argument("base", nargs="?", default=None,
                    help="base ref (default HEAD). The authoritative form: CI passes the push/PR base.")
    ap.add_argument("--staged", action="store_true",
                    help="compare the INDEX against the base — what scripts/hooks/pre-commit uses")
    ap.add_argument("--commit", metavar="REV",
                    help="judge REV alone (REV^..REV), or a range written A..B, for replaying history")
    ap.add_argument("--quiet", action="store_true",
                    help="print nothing when the verdict is a pass (used by the pre-commit hook)")
    args = ap.parse_args()

    if args.commit:
        # `A..B` judges a whole range as one unit — the shape CI's
        # authoritative run has, replayed over history. A bare `REV` is the
        # single-commit case, which is what the pre-commit hook approximates.
        if ".." in args.commit:
            lo, hi = args.commit.split("..", 1)
            base, tip = resolve(lo), resolve(hi or "HEAD")
        else:
            tip = resolve(args.commit)
            base = resolve(f"{args.commit}^") if tip else None
            if tip is not None and base is None:  # the root commit: the empty tree
                base = git("hash-object", "-t", "tree", "/dev/null").strip()
        if tip is None or base is None:
            print(f"check-changelog-entry: '{args.commit}' does not resolve here", file=sys.stderr)
            return 2
        rng = Range(base, tip)
        where = f"{args.commit}"
    else:
        base = resolve(args.base or "HEAD")
        if base is None and args.base is None:
            # An unborn branch: `HEAD` names no commit yet, so the base is the
            # empty tree and everything staged is an addition. This is NOT the
            # unresolvable-ref case below — nothing was asked for that could
            # not be found, and refusing here would make the hook block the
            # very first commit of any checkout.
            base = git("hash-object", "-t", "tree", "/dev/null").strip()
        if base is None:
            # ⚠ Never an empty diff. See WHAT IT COMPARES AGAINST.
            print(f"check-changelog-entry: base ref '{args.base}' does not resolve here.", file=sys.stderr)
            print("  Refusing to report 'nothing changed' for a ref this checkout cannot see —", file=sys.stderr)
            print("  a shallow clone, a force-push or an all-zero `before` SHA looks exactly", file=sys.stderr)
            print("  like a clean tree if this is swallowed. Fetch the ref, or pass one that", file=sys.stderr)
            print("  resolves.", file=sys.stderr)
            return 2
        rng = Range(base, ":" if args.staged else None)
        where = ("the index" if args.staged else "the working tree") + f" vs {args.base or 'HEAD'}"

    owed, escaped_ok, ok = [], [], []
    for m in touched_modules(rng):
        lines, pubs = src_churn(rng, m)
        if not pubs and lines <= CODE_LINES:
            continue
        dates, esc = entries_added(rng, m)
        why = []
        if pubs:
            why.append(f"{len(pubs)} published declaration line(s) changed")
        if lines > CODE_LINES:
            why.append(f"{lines} code lines moved under src/ (threshold {CODE_LINES})")
        if dates:
            (escaped_ok if esc else ok).append((m, dates[0]))
        else:
            owed.append((m, "; ".join(why), pubs[:3]))

    if owed:
        print(f"check-changelog-entry: {len(owed)} module(s) changed substantially and added no changelog entry.")
        print(f"  (comparing {where})")
        print()
        for m, why, pubs in owed:
            print(f"  modules/{m}/ — {why}")
            for path, ln, text in pubs:
                print(f"      {path}:{ln}: {text[:96]}")
        print()
        print("CONVENTIONS.md §8: a change to behaviour or API is recorded newest first in")
        print("the module's own changelog. Add ONE bullet at the top of the `## Unreleased`")
        print("section, using exactly the §8 form — the date first, any bold tag after it:")
        print()
        for m, _, _ in owed:
            print(f"  modules/{m}/CHANGELOG.md")
        print()
        print("    ## Unreleased")
        print()
        print("    - **YYYY-MM-DD** — what a consumer of this module can now do, or must now")
        print("      do differently. Prefix **BREAKING:** if they must change their code, or")
        print("      **BEHAVIOURAL, not breaking** if it still compiles but behaves anew.")
        print()
        print("If the change genuinely cannot be seen from outside the module — an internal")
        print("split, a helper moved between files — say that, in the same one-line form. It")
        print("is a real entry, it is dated, and this gate prints every time it is used:")
        print()
        print(f"    - **YYYY-MM-DD** — **{ESCAPE}:** <what moved, and why")
        print("      nothing a consumer can observe did>")
        print()
        print("Reproduce this verdict by hand for any module:")
        print(f"    git diff -w -U0 {rng.base[:12]} -- modules/<m>/src")
        print(f"    git diff    -U0 {rng.base[:12]} -- modules/<m>/CHANGELOG.md | grep '^+- \\*\\*20'")
        return 1

    if not args.quiet:
        total = len(ok) + len(escaped_ok)
        print(f"check-changelog-entry: {total} module(s) changed substantially, all {total} recorded it "
              f"({where})")
        for m, d in ok:
            print(f"  ok      modules/{m}/CHANGELOG.md  {d}")
        # The escape is never silent: it is named here, every run, next to the
        # ordinary passes it is standing in for.
        for m, d in escaped_ok:
            print(f"  ESCAPE  modules/{m}/CHANGELOG.md  {d}  ({ESCAPE})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
