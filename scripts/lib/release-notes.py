#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""release-notes — the message of a dated tag, computed from git.

    python3 -I scripts/lib/release-notes.py <prev-ref> <new-ref>
    python3 -I scripts/lib/release-notes.py --claim <new-ref>
    python3 -I scripts/lib/release-notes.py --self-test

CONVENTIONS §8: a tag message says what moved since the previous tag, and any
number in it is computed. The `2026-08-24` message, written by hand, claimed 5
commits where the range held 143. Everything here comes out of `git`: the same two
refs give the same bytes.

The text comes from the module changelogs, because only the author of a change
knows what a consumer notices. A bullet counts as added when no bullet of the
previous version starts the same way, so a later edit to an old entry's tail does
not make it new. Classified by its bold labels, as written across the collection:
BREAKING; CONSUMER-VISIBLE (with BEHAVIOURAL, ADDITIVE, API CHANGE and SECURITY, each
of which §8 or the changelogs use for something a consumer can see); other changes (Added,
New, Fix, Fixed, Changed), below those; NO CONSUMER-VISIBLE CHANGE and bullets that only
record a no-panic sweep, counted; everything else counted too. The output is capped at
MAX_BYTES, the lowest group first, with a pointer to the changelogs.

Bullets are Markdown that lands in a Release, so backticks stay and everything outside
a code span is neutralised: no bullet can mention a user or link an issue.
"""
import collections
import os
import re
import subprocess
import sys
import tempfile

MAX_BYTES = 60000  # a Release body is capped at 125000 characters; stay far below
GRADES_BUDGET = MAX_BYTES // 5

GRADE_RE = re.compile(r"^\*\*Grade:\*\*\s+(\S+)", re.M)
ENTRY_RE = re.compile(r"^- \*\*(20\d\d-\d\d-\d\d)\*\*\s*(?:—|--|-)?\s*(.*)$")
# `**BEHAVIOURAL, not breaking**` is a third classification (CONVENTIONS §8).
BREAKING_RE = re.compile(r"\*\*(?:[^*]{0,40}\s)?(?<!not )BREAKING\b", re.I)
NOT_VISIBLE_RE = re.compile(r"NO CONSUMER-VISIBLE")
SWEEP_RE = re.compile(r"no-panic sweep", re.I)
CHANGED_RE = re.compile(r"\*\*(?:Added|New|Fix|Fixes|Fixed|Changed)\b")
SPAN_RE = re.compile(r"(`[^`]*`)")
# What GitHub would link: `@user`, `#12`, `o/r#12`, `GH-12`. verify_bundle in
# auto-release.sh refuses the same shapes in a tag message.
MENTION_RE = re.compile(r"[@#][A-Za-z0-9]|\bGH-\d")
TOKEN_RE = re.compile(r"(\S*(?:[@#][A-Za-z0-9]|\bGH-\d)\S*)")
MARKDOWN_RE = re.compile(r"([\\*_\[\]<>~|!])")
VISIBLE_RE = re.compile(r"\*\*(?:CONSUMER-VISIBLE|BEHAVIOU?RAL|ADDITIVE|API CHANGE|Behaviou?r change|SECURITY)", re.I)


def git(*args, check=True):
    p = subprocess.run(["git", *args], capture_output=True)
    if check and p.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)}: {p.stderr.decode('utf-8', 'replace').strip()}")
    return p.stdout.decode("utf-8", "replace") if p.returncode == 0 else None


def show(ref, path):
    return git("show", f"{ref}:{path}", check=False)


def modules_at(ref):
    out = git("ls-tree", "-d", "--name-only", f"{ref}:modules", check=False) or ""
    return {m for m in out.split("\n") if m and not m.startswith("_")}


def grade_at(ref, module):
    for name in ("SPEC.md", "README.md"):
        text = show(ref, f"modules/{module}/{name}")
        if text:
            m = GRADE_RE.search(text)
            if m:
                return m.group(1)
    return None


def entries(text):
    """Top-level dated bullets: [(date, body)], continuation lines folded in."""
    out, cur = [], None
    for line in (text or "").split("\n"):
        m = ENTRY_RE.match(line)
        if m:
            cur = [m.group(1), [m.group(2)]]
            out.append(cur)
        elif line.startswith("- ") or line.startswith("#"):
            cur = None
        elif cur is not None and line.strip():
            cur[1].append(line.strip())
    return [(d, " ".join(b)) for d, b in out]


def identity(body):
    return " ".join(body.split())[:100]


def added_entries(old_text, new_text):
    seen = collections.Counter(identity(b) for _, b in entries(old_text))
    added = []
    for date, body in entries(new_text):
        key = identity(body)
        if seen[key] > 0:
            seen[key] -= 1
        else:
            added.append((date, body))
    return added


def classify(body):
    head = body[:300]
    if BREAKING_RE.search(head):
        return "breaking"
    if NOT_VISIBLE_RE.search(head):
        return "none"
    if SWEEP_RE.search(head[:120]):
        return "sweep"
    if VISIBLE_RE.search(head):
        return "visible"
    if CHANGED_RE.search(head):
        return "changed"
    return "other"


def neutralise(text):
    """Markdown that can mention nobody and link nothing, code spans untouched."""
    out = []
    for i, part in enumerate(SPAN_RE.split(text)):
        if i % 2:
            out.append(part)
            continue
        # A token with a mention in it becomes a code span of its own, which reads
        # the same and which GitHub does not link.
        for j, piece in enumerate(TOKEN_RE.split(part.replace("`", "'"))):
            out.append(f"`{piece}`" if j % 2 else MARKDOWN_RE.sub(r"\\\1", piece))
    return "".join(out)


def summary(body, limit=200):
    parts = SPAN_RE.split(" ".join(body.split()))
    text = "".join(p if i % 2 else p.replace("**", "") for i, p in enumerate(parts))

    def close(cut):
        # A cut inside a code span would leave it open: give that span up whole.
        return cut[: cut.rindex("`")].rstrip() if cut.count("`") % 2 else cut

    m = re.search(r"[.;](?:\s|$)", text[40:])
    if m:
        text = close(text[: 40 + m.start() + 1])
    if len(text.encode()) > limit:
        text = close(text.encode()[:limit].decode("utf-8", "ignore").rstrip()) + "…"
    return neutralise(text)


def claim(new):
    sha = git("rev-parse", f"{new}^{{commit}}").strip()
    return (
        f"Every module passed every CI lane at {sha} (ReleaseSafe and ReleaseFast on amd64, "
        "ReleaseSafe on arm64, examples, strict-Debug compile), directly or by a green stamp "
        "for its unchanged fingerprint; a red verdict withdraws this tag. That is the whole "
        "claim: a dated snapshot of the collection, not a semantic version. Per-module changes "
        "are in each module's CHANGELOG.md; see CONVENTIONS.md §8."
    )


def bounded(lines, budget):
    """(the lines that fit, how many did not)."""
    out, used = [], 0
    for i, line in enumerate(lines):
        size = len(line.encode()) + 1
        if used + size > budget:
            return out, len(lines) - i
        out.append(line)
        used += size
    return out, 0


def notes(prev, new, max_bytes=MAX_BYTES):
    count = int(git("rev-list", "--count", f"{prev}..{new}").strip())
    old_mods, new_mods = modules_at(prev), modules_at(new)
    created, removed = sorted(new_mods - old_mods), sorted(old_mods - new_mods)
    changed = git("diff", "--name-only", prev, new, "--", "modules").split("\n")
    touched = collections.defaultdict(set)
    for path in changed:
        parts = path.split("/")
        if len(parts) == 3 and parts[1] in new_mods:
            touched[parts[1]].add(parts[2])

    raised, lowered = [], []
    for m in sorted(touched):
        if m in created or not touched[m] & {"SPEC.md", "README.md"}:
            continue
        a, b = grade_at(prev, m), grade_at(new, m)
        if a is None or b is None or a == b:
            continue
        # Lower is better; a `?` (provisional) sorts after the plain number.
        (raised if (b.rstrip("?"), b) < (a.rstrip("?"), a) else lowered).append(f"{m} {a} -> {b}")

    groups = {"breaking": [], "visible": [], "changed": []}
    counts = collections.Counter()
    for m in sorted(touched):
        if "CHANGELOG.md" not in touched[m]:
            continue
        old = show(prev, f"modules/{m}/CHANGELOG.md")
        for date, body in added_entries(old, show(new, f"modules/{m}/CHANGELOG.md")):
            kind = classify(body)
            counts[kind] += 1
            if kind in groups:
                groups[kind].append(f"- **{m}** ({date}): {summary(body)}")
    total = sum(counts.values())

    head = [f"{count} commit{'' if count == 1 else 's'} since {prev}.", "", claim(new), ""]
    if created:
        head += [f"## New modules ({len(created)})", ""]
        head += [", ".join(f"{m} (grade {grade_at(new, m) or '?'})" for m in created), ""]
    if removed:
        head += [f"## Removed modules ({len(removed)})", "", ", ".join(removed), ""]
    if raised or lowered:
        head += [f"## Grade changes ({len(raised)} better, {len(lowered)} worse; 1 is best)", ""]
        grade_lines, cut = bounded(
            ([f"Better: {', '.join(raised)}"] if raised else []) + ([f"Worse: {', '.join(lowered)}"] if lowered else []),
            GRADES_BUDGET,
        )
        head += grade_lines + ([f"({cut} line(s) more: see each module's SPEC.md)"] if cut else []) + [""]
    head += [
        f"## Changelog bullets added: {total}",
        "",
        f"{counts['breaking']} BREAKING, {counts['visible']} consumer-visible, "
        f"{counts['changed']} other change{'' if counts['changed'] == 1 else 's'}, "
        f"{counts['none']} marked no consumer-visible change, {counts['sweep']} sweep-only, "
        f"{counts['other']} other (the last three counted, not listed).",
        "",
    ]

    # BREAKING first, because it is the group that may not be lost to the budget.
    reserve = 300  # the truncation pointer always fits
    budget = max_bytes - len("\n".join(head).encode()) - reserve
    body, omitted = [], collections.Counter()
    for kind, title in (("breaking", "BREAKING"), ("visible", "CONSUMER-VISIBLE"), ("changed", "Other changes")):
        if not groups[kind]:
            continue
        section = [f"### {title} ({counts[kind]})", ""]
        budget -= len("\n".join(section).encode()) + 1
        kept, cut = bounded(groups[kind], max(budget, 0))
        budget -= sum(len(k.encode()) + 1 for k in kept)
        body += section + kept + [""]
        omitted[title] = cut
    if sum(omitted.values()):
        detail = ", ".join(f"{n} {t}" for t, n in omitted.items() if n)
        body += [f"Truncated: {detail} not listed. Every entry is in modules/<name>/CHANGELOG.md.", ""]
    return "\n".join(head + body).rstrip() + "\n"


def self_test():
    fails = []

    def expect(label, cond):
        if not cond:
            fails.append(label)

    # Parsing, on the real shapes.
    text = (
        "# m — changelog\n\nNewest first.\n\n## Unreleased\n\n"
        "- **2026-10-20** — **BREAKING:** `f` takes a slice.\n  Second line.\n\n"
        "  Paragraph.\n"
        "  - nested bullet belongs elsewhere\n"
        "- **2026-10-19** — **CONSUMER-VISIBLE (additive):** new `g`.\n"
        "- **2026-10-18** — **NO CONSUMER-VISIBLE CHANGE:** moved a helper.\n"
        "- **2026-10-17** — **BEHAVIOURAL, not breaking:** rejects more input.\n"
        "- **2026-10-16** — Fix: plain words.\n"
        "- not dated\n"
    )
    es = entries(text)
    expect("five dated bullets", len(es) == 5)
    expect("continuation folded", "Second line" in es[0][1] and "Paragraph" in es[0][1])
    expect("classes", [classify(b) for _, b in es] == ["breaking", "visible", "none", "visible", "other"])
    expect("'not breaking' is not BREAKING", classify("**BEHAVIOURAL, not breaking:** x") == "visible")
    expect("a security fix is listed", classify("**SECURITY:** bounds") == "visible")
    expect("Added is the third group", classify("**Added:** `f`") == "changed")
    expect("New is the third group", classify("**New:** `f`") == "changed")
    expect("Fixed is the third group", classify("**Fixed:** a thing") == "changed")
    expect("Changed is the third group", classify("**Changed:** a thing") == "changed")
    expect("a bare sweep is counted", classify("**CONSUMER-VISIBLE (fixes only):** no-panic sweep + blind review (§ GU).") == "sweep")
    expect("a bare sweep is counted, Fix too", classify("**Fix (no-panic sweep):** no consumer-reachable panic.") == "sweep")
    expect("a BREAKING sweep stays listed", classify("**BREAKING:** no-panic sweep + blind review (§ GT).") == "breaking")
    # The real bullet, modules/dns/CHANGELOG.md, 2026-10-24.
    real = ("**NO CONSUMER-VISIBLE CHANGE:** the `strRepeat` helper (the Zig 0.17 stand-in for `**`) builds its "
            "string with one `@splat` + `@bitCast` instead of a comptime loop.")
    got = summary(real)
    expect("code spans keep their backticks", "`@splat`" in got and "`@bitCast`" in got and "`**`" in got)
    expect("no bare mention", not MENTION_RE.search(re.sub(r"`[^`]*`", "", got)))
    for raw in ("thanks @someone for this", "see #123 and o/r#9", "GH-12 again", "a@b.example", "@a`b`@c"):
        expect(f"no mention or link in {raw!r}", not MENTION_RE.search(re.sub(r"`[^`]*`", "", summary(raw))))
    expect("Markdown is escaped", summary("a *b* _c_ [d](e) <f> ~g~ |h| !i") == r"a \*b\* \_c\_ \[d\](e) \<f\> \~g\~ \|h\| \!i")
    expect("a stray backtick cannot open a span", summary("one ` stray").count("`") == 0)
    cut = summary("word " * 30 + "`" + "code " * 60 + "` tail")
    expect("truncation closes no span in half", cut.count("`") % 2 == 0)
    expect("tail edit is not a new bullet", added_entries("- **2026-01-01** — " + "a" * 120, "- **2026-01-01** — " + "a" * 120 + " more") == [])
    expect("added", len(added_entries("- **2026-01-01** — old\n", "- **2026-01-02** — new\n- **2026-01-01** — old\n")) == 1)
    expect("identical bullets are a multiset", len(added_entries("- **2026-01-01** — same\n", "- **2026-01-01** — same\n- **2026-01-01** — same\n")) == 1)
    expect("summary bounded", len(summary("x" * 500).encode()) <= 204)
    expect("summary keeps a multibyte tail valid", summary("é" * 300).endswith("…"))

    # A whole range, in a throwaway repository.
    cwd = os.getcwd()
    with tempfile.TemporaryDirectory() as d:
        os.chdir(d)

        def put(path, content):
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as f:
                f.write(content)

        def commit(msg):
            git("add", "-A")
            git("-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", msg)

        git("init", "-q", "-b", "main", ".")
        for m in ("a", "gone", "same"):
            put(f"modules/{m}/SPEC.md", "## Maturity\n\n**Grade:** 3 · S3 *(generated)*\n")
            put(f"modules/{m}/CHANGELOG.md", f"# {m}\n\n## Unreleased\n\n- **2026-01-01** — New module.\n")
        put("modules/_template/SPEC.md", "**Grade:** 5\n")
        commit("base")
        git("tag", "old")
        put("modules/a/SPEC.md", "## Maturity\n\n**Grade:** 2 · S2 *(generated)*\n")
        put(
            "modules/a/CHANGELOG.md",
            "# a\n\n## Unreleased\n\n- **2026-02-02** — **BREAKING:** `f` moved.\n"
            "- **2026-02-01** — **NO CONSUMER-VISIBLE CHANGE:** tidy.\n"
            "- **2026-01-31** — **CONSUMER-VISIBLE:** new `g`.\n- **2026-01-30** — **Added:** new `h`.\n- **2026-01-01** — New module.\n",
        )
        commit("a")
        put("modules/new/SPEC.md", "**Grade:** 2\n")
        put("modules/new/CHANGELOG.md", "# new\n\n## Unreleased\n\n- **2026-02-03** — New module.\n")
        git("rm", "-rq", "modules/gone")
        commit("new")
        out = notes("old", "HEAD")
        expect("count computed", out.startswith("2 commits since old."))
        expect("new module with grade", "new (grade 2)" in out)
        expect("removed module", "## Removed modules (1)" in out and "gone" in out)
        expect("grade change", "Better: a 3 -> 2" in out)
        expect("no grade change for an untouched module", "same" not in out)
        expect("template is not a module", "_template" not in out)
        expect("counts", "1 BREAKING, 1 consumer-visible, 1 other change, 1 marked no consumer-visible change, 0 sweep-only, 1 other" in out)
        expect("BREAKING before CONSUMER-VISIBLE", out.index("### BREAKING") < out.index("### CONSUMER-VISIBLE"))
        expect("the invisible bullet is not listed", "tidy" not in out)
        expect("the third group comes after CONSUMER-VISIBLE", out.index("### CONSUMER-VISIBLE") < out.index("### Other changes"))
        expect("claim names the commit", git("rev-parse", "HEAD").strip() in out)
        expect("deterministic", out == notes("old", "HEAD"))

        # Truncation: BREAKING survives, the pointer appears, the bound holds.
        many = "".join(f"- **2026-03-01** — **CONSUMER-VISIBLE:** item {i} {'x' * 150}.\n" for i in range(50))
        put("modules/a/CHANGELOG.md", "# a\n\n## Unreleased\n\n- **2026-03-02** — **BREAKING:** kept.\n" + many)
        commit("many")
        small = notes("old", "HEAD", max_bytes=3000)
        expect("bounded", len(small.encode()) <= 3000)
        expect("truncation points at the changelogs", "Truncated:" in small and "CHANGELOG.md" in small)
        expect("BREAKING survives truncation", "kept." in small)
        expect("the count is the whole count", "Changelog bullets added: 52" in small)
        os.chdir(cwd)

    if fails:
        for f in fails:
            print(f"  FAIL {f}")
        return 1
    print("release-notes self-test: all cases behaved")
    return 0


def main(argv):
    if argv == ["--self-test"]:
        return self_test()
    if len(argv) == 2 and argv[0] == "--claim":
        print(claim(argv[1]))
        return 0
    if len(argv) != 2 or argv[0].startswith("-"):
        print(__doc__.split("\n\n")[1], file=sys.stderr)
        return 2
    sys.stdout.write(notes(argv[0], argv[1]))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
