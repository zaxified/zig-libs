#!/usr/bin/env python3
"""check-model-field — a class C/D card whose evidence is a model names it.

WHY THIS EXISTS
---------------
For class C/D modules the evidence axis reads `**Evidence:** model-fuzz — …`
(E1) or `model — …` (E2) from SPEC.md/README.md, and the text after the dash is
prose: "naive oracle", "map model", "VOPR". A reader -- or an audit -- could not
find the model, and nothing stopped a card from claiming one that had been
deleted or had become a copy of the code it judges (owner 2026-11-14, plan v3
Part E: E measures the INDEPENDENCE of the truth). The card now names it:

    **Model:** src/model_test.zig:NaiveTrie · std:std.sort.block

Each reference, separated by ` · `, is one of
  <path>                 a file under modules/<m>/ (a whole model file)
  <path>:<identifier>    a declaration in that file (`fn`, `const`, `var`,
                         `struct`, or a `test "…"` whose name contains it)
  std:<dotted.name>      a std implementation used as the model

WHAT IT CHECKS
--------------
Every card with `**Evidence:** model-fuzz` or `model` has a `**Model:**` line in
the same file; every path exists; every identifier occurs as a declaration in
its file; a model file is not one of the module's production files unless an
identifier inside it is named (a test block's helper in root.zig is fine, the
whole of root.zig is not a model of itself). It cannot judge whether the model is
INDEPENDENT -- that stays the auditor's call, recorded on the card.

`--advisory` lists and exits 0 (the dry run before the cards are filled).
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
EVIDENCE = re.compile(r"^\*\*Evidence:\*\* (model-fuzz|model) — ")
MODEL = re.compile(r"^\*\*Model:\*\* (.+)$")


def declared(src: str, ident: str) -> bool:
    pat = re.compile(
        r"(\bfn\s+" + re.escape(ident) + r"\b)|(\b(const|var)\s+" + re.escape(ident) + r"\b)"
        r"|(^\s*test\s+\"[^\"]*" + re.escape(ident) + r"[^\"]*\")",
        re.M,
    )
    return pat.search(src) is not None


def production_files(m: str) -> set[str]:
    out = set()
    for f in (ROOT / "modules" / m / "src").rglob("*.zig"):
        rel = str(f.relative_to(ROOT / "modules" / m))
        if not re.search(r"(_test|test_[a-z0-9_]*)\.zig$|/testdata/", rel):
            out.add(rel)
    return out


def check_ref(m: str, ref: str) -> str | None:
    if ref.startswith("std:"):
        return None if re.fullmatch(r"std:std(\.[A-Za-z_][A-Za-z0-9_]*)+", ref) else f"malformed std reference '{ref}'"
    path, _, ident = ref.partition(":")
    f = ROOT / "modules" / m / path
    if not f.is_file():
        return f"'{path}' does not exist under modules/{m}/"
    if ident:
        if not declared(f.read_text(errors="replace"), ident):
            return f"'{ident}' is not declared in {path}"
    elif path in production_files(m):
        return f"'{path}' is a production file -- name the declaration that is the model ({path}:<identifier>)"
    return None


def main() -> int:
    advisory = "--advisory" in sys.argv[1:]
    cards = 0
    bad: list[str] = []
    for card in sorted(ROOT.glob("modules/*/SPEC.md")) + sorted(ROOT.glob("modules/*/README.md")):
        m = card.parent.name
        lines = card.read_text().splitlines()
        if not any(EVIDENCE.match(l) for l in lines):
            continue
        cards += 1
        models = [MODEL.match(l) for l in lines]
        models = [x.group(1) for x in models if x]
        rel = card.relative_to(ROOT)
        if not models:
            bad.append(f"{rel}: evidence is a model, but there is no **Model:** line naming it")
            continue
        for ref in (r.strip() for r in models[0].split(" · ")):
            err = check_ref(m, ref)
            if err:
                bad.append(f"{rel}: **Model:** {err}")
    if cards < 20:
        print(f"check-model-field: found only {cards} model cards -- parser out of date?", file=sys.stderr)
        return 1
    print(f"check-model-field: {cards} card(s) with model evidence, {len(bad)} problem(s)")
    for b in bad:
        print("  " + b, file=sys.stderr if not advisory else sys.stdout)
    return 1 if bad and not advisory else 0


if __name__ == "__main__":
    sys.exit(main())
