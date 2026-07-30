# SPDX-License-Identifier: MIT
"""Render the whole corpus with the REFERENCE implementation (Python Jinja2).

Invoked as `python3 -c "<this file>" corpus.json out.json` by
`../reference_test.zig`, and by hand to regenerate the committed golden file.
Its output IS the golden file — the two oracles are the same bytes produced at
different times, which is the point: the live run catches drift in the peer,
the committed run keeps the assertion alive with no peer at all.

Nothing here is imported into the library; this is a black-box test oracle run
as a subprocess, exactly like wolfSSL in `modules/dtls`.
"""

import json
import sys

import jinja2
from jinja2 import Environment, StrictUndefined, Undefined


def main() -> int:
    with open(sys.argv[1], encoding="utf-8") as fh:
        corpus = json.load(fh)

    results = {}
    for case in corpus:
        env = Environment(
            autoescape=case["autoescape"],
            trim_blocks=case["trim_blocks"],
            lstrip_blocks=case["lstrip_blocks"],
            keep_trailing_newline=case["keep_trailing_newline"],
            undefined=StrictUndefined if case["strict"] else Undefined,
        )
        context = json.loads(case["context"])
        try:
            rendered = env.from_string(case["template"]).render(**context)
            results[case["name"]] = {"status": "ok", "out": rendered}
        except Exception as exc:  # noqa: BLE001 - any failure is a datum
            results[case["name"]] = {
                "status": "error",
                "kind": type(exc).__name__,
                "msg": str(exc),
            }

    with open(sys.argv[2], "w", encoding="utf-8") as fh:
        json.dump(
            {"jinja2": jinja2.__version__, "python": sys.version.split()[0], "cases": results},
            fh,
            ensure_ascii=True,
            indent=1,
            sort_keys=True,
        )
        fh.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
