# SPDX-License-Identifier: MIT
"""Render the whole conformance corpus with the REFERENCE implementation
(Python Jinja2) and emit an input-to-output transcript.

WHERE THIS LIVES AND WHY. `modules/jinja/tools/`, not `src/`: a module in this
repository is standalone Zig with no external dependency, and this file needs a
`python3` with `jinja2`. Until 2026-09-06 it was `@embedFile`d into module
source and spawned from inside `zig build test-jinja`, so every consumer of the
library carried foreign source and the module's own test lane needed a
toolchain it has no business needing — and skipped, loudly, when it was absent.

It is driven by `tools/interop.zig`, never by the module's tests. What it
produces is captured once into `src/testdata/golden.json`, and
`src/reference_replay_test.zig` replays that file with no Python anywhere.

Usage:  reference.py <corpus.json> <out.json>

The transcript is one object per case: every input field the case was rendered
from, verbatim, plus the reference's outcome. Recording the inputs is what lets
this file be re-run against a future Jinja2 without the Zig corpus, and what
lets the replay test check that the fixture still describes the corpus it
claims to.

DETERMINISM. Rendering depends on more than the template: the Jinja2 version,
MarkupSafe's escaping, the environment's autoescape/undefined policy, the
delimiters, the `policies` table (which decides `tojson`'s key order and
`truncate`'s leeway), and Python's own float repr. Every one of those is
recorded in the transcript header — including the process environment the
capture ran with, which `tools/interop.zig` pins to `PYTHONHASHSEED=0`,
`LC_ALL=C`, `TZ=UTC`. The per-case knobs (autoescape, strict, trim_blocks,
lstrip_blocks, keep_trailing_newline) are recorded per case, in the case.
Nothing here reaches determinism by comparing less: every case in the corpus is
rendered and every rendered byte is stored.
"""

import datetime
import json
import os
import sys

import jinja2
import markupsafe
from jinja2 import DictLoader, Environment, StrictUndefined, Undefined


def header(defaults: Environment) -> dict:
    """Everything outside the case that the outputs below depend on."""
    stamp = datetime.datetime.now(datetime.timezone.utc)
    return {
        "captured": stamp.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "command": "zig build interop-jinja -- --capture",
        "driver": "modules/jinja/tools/reference.py",
        "jinja2": jinja2.__version__,
        "markupsafe": markupsafe.__version__,
        "python": sys.version.split()[0],
        "determinism": {
            "process_env": {
                k: os.environ.get(k) for k in ("PYTHONHASHSEED", "LC_ALL", "LANG", "TZ")
            },
            "float_repr_style": sys.float_repr_style,
            "autoescape_default": defaults.autoescape,
            "undefined_default": defaults.undefined.__name__,
            "newline_sequence": defaults.newline_sequence,
            "keep_trailing_newline_default": defaults.keep_trailing_newline,
            "delimiters": {
                "block": [defaults.block_start_string, defaults.block_end_string],
                "variable": [defaults.variable_start_string, defaults.variable_end_string],
                "comment": [defaults.comment_start_string, defaults.comment_end_string],
                "line_statement_prefix": defaults.line_statement_prefix,
                "line_comment_prefix": defaults.line_comment_prefix,
            },
            "extensions": sorted(defaults.extensions),
            # `repr`, not the value: some policies hold callables. What matters
            # is that a change to any of them is visible in the diff.
            "policies": {k: repr(v) for k, v in sorted(defaults.policies.items())},
        },
    }


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: reference.py <corpus.json> <out.json>", file=sys.stderr)
        return 2

    with open(sys.argv[1], encoding="utf-8") as fh:
        corpus = json.load(fh)

    cases = []
    for case in corpus:
        env = Environment(
            loader=DictLoader(case.get("templates", {})),
            autoescape=case["autoescape"],
            trim_blocks=case["trim_blocks"],
            lstrip_blocks=case["lstrip_blocks"],
            keep_trailing_newline=case["keep_trailing_newline"],
            undefined=StrictUndefined if case["strict"] else Undefined,
        )
        context = json.loads(case["context"])
        # The whole input, verbatim, then the outcome next to it.
        record = dict(case)
        try:
            record["status"] = "ok"
            record["out"] = env.from_string(case["template"]).render(**context)
        except Exception as exc:  # noqa: BLE001 - any failure is a datum
            # The exception TYPE is Python's and means nothing to the Zig
            # engine; only the fact of failing is compared. It is recorded
            # anyway, because a change of kind is worth seeing in a diff.
            record["status"] = "error"
            record["kind"] = type(exc).__name__
            record["msg"] = str(exc)
        cases.append(record)

    out = header(Environment())
    out["cases"] = cases
    with open(sys.argv[2], "w", encoding="utf-8") as fh:
        json.dump(out, fh, ensure_ascii=True, indent=1, sort_keys=True)
        fh.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
