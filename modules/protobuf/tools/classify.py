#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""How two answers to the same input differ — the vocabulary the campaigns count in.

WHY THIS EXISTS. A differential run produces pairs of answers, and "they differ"
is not one fact but three, which have to be counted apart because they mean
different things:

  - agree-reject      both refused. The strongest agreement there is: the two
                      implementations drew the same line in the same place.
  - agree-accept      both accepted and produced the same value.
  - DIVERGE-value     both accepted, different values. A decoding bug.
  - DIVERGE-decision  one accepted what the other refused. A POLICY difference,
                      and the direction matters: accepting what the reference
                      rejects is an attack surface, rejecting what it accepts is
                      an interop failure. The label carries which way round.

Collapsing these into one "mismatch" number is how a security-relevant
divergence gets averaged away among harmless ones.

WHAT IT NEEDS / PRODUCES. Nothing; it is a helper imported by `camp4.py` and
`camp5.py`. Both sides' answers are the line protocol of `probe.zig` and
`oracle.py`: `OK <dump>` or `ERR <reason>`.
"""


def kind(z, p):
    zr, pr = z.startswith("ERR"), p.startswith("ERR")
    if zr and pr:
        return "agree-reject"
    if not zr and not pr:
        return "agree-accept" if z == p else "DIVERGE-value"
    return "DIVERGE-decision(zig=%s)" % ("reject" if zr else "accept")
