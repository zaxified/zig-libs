# `whois` verification instruments

One instrument: a mutation runner. It lives here rather than in `src/` because
it drives the compiler as a subprocess and writes working trees
(`CONVENTIONS.md` §9).

| tool | question it answers | why this tool and not a test |
|---|---|---|
| `mutate.py` | Would the suite notice if an SSRF guard were deleted? | A whois client follows referrals to hosts the *response* names. Over half the 31 mutations disarm one of the checks standing between a caller and a request aimed at 127.0.0.1, at RFC1918 space, or at cloud metadata on 169.254.169.254 — and none of them is visible in a functional test that looks up a domain and gets the right answer. |

    python3 mutate.py            # all 33
    python3 mutate.py M7 M13     # only these

It copies `../src` into `.zig-cache/whois-mutate/`, applies one edit, verifies by
`diff` that the edit landed, and runs the suite against the copy with `netaddr`
taken from this repository. The tracked tree is never touched.

## How to read the output

`RED` means the suite caught it. `GREEN` means the guard could be deleted with
every test still passing — that is the finding. `NOLAND` means the edit did not
apply and is a **missing row**, never a verdict: a runner that fails open prints
GREEN for a mutation that never happened, which reads as a hole in the suite when
the truth is that nothing was tested.

`PC-ok` must stay GREEN and `PC-bad` must go RED. If either is wrong the runner
is broken and the rest of the run says nothing, so it exits non-zero.

## ⚠ Seven anchors are stale

Against the current `src/root.zig`: **M2, M3, M4, M11** no longer occur at all,
and **M9, M22, M23** now occur **twice**. Both report NOLAND.

The two-site case is the one worth understanding. `str.replace(old, new, 1)`
would have mutated the first site and left the second intact, producing a mutant
that is neither the original nor the intended edit — and a verdict describing
neither. The runner refuses an ambiguous anchor for that reason; re-deriving
these means re-reading the function and writing an edit that names one site, not
relaxing the match until it sticks.

The audit kept its own `netaddr` checkout beside this runner; by 2026-09-16 it
was 128 lines behind the repository's, so it was compiling the module against a
dependency nobody ships. This version uses `modules/netaddr/src/root.zig`.
