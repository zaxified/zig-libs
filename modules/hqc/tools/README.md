# `hqc` verification instruments

Four instruments that check this module against the **C reference implementation**,
plus the mutation runner that checks the test suite itself. They live here and not in
`src/` because every one of them needs a foreign toolchain — a C compiler, CMake, a
Python — which a module must never require (`CONVENTIONS.md` §9).

None of them is wired into `zig build`. They are run by hand, and each prints what it
found; the repository-side claims they support are in `NOTICE`, `SPEC.md` and
`CHANGELOG.md`, which cite these files by path.

## The reference checkout they all need

    R=.zig-cache/hqc-cref                     # disposable; never add it to this tree
    git clone https://gitlab.com/pqc-hqc/hqc.git "$R/hqc-gitlab"
    git -C "$R/hqc-gitlab" worktree add "$R/hqc-v5.0.0" v5.0.0

    cmake -S "$R/hqc-v5.0.0" -B "$R/hqc-v5.0.0/build-ref" -G Ninja \
          -DCMAKE_BUILD_TYPE=Release -DHQC_ARCH=ref
    cmake --build "$R/hqc-v5.0.0/build-ref" -j8
    cmake -S "$R/hqc-v5.0.0" -B "$R/hqc-v5.0.0/build-avx256" -G Ninja \
          -DCMAKE_BUILD_TYPE=Release -DHQC_ARCH=x86_64 -DHQC_X86_IMPL=avx256
    cmake --build "$R/hqc-v5.0.0/build-avx256" -j8

Tag `v5.0.0` is commit `f46e54222ffb76706678a9ec8a43cd2188a12ab1`. The licence of that
tree is **public domain** — recorded, with the grant reproduced verbatim, in this
module's `NOTICE`. Nothing is copied out of it: these tools *run* it.

⚠ **Pin the tag, not the branch.** A bare clone lands on `next-release`, whose KAT
files DIFFER from v5.0.0's. Pointed at that checkout, `compare_kat.py` reports only the
nine seeds matching and every other field differing — which looks exactly like a defect
in this module and is not one.

## What each one is for

| tool | question it answers | why this tool and not a test |
|---|---|---|
| `compare_kat.py` | Are the vectors pinned in `src/kat_vectors_kem.zig` the official NIST `.rsp` bytes? | A Zig test can only compare our vectors with themselves. This reads the reference's own `.rsp` files, which the module does not ship. |
| `oracle_hqc.c` | Given a seed, what does the **C reference** produce? | A differential oracle. Our tests replay frozen vectors; this recomputes the answer on the other implementation, including for seeds no KAT covers. |
| `oracle.sh` | — | Builds `oracle_hqc.c` for all three parameter sets in both lanes (`ref`, `avx256`), so the two reference lanes can also be compared against each other. |
| `bench.sh` | What does the reference cost, on this machine, in the same units? | Comparing our numbers to published ones compares two machines. This builds the reference here. |
| `mutate.py` | Would this module's own suite notice if the code were wrong? | Tests prove the code passes; only mutation shows the suite can fail. Carries positive controls that MUST be killed. |

`bench_hqc.c` is the benchmark body `bench.sh` compiles; it is our own code and does not
appear in the table because it is not run directly.
