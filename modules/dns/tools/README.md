# `dns` verification instruments

Five instruments. Two are wired into `zig build`; three are run by
hand. They live here rather than in `src/` because each needs something
`zig build test-dns` must not require — a foreign toolchain (dnspython), a real
socket and a second schedulable thread, or the live internet
(`CONVENTIONS.md` §9).

Only two kinds of instrument are kept here (`CONVENTIONS.md` §9): recipes for data the
tests pin, and oracles that drive a foreign implementation through the public API or
wire format. The audit's mutation runners and per-finding probes were deleted on
2026-09-17; what they found is pinned by tests in `src/` or filed as open findings.

Figures below were measured on 2026-09-16 against the tree as it stands.

## Already wired into the build (read their own headers first)

| tool | what it is |
|---|---|
| `interop.zig` | `zig build interop-dns` — the `Resolver` against a hostile loopback UDP server over a real socket, plus the `--capture` recorder that turns each exchange into a committed frame in `src/testdata/` which `test-dns` replays with no socket, no thread and no clock. `zig build check-interop` compiles it on every run as a rot guard. |
| `live.zig` | Real-internet checks — recursive UDP and TCP, a reverse PTR, and three DoH shapes. A program rather than seven tests, because a slow DNS server is not a defect in this module and must not redden the gate. |

Both carry a long argument in their own headers for why they are programs and
not tests. That argument is the reason the hostile-stub harness the 2026-09-04
audit carried (`run.sh` + `stub.py` + `driver.zig` + its own `build.zig`) is
**not** here: `interop.zig` covers the same ground, is in the gate, and its
frames are committed.

## Is the decoder's answer the same as a second implementation's?

    modules/dns/tools/gen_corpus.py 25000 1 > .zig-cache/dns-oracle/corpus.hex
    scripts/lib/capped zig build-exe --cache-dir .zig-cache \
      -femit-bin=.zig-cache/dns-oracle/probe_dump \
      --dep msg -Mroot=modules/dns/tools/probe_dump.zig \
      --dep testkit -Mmsg=modules/dns/src/message.zig \
      -Mtestkit=modules/testkit/src/root.zig
    .zig-cache/dns-oracle/probe_dump .zig-cache/dns-oracle/corpus.hex \
      .zig-cache/dns-oracle/zig.txt
    modules/dns/tools/oracle_dnspython.py .zig-cache/dns-oracle/corpus.hex \
      .zig-cache/dns-oracle/zig.txt

`gen_corpus.py` writes seeded hostile packets (truncations, byte flips,
compression pointers into the middle of the packet, RDLENGTH off by one).
`probe_dump.zig` renders what `decode` made of each — **that format is an
interface**, `oracle_dnspython.py` parses it, so changing a field means changing
the parser in the same commit. The oracle compares the security-relevant
projection: accept/reject plus every owner name, type, class and RDATA name.

Measured, and **pinned** (`gen_corpus.py 25000 1`, dnspython 2.8.0):

| | packets |
|---|---|
| both accept | 6 187 |
| `dns` accepts, dnspython rejects | 2 538 |
| `dns` rejects, dnspython accepts | 130 |
| both reject | 22 322 |
| total | 31 177 |

### Why those 2 538 are not a defect, and why the check is a pin rather than a threshold

The first version of this oracle failed whenever the "we accept, they reject"
count was non-zero. That was wrong in an instructive way: on a hostile random
corpus it is *always* non-zero, so the instrument **could only fail** — the
mirror image of the "cannot fail" defect, built by hand hours after that same
shape was found and fixed in `tc`'s reach probe.

The two implementations differ by design. `dns` decodes the wire for the record
types it knows and keeps the rest as RAW; dnspython parses every type
semantically. Of the 2 538: **1 620 are dnspython `FormError` and 833
`BadEDNS`** — its own strictness about RDATA and EDNS. The remaining 85
(`BadLabelType`, `BadPointer`) were **sampled, not exhausted**: the three
inspected were each a name inside the RDATA of a type this module stores as
RAW, i.e. the same scope difference. The other direction (130) is 121
`BadRecord` — this module being deliberately stricter about RDATA overrunning
RDLENGTH.

So the useful question is not *do they differ* but *did the difference move*.
The counts are pinned against a fingerprinted corpus (SHA-256 in the script);
any movement fails the run and names which count moved. Against any other
corpus it reports and exits 0. If dnspython itself moves, re-pin deliberately —
do not widen the check.

Demonstrated 2026-09-16 that each branch works: pinned corpus → exit 0; a
truncated probe output → exit 2 naming the misalignment; an unpinned corpus →
reported, exit 0.
