# `http` verification instruments

Four instruments. They live here rather than in `src/` because each one needs an
environment `zig build test-http` must never require: three of them stand up real
loopback peers on their own threads and read the bytes that actually leave the
process, and the fourth drives the compiler as a subprocess over a mutated copy
of the module (`CONVENTIONS.md` §9).

None of them is wired into `zig build`. They are run by hand, they print what
they found, and nothing here is a gate — `tools/` is not walked by `build.zig`.
The one gate that *does* reach any of them is `zig fmt --check`, which runs over
the whole `modules` tree: it holds the three `.zig` files here to the same
formatting as the module itself, and does not look at `mutate.py` at all.

| tool | the question it answers | why this tool and not a test |
|---|---|---|
| `probe_injection.zig` | Can a caller-supplied byte become a new **line** on the wire — through an h1 header, a URL, or an h2 field that HPACK framed by length? | The subject is the bytes that leave the process, so the observer has to be a real peer on a real socket; the h2 cases need a front server and a backend alive on their own threads at once. A unit test can assert what a writer *returns*, not what a peer *received*. |
| `probe_redirect_credentials.zig` | Which caller-pinned headers survive a **cross-origin redirect hop**? | Needs two listeners and a real 302 chain between them. What is being observed is hop **two**, which does not exist inside a single-call test. |
| `probe_limits.zig` | What do the parsers **cost**, and are the documented bounds real? | Every answer is a measurement. A threshold pinned in a test would be a benchmark pinned to one machine; this prints numbers for a human to compare and asserts nothing about them. |
| `mutate.py` | Would the suite **notice** if a shipped guard were deleted? | Most of what makes this module safe to expose is a constant or a single refusal, and a functional test passes just as well with the limit at 2^40. The question is not "does it work" but "would anyone notice if it stopped". |

## Running them

```
zig build-exe -OReleaseSafe --dep http -Mroot=probe_injection.zig \
  --dep netaddr --dep datefmt -Mhttp=../src/root.zig \
  -Mnetaddr=../../netaddr/src/root.zig -Mdatefmt=../../datefmt/src/root.zig
./probe_injection

python3 mutate.py            # every row
python3 mutate.py M4 M13     # only these
```

The probes take no arguments. `probe_injection` exits non-zero if an injection
reached the peer **or** if a control did not; the other two print and exit 0.
`mutate.py` exits non-zero if a positive control misbehaved.

⚠ Run the probes in a **release** mode. In Debug, `probe_limits`' numbers say
nothing about shipped code.

## What they measured on 2026-09-16 (zig 0.16.0, ReleaseSafe, this tree)

**`probe_injection` — all eleven cases, exit 0.** Both controls reached their
peer; all nine injections were refused with **zero request bytes on the wire**.
Seven were refused as `InvalidHeader`; the two URL cases as `BadUrl`, which is a
different guard (the URL parser) and worth keeping distinct.

**`probe_redirect_credentials`.** Hop 1 receives all five headers including the
caller's `Host: vhost.internal`. Hop 2 — cross-origin by port — receives neither
`Authorization` nor `Cookie` nor `Proxy-Authorization`, and the caller's `Host`
is replaced by the real one. `X-Api-Key` **does** survive: the module strips the
credentials it can name and does not guess at bearer-shaped custom headers. A
consumer that ships its own credential header keeps it off a cross-origin hop
with `RequestOptions.redirect_filter`, which is also the destination gate for
loopback / link-local / RFC1918 targets.

**`probe_limits`.**

- Sweep: 300 000 iterations × 16 parsers, 3 348 ms, no panic.
- `conneg.negotiate` is ~24–27 ns per range per offer from 100 ranges upward —
  flat, so the whole Accept header is no longer re-walked once per offer (G7).
  Against a fixed 1000-range header, 1→8 offers still costs 134 → 212 µs
  (1.58×), so per-offer work remains; it is no longer the whole parse.
- One 53-byte `Range` header resolves to 16 ranges and **167 773 657 B** of
  body — 16.00× the representation. The interesting multiple is of the
  representation, not of the header.
- `bufpool` under 2000 concurrent checkouts: 2000 allocations, 8 192 000 B live.
  `max_idle_slabs=8` bounds the **idle** list, not the checked-out set — after
  releasing all 2000 the idle list is back to 8 and the other 1992 were freed.

**`mutate.py`.** All 16 rows (14 mutations + 2 controls) were dry-run against the
live sources: every anchor matches **exactly once**, and every replacement
changes the text. A full run rebuilds and re-runs the suite per row, so it takes
tens of minutes; the suite it runs is 539 passed / 4 skipped / 0 failed on the
unmutated tree.

## What these found, and what closed it

On 2026-09-04 every injection case here **succeeded**. `GET /admin` reached the
peer through an h1 header value and through the URL path; through h2c, a `:path`
carrying CRLF smuggled a whole second request past `proxy.ProxyHandler` onto the
backend's wire, answered 200 to an unauthenticated client (A1 G1 CRITICAL, F1 and
F13 HIGH).

Commit `a4c1ab95` closed it with three guards — `h1.isToken`,
`h1.isValidFieldValue` and `h1.isValidRequestTarget`, none of which existed
before it — on both the h2 serving path and the client, with tests pinning each.
Every case in `probe_injection` is now a **regression detector** for that fix:
the run is green precisely because each one is refused.

## ⚠ Why these files had to be re-derived, not merely moved

The originals lived in `.zig-cache/audit-http-client/`, outside every gate this
module has, and by 2026-09-16 every one of them was broken:

- They mutated and compiled a **snapshot** of the module kept beside them. That
  snapshot was 661 lines behind `Client.zig`, 1 221 behind `h2_server.zig` and
  331 behind `Server.zig` — so the verdicts described a module nobody ships.
  These tools copy from the live `../src` at run time instead.
- Two mutation anchors named a two-clause credential strip. The shipped guard
  has had **three** clauses since `proxy-authorization` was added, so the old
  text matched nothing and both rows silently read as "did not apply". They are
  re-derived here against the current site; an anchor that matches zero times or
  twice is **refused**, never loosened until it sticks.
- The network probes joined a recorder thread parked in `accept()`. While the
  guards did not exist the client always dialed, so `accept()` always returned.
  Once the client began refusing, nothing dialed — and the probes hung **on the
  fix**, indefinitely, with no output. `wake()` exists for exactly this: it
  dials the listener itself so a refusal becomes a printable result.
- One probe let the refusal escape `main` through `try`, which skipped its own
  ordered teardown. A worker then kept serving a destroyed `Server` until
  `req_index: u32` wrapped at 2^32 and panicked — a crash that looked like a
  defect in the module and was not one.

Two rules came out of that and are worth keeping when editing these files:

1. **A control is judged the other way up.** A case fails when its needle
   reaches the peer; a control fails when it does **not**. The first version of
   `probe_injection` read both the same way and reported a perfectly healthy run
   as two breaches.
2. **Bytes are the evidence, not the connection.** Since `wake()` dials the
   listener itself, having *accepted* a connection proves nothing about whether
   anything was sent.
