# conntrack — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-10** — **A1 audit, two findings.** (A1) `dumpOver`/`dumpEachOver` carried the old
  unbounded multi-part reply loop forward when they were factored out of `Socket.dump` — unlike
  the sibling `awaitFlow` (C-06, F6), which got a message budget in the same pass. `DumpError`
  already declared `error.TooManyMessages` (inherited from `netlink.DumpError`), advertising a
  bound neither engine could ever produce; a kernel that never sends `NLMSG_DONE` spun both loops
  forever. New `max_dump_messages` (65536, same ceiling as `max_await_messages`, reset per dump
  attempt) makes it real. (A5) `decodeFlow` cross-checked a tuple's own src/dst family (F5) but
  never `orig` against `reply`, nor either against the message's own `nfgen_family` — both now
  rejected with the existing `error.AddressFamilyMismatch`. Not breaking: both errors already
  existed in their respective error sets.
- **2026-09-07** — Both fuzz targets ran one fixed input. `wire.fuzzDecode` opened with
  `smith.bytes(&raw)` and a ranged length, which returns the range minimum when fewer than eight
  input octets remain, so the length was 0 on every seed and all four of its readings — flow
  payload, `nfgenmsg`, tuple nest, and message stream — were handed an empty slice. Its buffer
  was 512 octets, so `dump_reply_three_flows` could not have passed through it either: a seed
  longer than the buffer reads back as the EMPTY one. `root.fuzzDumpEngine` was worse. It opened
  with `smith.value(u8)`, so outside `--fuzz` every draw was its minimum, in order: errno 0, a
  ONE-datagram script, and selector 0 — a single reply with no `NLMSG_DONE` behind it, which runs
  the scripted transport off the end and errors out before the retry budget, the errdefer or the
  ownership of the collected flows is touched. Its own doc comment says the W2-07 double free
  "needed four consecutive `NLM_F_DUMP_INTR`"; the engine never saw two datagrams, let alone
  four. Both now draw bytes first (`smith.slice`, with `testkit.fuzz.Cursor` reading the dump
  scenario out of the seed) and carry corpora: eleven readable dump scripts including the
  four-INTR sequence and an error arriving after flows were collected, and twelve ctnetlink
  buffers built from the module's captured goldens. Guards pin flows collected, INTR retries
  entered, tuple nests walked and addresses read — an `nfgenmsg` with no attributes decodes into
  an all-default `Flow`, so acceptance says nothing about whether the attribute walk ran.

- **2026-08-18** — **BEHAVIOURAL, not breaking**: `dump`/`dumpEach`/`flush` now return a new
  `error.SubsystemUnavailable` instead of `error.InvalidRequest` when the kernel's `EINVAL`
  means "`nf_conntrack_netlink` is not registered" (e.g. stock OpenWRT 25.12.4) rather than
  "malformed request" — the two were indistinguishable before, and reporting the wrong one for
  a mutating op like `flush` is an operational hazard. `get`/`delete`/`insert`/`update` are
  unchanged (deliberately: they carry a caller-supplied `Tuple`/`NewSpec`, so `EINVAL` there
  stays genuinely ambiguous with a malformed request). Additive to `DumpError`/`RequestError`/
  `WriteError`, so no existing `catch`/`switch` with an `else` arm needs a change; a caller with
  an *exhaustive* switch over the old error set on `dump`/`flush` specifically needs a new arm.
  See SPEC.md "EINVAL vs subsystem absent".
- **2026-08-06** — Security audit: six findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this). Verified against a
  live capture from `libnetfilter_conntrack` / conntrack-tools — used in-repo as a
  black-box capture oracle.
- **2026-07-22** — New module: Linux ctnetlink (`NETLINK_NETFILTER` /
  `NFNL_SUBSYS_CTNETLINK`) client — typed conntrack flow dump/get/delete plus event
  subscription, over `netlink`'s write engine.
