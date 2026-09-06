# grpc — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-06** — **The external anchor moved out of the module and its evidence moved in.**
  `src/reference_interop.zig` spawned Python `grpcio` from inside `test-grpc` and
  `@embedFile`d `src/testdata/reference_server.py` / `reference_client.py` into module
  source. Two things were wrong with that. A `zig-libs` module is standalone Zig with no
  external dependency, and this one shipped 16 KB of foreign-driving Python to every
  consumer. Worse, the 13 live tests **skipped loudly** when the interpreter was missing —
  and a skip is a pass, so on any host without `grpcio` the module's strongest evidence
  evaporated without a sound.

  The split:

  - `tools/interop.zig` is now a standalone PROGRAM (`zig build interop-grpc`). It spawns
    `tools/reference_server.py` / `tools/reference_client.py` **from their own path** — no
    `@embedFile` — compares live in both directions, and is never compiled into `test-grpc`
    or into `zig build`. `zig build check-interop` compiles it and runs no peer. A missing
    `grpcio` exits 2 with instructions, never a silent pass.
  - `zig build interop-grpc -- --capture` records **every byte the reference put on the
    wire** into `src/testdata/grpcio/*.bin`, with the manifest `src/testdata/grpcio_capture.zig`
    naming the implementation (`Python grpcio 1.83.0 / protobuf 7.35.1`), the date, the exact
    command, and what had to be pinned for replay to be deterministic (one connection per
    forward case so stream ids and the HPACK dynamic table restart; the reference's own
    `grpc-timeout` rendering; the reverse direction's advertised SETTINGS).
  - `src/reference_replay.zig` replays it inside the ordinary test lane: pure Zig, no child
    process, no socket, no foreign source. Both directions are covered — the reference
    server's bytes parsed by our client, and the reference client's bytes fed to our server
    through the same `h2_server.serve` entry point the capture ran on. The reverse
    assertions are checked against `grpcio`'s own readings, captured alongside as
    `src/testdata/grpcio/reverse_report.txt`, so they are the reference's numbers and not
    hand-typed ones.

  **Coverage did not shrink.** Every one of the 15 old tests has a replay: 12 forward
  interactions (the three `grpc-timeout` calls, previously three calls on one connection,
  are now three recordings — see the note in `tools/interop.zig` on why a recording of
  sequential calls cannot be replayed on one connection; `multiplex` keeps the
  several-calls-one-connection coverage), the 28-observation reverse run, and the two frozen
  byte constants from 2026-08-08. `test-grpc` went from **15 tests of which 13 skipped
  without `grpcio`** to **119 tests, 0 skipped**, verified on a `PATH` with no `python3`,
  no `go` and a `HOME` without the virtualenv.

  What replay cannot carry, stated rather than papered over: `grpcio`'s *parser* running on
  freshly produced bytes. A genuinely NEW divergence in the reverse direction is still only
  findable by `zig build interop-grpc`, which is now a pre-release check.

  **No API change.** `src/testdata/reference_{client,server}.py` are gone from the module;
  `zig build interop-grpc` and `zig build check-interop` are new entry points.

- **2026-08-21** — Published `statusParse` and the `grpc-message` percent-codec
  (`statusDecodeMessage`, `statusDecodeMessageAlloc`, `statusEncodeMessage`,
  `statusEncodedMessageLen`). They existed and were `pub` inside the module, but the
  root re-exported only `Status`, `StatusError`, `statusToError`, `statusFromError`
  and `statusFromHttpStatus` — so a consumer taking `frame.Deframer`'s own invitation
  to read this envelope from elsewhere (gRPC-Web, a proxy, a capture) could not parse
  the status trailer without reimplementing the one validation this module calls
  safety-critical: never letting a leading `+`, whitespace or trailing junk read as
  `.ok`. Additive; nothing existing changes. Found by writing `example/main.zig` —
  the first code ever to consume this module from outside.

- **2026-08-13** — **BEHAVIOURAL, not breaking** (server) — response metadata that cannot be
  written now turns the RPC `INTERNAL` (13) instead of passing as OK. `Call.finish`
  wrote `initial_md` / `trailing_md` with a bare `catch {}`, so once the
  response writer's 4 KiB header/trailer copy store ran out, the metadata the
  handler promised was dropped and the client was told `grpc-status: 0` — a
  successful RPC that silently lost part of its answer, invisible to both ends.
  `commitHead` already treats the SAME failure on the SAME `initial_md` as
  `error.BadMetadata`, so which of two identical failures a client heard about
  depended only on whether the head had been committed yet. `finish` returns
  `void` and is the last exit, so the status is the only channel it has, and it
  now uses it (with `grpc-message: response metadata could not be written`).
  **What changes for a consumer:** an RPC whose metadata exceeds the writer's
  copy budget used to report success and now reports INTERNAL; everything
  inside the budget is unchanged. `grpc-message` itself stays best-effort and
  is now documented as such — it is optional, and `grpc-status` is already on
  the wire by the time it is attempted.
- **2026-08-13** — **BEHAVIOURAL, not breaking** (server) — `handleRequest` no longer calls
  `ResponseWriter.end()` itself. It did so to beat the per-call arena's
  `deinit` to the metadata `Call.finish` had just handed `setHeader` /
  `setTrailer` — the status digits, the percent-encoded `grpc-message`, the
  trailing metadata — which `http` copies into the writer now, so the arena
  dying with the frame no longer reaches them. **What changes for a consumer:**
  the response head (and, on the Trailers-Only path, the whole response) is
  committed by the serving loop after the handler returns rather than inside
  it, so a middleware wrapped around the gRPC router can still touch the head.
  The frames on the wire are unchanged.

- **2026-08-06** — Security audit: five findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this). Verified: live
  bidirectional interop against a real Python `grpcio` server and client.
- **2026-07-30** — New module: a gRPC **client** over HTTP/2, per the `grpc-over-http2`
  specification — the layer between the `http` module's multiplexing h2
  client and the `protobuf` codec, with no code generation (a method is a
  path, its messages are Zig structs with a `pb_fields` descriptor).
  Length-Prefixed-Message framing where "several messages in one DATA
  frame" and "one message across many DATA frames" are both the normal
  case; Trailers-Only responses detected as such (the common error path,
  and what hangs a client that only looks for trailers after a body);
  status 0-16 as one Zig error per code with the percent-encoded
  `grpc-message` decoded; `-bin` metadata base64-coded in both directions;
  all four call shapes from one engine. The LPM length is read from the
  wire, so the invariant is stronger than "check before allocating" — *the
  declared length never sizes an allocation at all* — and
  `max_recv_message_size` (4 MiB, gRPC's own default) is enforced the
  instant the 5-byte header completes. Anchored live on Python `grpcio`:
  all four shapes, a real Trailers-Only failure, metadata both ways, a
  deadline the reference reads back, a 256 KiB reply reassembled across
  DATA frames — which also makes it the first third-party HTTP/2 peer our
  h2 client has faced. 14 mutations run; three of them (little-endian
  length, compressed flag misplaced, `-bin` sent raw) stay consistent
  between our framer and our parser and so survive every self round trip,
  dying only to the reference. **Client only**: the sibling `http`
  module's h2 server buffers each request to END_STREAM before dispatch
  and stages the whole response before framing it, so three of the four
  call shapes cannot be built on it today (`SPEC.md`).
