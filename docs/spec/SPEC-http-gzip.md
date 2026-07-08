# SPEC — `http` Phase 2.2 (response compression / gzip)

Extends the existing `http.Server` (no new module) with negotiated gzip response compression, using
`std.compress.flate`. Direct-HTTPS/feature-rich story (T5.13). Model after: Go `net/http` gzip
handler / nginx `gzip`. `any · server`. **No new module_list entry — it's part of `http`.**

## Why

An internet-facing API should compress text responses (JSON/HTML/CSS/JS) to cut bandwidth. This is
the standard `Content-Encoding: gzip` negotiation, done at the server so every handler benefits.

## Scope

1. **Negotiation:** compress only when the request `Accept-Encoding` accepts `gzip` (honor `q=0` =
   refused); set `Content-Encoding: gzip` and **`Vary: Accept-Encoding`** on compressed responses.
2. **Eligibility:** compress only if — body is present (skip HEAD/204/304), the response isn't already
   `Content-Encoding`'d, the content-type is in a **compressible allowlist** (text/*, application/json,
   application/javascript, xml, svg, … — configurable), and the body is **≥ a min-size threshold**
   (e.g. 1 KiB — below that gzip overhead loses). Never double-compress.
3. **Encoding path — pick the cleaner, document it:**
   - **Streaming (preferred):** wrap the body writer with a gzip encoder (`std.compress.flate` gzip
     container) feeding the existing chunked-transfer path — no Content-Length needed, bounded memory.
   - **Buffered:** buffer the handler body up to a cap, compress, emit with Content-Length; fall back
     to passthrough (uncompressed) above the cap. Simpler; acceptable.
   Whichever: the handler code does not change — it writes normally; the server compresses transparently.
4. **Config:** `Options.compression: ?Compression` (null = off) with `min_size`, `level`, and the
   content-type allowlist. Off by default OR on with safe defaults — pick and document.
5. **Correctness:** the compressed bytes MUST decompress back to exactly what the handler wrote; keep
   framing correct (chunked when streaming, Content-Length when buffered); `Vary` always set when
   compression is even considered (so caches key on Accept-Encoding).

## Integration note

This needs the `ResponseWriter` / serving loop to route the body through the compressor. You may add a
minimal internal hook to `http.Server` (a body transform / a buffering mode on `ResponseWriter`) to
enable it — keep the public Client/Server API stable, and keep the compression logic tidy (a small
internal `gzip`/`compress` helper in the http module is fine). Reuse `h1.zig` framing; don't duplicate.

## Acceptance / verification

- **Offline unit tests:** Accept-Encoding parsing (gzip present / absent / `gzip;q=0` / `*`);
  eligibility gate (min-size, content-type allowlist, already-encoded, HEAD/204/304 → no compression);
  a compressed response **round-trips** (gzip-compress then `std.compress.flate` decompress == original
  body); `Vary: Accept-Encoding` present; framing correct (chunked or Content-Length).
- **In-process integration (must NOT skip normally):** `http.Server` (compression on) + `http.Client`
  — a request with `Accept-Encoding: gzip` to a route returning a >min-size JSON body → response has
  `Content-Encoding: gzip` + `Vary`, and the body **decompresses to the expected JSON** (decompress in
  the test via `std.compress.flate`, since the Phase-1 client leaves gzip decode to the caller); a
  request WITHOUT `Accept-Encoding: gzip` → uncompressed, no `Content-Encoding`; a tiny body → not
  compressed. Gate only genuine bind failures via `error.SkipZigTest`.
- `zig build test-http` + `zig build test` (all) green, Debug + ReleaseFast; `zig fmt --check` clean.
  Client + existing Server API + existing server tests unchanged.

## Notes for the implementer

- Use the **zig skill** for `std.compress.flate` (gzip container) + Zig 0.16 std.Io.Writer wrapping.
- Don't break existing http tests. Keep `Vary` correct for cache safety. Document the default
  posture + the compressible-type allowlist. Optionally support `deflate` too (gzip is the priority).
- README: document the compression option + defaults. (No Provenance/NOTICE change needed — it's std
  + RFC 9110/1952 behavior; add a one-line note in the http README.)
