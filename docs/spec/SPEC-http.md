# SPEC — `http`

HTTP client (and later server codec), pure-Zig, over `std.crypto.tls`.
`extract+gap · any · both · async`. One module, `Client` + `Server` submodules.
Model after: `lalinsky/dusty` (1.1 shape) + `nghttp2` (h2 framing/HPACK); verify h2 with **h2spec**.
Seed: `~/workspace/axp/axp-core/httpclient.zig` (streaming client) + `http.zig` (server codec).

## Why

The data plane / MCP / agent uploads all want a native HTTP client instead of shelling `curl` or
depending on the churny `std.http.Client`. HTTP/2 is a genuine ecosystem gap. `dns` (DoH), `rdap`,
and the REST/API cluster all sit on this. **Do NOT build on `std.http.Client`.**

## Phased scope — THIS TASK IS PHASE 1 ONLY

- **Phase 1 (DO NOW): HTTP/1.1 client over TCP + TLS.**
- Phase 2 (later spec): server codec (request parse / response write, streaming).
- Phase 3 (later spec): HTTP/2 (framing + HPACK) — verify against h2spec. **Do not start h2 yet.**

## Phase 1 requirements

1. **Transport:** TCP connect via std net; TLS via `std.crypto.tls` for `https`. IP or hostname
   (resolve via std for now; swap to the `dns` module once it lands). Use `netaddr` for address
   parsing / `host:port` splitting.
2. **Requests:** GET/POST/PUT/DELETE/HEAD; caller-set headers; request body (fixed length +
   chunked). Sane defaults for Host, User-Agent, Accept-Encoding: identity.
3. **Responses:** status line + headers parse (bounded header size), body via Content-Length
   **and** chunked transfer-encoding; expose body as a streaming reader AND a read-all-to-buffer
   helper. Decode is the caller's job for gzip (adopt std.compress if needed).
4. **Redirects:** follow 3xx up to a caller-set cap (default e.g. 10), method/redirect rules per RFC.
5. **Robustness:** connect + total timeouts; connection close handling; keep-alive optional
   (can defer pooling to a follow-up). Never panic on malformed server output — return errors.
6. **Streaming:** support bodies > memory without buffering the whole thing (the axp seed does
   `putFile`/`getToFile` straight to/from disk — keep that streaming capability).

## Public API sketch (keep small, allocator-explicit; final shape your call)

```zig
pub const Client = struct {
    pub fn init(gpa: std.mem.Allocator, opts: Options) Client;
    pub fn deinit(self: *Client) void;
    pub fn request(self: *Client, method: Method, url: []const u8, opts: RequestOptions) !Response;
    // convenience: getAlloc(url) -> owned body; getToFile(url, path); putFile(url, path)
};
pub const Options = struct { connect_timeout_ms: u32 = 5000, total_timeout_ms: u32 = 30000, max_redirects: u8 = 10, tls: TlsOptions = .{} };
```

## Acceptance / verification

- **Offline unit tests** (the bulk, must pass in the sandbox): status/header parser on canned
  byte buffers; chunked decoder incl. trailer + edge cases (0-chunk, split reads); URL parsing;
  redirect-chain logic driven by fabricated responses. `zig build test-http` green.
- **Live round-trip when the network is available:** `GET https://example.com` returns 200 +
  body; a small JSON API GET parses; a redirect (http→https) follows. If the sandbox has no
  network, note it and rely on the offline tests — do NOT fail the task for a missing network.
- No dependency on `std.http.Client`. TLS strictly via `std.crypto.tls`.

## Notes for the implementer

- Use the **zig skill** for correct Zig 0.16 std APIs (`std.crypto.tls`, `std.Io` reader/writer
  patterns, buffered I/O) — they differ from older training data.
- Extract/adapt the streaming client shape from the axp seed; implement HTTP/1.1 framing yourself
  (it's small and stable). Register `http` in `build.zig` with `deps = &.{"netaddr"}`.
- Land Phase 1 as a clean, tested increment; leave clear TODOs where Phase 2/3 will hook in.
