# dns — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-11-16** — `CachingResolver`: a lookup the Resolver refuses before sending anything (`BadName`, `NameTooLong`,
  `RequestTooLarge`, `InvalidOptions`, `NoDotSupport`, `NoDohEndpoint`) no longer counts in `Stats.network_lookups` and gives
  its `max_network_lookups` token back, as the table-bypass path already did. Two tests.
- **2026-11-16** — **NO CONSUMER-VISIBLE CHANGE:** delta mutation audit of the coalescing, prefetch and `lookupIpMany` code in
  `CachingResolver`, 77/80 killed, 3 equivalent or unobservable; ten new tests (every key kind renewed by `refreshDue`, its
  order and cancelation, the prefetch boundary, refused and failed refreshes, waiters of a canceled lead), and the test Stub
  counts SRV query names.
- **2026-11-16** — `CachingResolver` review fixes (same day, before any release): a waiter whose coalesced lead left nothing in
  the table asks itself in parallel instead of queueing behind the next waiter (TTL-0 / non-cacheable answers were serialised);
  a failed prefetch refresh arms the key's backoff while the old answer keeps being served (it retried a dead upstream on every
  refresh); a refresh refused by backoff or budget no longer counts as a stale answer.
- **2026-11-16** — `CachingResolver`: **request coalescing** (concurrent misses on one key share one network lookup; waiters read
  the lead's answer or its failure through the backoff; a canceled lead wakes them and one asks in turn; `Stats.coalesced`),
  **prefetch** (`Options.prefetch_pct`, off by default, ≤ 99 else `InvalidOptions`; `refreshDue(max)` refreshes the keys a late
  hit marked, caller-driven; `Stats.prefetches`) and **`lookupIpMany(names, results)`** (concurrent `lookupIp` over a
  `std.Io.Group`, one `IpResult` per name, every result set on cancel; `error.LengthMismatch`). `Stats` gains two fields
  (a consumer that builds `Stats` literals must add them). Scope core -> parity.
- **2026-11-16** — **NO CONSUMER-VISIBLE CHANGE:** the CachingResolver tests' clock uses 64-bit atomics only where the target has them, so `check-portable` compiles the tests for linux32 (mips32) again; the card's src hash re-recorded for this test-only change.
- **2026-11-16** — **NO CONSUMER-VISIBLE CHANGE:** delta mutation audit of the `forget*` / `stale_reason` / `resort_ip_hits` code in `CachingResolver` (24 schemata mutants, all killed); 3 new tests (`forget` over all five name kinds, a stale IP answer re-sorted and a network answer not probed, a 65-address hit served unsorted with the default `sort_source` pinned) and the "absent key" test now reaches the too-long-key path.
- **2026-11-15** — **CONSUMER-VISIBLE (additive, FEATURE):** `CachingResolver` gaps for callers that refresh single names. `forget(kind, name)` (`NameKind`: `.ip .mx .ns .txt .cname`), `forgetReverse(ip)` and `forgetSrv(service, proto, name)` drop one key's answer and backoff so its next lookup goes to the network (absent key: no-op). `Options.resort_ip_hits` (default true): a `lookupIp` `.cache`/`.stale` hit is re-sorted with RFC 6724 destination selection as of the hit, on the caller's clone after the mutex is released (one route query per item per hit; `false` keeps the stored order), with `Options.sort_source` (default `netaddr.systemSource`) as a test seam. `Answer.stale_reason: ?Error` says why a `.stale` answer was served (the upstream failure, the error the backoff holds, `error.BudgetExceeded`). Behaviour change: hits of `lookupIp` are now re-ordered by default. Docs: the stale window counts from expiry (RFC 8767) and how to express "keep the last answer N seconds"; negative answers follow the SOA TTL (RFC 2308), not the failure backoff. **Tests:** forget per kind, absent key, forget during backoff, `stale_reason` for each of the three causes, a changed source reorders a hit, the option off skips the probe.
- **2026-11-15** — **NO CONSUMER-VISIBLE CHANGE:** delta mutation audit of the review-fix code in `CachingResolver` (38 schemata mutants: 36 killed, 2 unobservable); 6 new tests (every lookup kind's local bypass with an empty budget, the expiry measured from the send after a pool wait, `refundLocked`, the direct `bypass` counting, a failure serving a fresh entry, `resetFailures` reaching every entry); card Audit line re-recorded over the current source.
- **2026-11-15** — **FIX (CachingResolver):** a name too long for the cache key (it bypasses the table) is counted as a network lookup only once a Resolver is held and only when the answer came from DNS, like the cached path after review F1/F5; two tests written by the mutation wave that pinned the pre-review behaviour (expiry measured after the call, a failed `acquire` still counted) now pin the reviewed one.
- **2026-11-15** — FIX (`CachingResolver`, review findings): IP literals and `.onion`/`.invalid` names are answered before the budget, pool and statistics (they spent a token, a slot and a `network_lookups` count; an /etc/hosts hit is refunded after the fact); an answer's TTL now runs from the moment its query was sent, not from when the lookup returned; a failure of a concurrent miss no longer arms backoff on an entry that holds a fresh answer (the answer is served); the budget token and `network_lookups` are given back when the pool wait fails (cancel, out of memory). **Added:** `resetFailures()` (clears every key's backoff, keeps the answers). Docs: `gpa` must be thread-safe; `canonical` keeps the first caller's letter case; rooted and unrooted names are separate entries; eviction drops backoff state; backoff is per key and `MalformedResponse` arms it; `lookupIp` order is RFC 6724 as of the lookup time. **Tests:** budget {1,1} with two literals, `.onion` and a hosts name all succeed with 0 queries and 0 network lookups; the clock advancing during a lookup; a failure on a fresh entry; cancel while waiting for a slot returns the token; `resetFailures`.
- **2026-11-15** — **NO CONSUMER-VISIBLE CHANGE:** delta mutation audit of `CachingResolver` (208 schemata mutants: 191 killed, 17 equivalent or unobservable); 23 new tests (option bounds, key separation and limits, prune and drop decisions with allocator accounting, clock regressions and saturation, the Resolver pool's free list, OOM and cancel paths, expiry and backoff measured after the network call, the 16-entry expiry scan); card Audit line re-recorded over the current source.
- **2026-11-15** — **CONSUMER-VISIBLE (additive, before first release):** `CachingResolver` owns a pool of `Resolver`s instead of wrapping one: `init(gpa, io, resolver_options: Resolver.Options, options)` (no `*Resolver` parameter), `Options.max_concurrent_lookups` (default 8, 0 = `InvalidOptions`). Resolvers are created lazily; a miss takes a free one for its lookup and waits, cancelable through `io`, when all are busy — so one slow name no longer blocks misses on other names. Two concurrent misses on one key may still both query. The slices in `resolver_options` must outlive the cache. **Tests:** a held-back answer for one name does not block another name (deterministic: the stub releases it only after the other finished); with `max_concurrent_lookups = 1` the second miss parks in the pool and sends nothing; the OOM-while-storing test now fails the last measured allocation of an identical run.
- **2026-11-15** — **CONSUMER-VISIBLE (additive, FEATURE):** `dns.CachingResolver` — an answer cache over `lookupIp`, `reverse`, `lookupMx`/`Ns`/`Txt`/`Cname`/`Srv` (consumer request 2026-11-15; parity: hickory `CachingClient`, c-ares query cache, RFC 2308, RFC 8767). `init(gpa, io, resolver_options, Options)`; each call returns `Answer(T){ lookup: Resolver.Lookup(T) (a clone, `ttl_s` = seconds left), source: .network/.cache/.stale }`. Key = (kind, ASCII-lowercased name, rooted name distinct); only DNS answers are cached (literals, /etc/hosts, `.onion` pass through); positive and negative TTL clamps, `no_ttl_s` for an empty answer without SOA, `partial_ttl_s`; opt-in serve-stale (`stale_s`, RFC 8767 with the 30 s failure recheck); per-key exponential failure backoff; optional token-bucket budget (`error.BudgetExceeded`); LRU bound with expired-first eviction, `prune`, `clear`, `stats`; thread-safe (table mutex never held across a lookup; pooled Resolvers). **Tests:** loopback stub with a query counter and an injected clock — hit/expiry/aging, both clamps, NXDOMAIN/NODATA, no-SOA, partial, literals, case and root dot, stale on SERVFAIL and timeout, backoff doubling/cap/reset, budget, LRU, prune, InvalidOptions, backwards clock, failing allocator, every lookup kind, four threads.
- **2026-11-15** — **NO CONSUMER-VISIBLE CHANGE:** documentation wording (consumer project names removed). Source changes are comment and test-label text only; the card's audit `src` hash is re-recorded over them (the audited code is unchanged).
- **2026-11-15** — **NO CONSUMER-VISIBLE CHANGE:** delta mutation audit of the API wave (49 schemata mutants, 49/49 killed after six new tests: hosts family filter, per-family TTL and AD folds, `reverse` SERVFAIL, resolv.conf unchanged and same-tick size-only rewrite); card Audit line and grade regenerated (3, limited by scope `core`); SPEC competitor sources dated.
- **2026-11-15** — **BREAKING (CONSUMER-VISIBLE):** one result shape for every high-level lookup. `lookupIp`, `reverse`, `lookupCname`, `lookupMx`/`Ns`/`Txt`/`Srv` all return `Resolver.Lookup(T)` (arena-owned; `deinit`, new `clone(gpa)`) with `items`, `status: Resolver.Status` (`.found` / `.nxdomain` / `.nodata` — search list: NODATA outranks NXDOMAIN as in glibc `res_search`), `ttl_s` (min over records + CNAME chain; RFC 2308 negative TTL from the SOA; null for literals/hosts), `canonical` (end of the CNAME chain), `authenticated` (AD on every reply used; only with `Options.authentic_data`) and `partial` (lookupIp: one family failed — same meaning as before). `lookupIpTtl`, `reverseTtl`, `IpLookup`, `ReverseLookup` and `freeNames` are removed. Any rcode other than NOERROR/NXDOMAIN (FORMERR, YXDOMAIN … as well as SERVFAIL/REFUSED/NOTIMP) is now `error.ServerFailed` in every high-level call — `reverse` used to return an empty list for it. `lookupIp`/typed lookups no longer take A/AAAA records of the other type from a reply. Search list: a typed lookup now moves past a candidate whose reply holds no record of the type (as `lookupIp` and Go do) instead of stopping at any non-empty answer. **Added:** `Options.resolv_conf_recheck_ms` (default 5000: the outermost public call re-stats resolv.conf at most that often and re-reads it on an inode/size/mtime change; null = read once, the old behaviour; 0 = every call); `Options.case_randomization` (DNS 0x20, opt-in, UDP only, exact-case echo required). Migration:

  | before | after |
  |---|---|
  | `const ips = try r.lookupIp(n); defer gpa.free(ips); ips[i]` | `var l = try r.lookupIp(n); defer l.deinit(); l.items[i]` |
  | `const f = try r.lookupIpTtl(n); defer gpa.free(f.ips);` `f.ips` / `f.ttl_s` / `f.partial` | `var l = try r.lookupIp(n); defer l.deinit();` `l.items` / `l.ttl_s` / `l.partial` (+ `l.status`, `l.canonical`, `l.authenticated`) |
  | `const names = try r.reverse(ip); defer r.freeNames(names);` | `var l = try r.reverse(ip); defer l.deinit();` `l.items` (+ `l.ttl_s`, `l.status`, `l.canonical`) |
  | `const f = try r.reverseTtl(ip); defer r.freeNames(f.names);` `f.names` / `f.ttl_s` | `var l = try r.reverse(ip); defer l.deinit();` `l.items` / `l.ttl_s` |
  | `const c = try r.lookupCname(n); defer gpa.free(c);` | `var l = try r.lookupCname(n); defer l.deinit(); l.canonical.?` (`l.items` = the aliases) — or `.canonical` of any other lookup |
  | empty result read as "no such name" | `switch (l.status) { .found, .nxdomain, .nodata }` |
  | `reverse` on SERVFAIL → empty list | `error.ServerFailed` |

  **Tests:** every call against stubs with an authority section (new `stubResponseAuth`, `WireBuf.soaRr`): TTL over the CNAME chain and both families, NXDOMAIN vs NODATA with and without SOA, canonical name, AD on/off, hosts and literals, `clone`, search-list NODATA-over-NXDOMAIN, FORMERR → ServerFailed, 0x20 randomizes and drops a case-folded echo, resolv.conf reload (changed / `null` / throttled). **Scope:** parity → core (re-survey 2026-11-15: no answer cache, blocking only).
- **2026-11-15** — **CONSUMER-VISIBLE (additive):** `Resolver.reverseTtl` → `ReverseLookup{ names, ttl_s }`: `reverse` plus how long the answer may be cached — the smallest TTL of the PTR records and the CNAMEs on their chain (RFC 2317 delegation), or for an empty answer the SOA's negative TTL, `min(TTL, MINIMUM)` (RFC 2308 §5); null for /etc/hosts or an empty answer without SOA. Free `names` with `freeNames`. No `partial` (one query). `reverse` unchanged (now a wrapper). For callers that cache PTR answers like address lookups (the network-monitor consumer). **Tests:** PTR TTL minimum, CNAME chain, NXDOMAIN/NODATA negative TTL table, hosts, `reverse` parity.
- **2026-11-03** — **NO CONSUMER-VISIBLE CHANGE:** three test stubs counted a query after sending its reply, and a test reads the count as soon as it has the reply: `expected 2, found 1` in full CI 41660835693, reproduced with a 50 ms delay in the stub. Tests only.
- **2026-11-02** — **NO CONSUMER-VISIBLE CHANGE:** the bailiwick loopback test sends its queries in turn: its stub answers one datagram with an A question, so with parallel families an AAAA arriving first failed the test (full CI 41400687116).

- **2026-11-02** — **NO CONSUMER-VISIBLE CHANGE:** README: `lookupIp`'s time bound now says A and AAAA run together by default.

- **2026-11-02** — **Fixed (independent review of R5/R6/R8):** the parallel A/AAAA path copied the Resolver before its lazy state existed, so a fresh Resolver could load resolv.conf (and, for strict DoT, the system CA bundle, ~200 KB) twice and leak the copy's; both are now loaded first, which also makes resolv.conf `no-aaaa`/`single-request` count on the first lookup with `use_search = false`. `rotate` now advances past the AAAA query too. A null MX (RFC 7505, exchange ".") is no item of `lookupMx`. The DoT key entropy is wiped after the handshake. Documented: a parallel lookup can hold three concurrent tasks.
- **2026-11-02** — **Added** (S2 step R8, agent W, reviewed): DNS-over-TLS, RFC 7858 — `Transport.tls`, `Options.dot_port` (853), `tls_server_name` (SNI + certificate name; null = the server IP), `dot_tls` (strict by default); one TLS connection per exchange with RFC 1035 §4.2.2 framing, bounded by `timeout_ms`/`call_timeout_ms`; never a plain-DNS fallback. `Error.TlsFailed`, `Error.NoDotSupport` (a `-Ddns-dot=false` build, which is the `-Dprofile=small` default). New dependency `tlsclient`; `tlsserver` for tests. **Scope:** core → parity (R1–R8 of the 2026-11-01 survey closed).
- **2026-11-02** — **Added** (S2 steps R5 + R6): typed lookups `lookupMx` (by preference, equal ones random, RFC 5321 §5.1), `lookupNs`, `lookupTxt` (strings joined per record), `lookupCname` (the chain of an A answer, as Go; cut at 8 hops; `name` itself without CNAME), `lookupSrv` (`_service._proto.name`, RFC 2782 priority + weighted order; `.` targets dropped, a lone one = empty set) returning `Lookup(T)` (arena, `ttl_s`), owner-chain checked like `lookupIp`, plus pure `orderMx`/`orderSrv`; `Options.family` (`.any`/`.v4`/`.v6`, literals and /etc/hosts filtered), `Options.parallel_families = true`, `Options.rotate`; resolv.conf `rotate`, `single-request(-reopen)`, `use-vc`/`usevc`, `no-aaaa` honoured when read. **Changed (CONSUMER-VISIBLE):** `lookupIp`/`lookupIpTtl` send A and AAAA at the same time (Go/glibc/c-ares behaviour; `parallel_families = false` or resolv.conf `single-request` restores sequential); both queries allocate through a private lock, so a non-thread-safe `gpa` stays safe. **Tests:** typed-lookup stubs, SRV weight statistics (10,000 draws), parallel-vs-sequential timing stub, family filtering, resolv.conf options over three servers, an arena `gpa` under the parallel path; fuzz harness `dns-srv-order` (200,000 driver runs clean).
- **2026-11-02** — **Added** (S2 step R7): `dns.rdata` — typed, on-demand parsers over a record's raw rdata: `Tlsa` (RFC 6698), `Sshfp` (RFC 4255), `Uri` (RFC 7553), `Naptr` (RFC 3403), `Svcb` for SVCB/HTTPS (RFC 9460: strictly ascending params, §7 value shapes, `mandatory` cross-check; accessors `alpn`/`port`/`ipv4hint`/`ipv6hint`/`ech`/`mandatory`/`noDefaultAlpn`/`param`/`isAlias`), `parse(comptime T, arena, rec)`. No new `Record.Data` variant (dnssec's canonical form unchanged). **Tests:** dnspython 2.8.0 vectors (`tools/rdata_oracle.py` → `src/rdata_vectors.zig`), 29-case negative table, OOM loop, fuzz harness `dns-rdata` (200,000 driver runs clean); the `mandatory` presence check is one merge walk (a nested scan was quadratic in a hostile 64 KiB record).
- **2026-11-02** — **Added** (S2 step R4): special-use names, RFC 7686 §2 / RFC 6761 §6.4 — `config.isDnsAvoided`; `resolve` refuses a `.onion` / `.invalid` name with `error.BadName` and `lookupIp`/`lookupIpTtl` answer it empty after /etc/hosts, without sending a query (Go's `avoidDNS`); `query` stays unfiltered. **Consumer-visible:** a Tor name no longer leaks to the configured resolver.
- **2026-11-02** — **Added** (S2 step R3): `Options.call_timeout_ms` — a budget for one public call (`resolve`/`query`/`lookupIp`/`lookupIpTtl`/`reverse`/`exchange`/`queryJson`) across attempts, servers, candidates and families, Go's `ctx` deadline; each attempt waits for the earlier of `timeout_ms` and the rest of the budget; nested calls share the outer one; 0 (default) = unchanged behaviour. Not applied to DoH. Closes the SPEC Backlog "per-CALL deadline" item.
- **2026-11-02** — **Added** (S2 step R2): EDNS fallback, RFC 6891 §7 — a server that answers an EDNS query with FORMERR (no OPT of its own) or BADVERS is asked once more without OPT (and so without DO/options), and remembered per `Resolver` (≤ 8 servers) to be asked plainly from then on; never on SERVFAIL. Before, such a server failed every lookup while glibc (no EDNS by default) resolved. `Type` gains `naptr`, `sshfp`, `tlsa`, `svcb`, `https`, `uri` (non-exhaustive enum: source compatible). **Tests:** scripted `EdnsStub` (FORMERR-to-OPT, FORMERR-always = exactly one retry, BADVERS), bounded memory; the glibc rcode oracle test now runs EDNS-off like glibc's default.
- **2026-11-02** — **Added** (scope S2 step R1, survey 2026-11-01): `Header.authentic_data`/`checking_disabled` (decoded); `QueryOptions` and `Resolver.Options` `dnssec_ok` (RFC 3225 DO), `authentic_data` (RFC 6840 §5.7, glibc `trust-ad`), `checking_disabled` (RFC 4035 §3.2.2), `edns_options: []const EdnsOption` (RFC 6891 §6.1.2, ≤ `max_edns_options_len` = 128 B). `EncodeError` gains `EdnsRequired`, `TooManyOptions` (`writeName` keeps its own `NameError`); `Resolver.Error` gains `InvalidOptions`. **Changed (consumer-visible):** `max_query_len` grows by 128; `Resolver` clears a reply's AD bit unless `Options.authentic_data`. **Performance:** `tools/bench.zig` + `go_bench` vs Go dnsmessage v0.59.0: 0.29–0.68× (P2). **Tests:** `dns-query-roundtrip` fuzz harness.
- **2026-10-31** — **CONSUMER-VISIBLE:** `lookupIp`/`lookupIpTtl` answer `error.ServerFailed` (new `Error` member) when every server answered SERVFAIL/REFUSED/NOTIMP, instead of an empty list indistinguishable from NODATA (SPEC backlog since 2026-10-16; Go: "server misbehaving"). An exhaustive switch over `Resolver.Error` needs the new arm. `IpLookup.partial`: one family's query failed while the other answered.
- **2026-10-31** — **CONSUMER-VISIBLE (additive):** `Resolver.lookupIpTtl` → `IpLookup{ ips, ttl_s }`: `lookupIp` plus how long the answer may be cached — the smallest TTL of the address and CNAME records it was built from, or for an empty answer the SOA's negative TTL (RFC 2308 §5); null for a literal, /etc/hosts or an empty answer without SOA. For callers that keep addresses between lookups (the network-monitor consumer's per-target cache). `lookupIp` unchanged (now a wrapper).
- **2026-10-31** — **CONSUMER-VISIBLE (opt-in):** build option `-Ddns-doh` (default `true`; `-Dprofile=small` → `false`). Without DoH the `http` module and the TLS stack are not in the binary (size probe, ReleaseSmall: 1 811 032 → 175 160 B); a `Resolver` given `Options.doh_url` then refuses every query with `error.NoDohEndpoint` instead of falling back to plain DNS. New `Resolver.doh_enabled`. Default build unchanged.
- **2026-10-31** — **NO CONSUMER-VISIBLE CHANGE:** delta-audit tests for the § GV sweep (exchange drops a QR-clear datagram, DoH cap boundary, OOM sweep over `query`, bare TC reply → TCP) and their test stubs in `Resolver.zig`; no runtime code changed.
- **2026-10-31** — **CONSUMER-VISIBLE:** no-panic sweep + blind review (§ GV). New `Resolver.Error.RequestTooLarge`: `exchange` (and `update.send`) with a message over 65535 bytes returns it before sending (was a trap on the TCP length prefix). UDP: a datagram with our id that has QR clear, does not decode or asks another question is dropped and the wait goes on to the same deadline (one spoofed datagram no longer ends the query). `resolve` skips a search candidate that is not a valid name instead of aborting. `max_doh_response` = 65535 (RFC 8484). `decode` shares owner names that resolve to the same wire position (a 64 KiB pointer flood: 17.8 MB → 0.85 MB). TSIG `sign`/`verify` length guards, `update` clock clamp.
- **2026-10-24** — **NO CONSUMER-VISIBLE CHANGE:** the `strRepeat` helper (the Zig 0.17 stand-in for `**`) builds its string with one `@splat` + `@bitCast` instead of a comptime loop, which Sema evaluated in O(n²) (http's test binary: 323 s → 13 s). Same bytes, faster compile.

- **2026-10-18** — **NO CONSUMER-VISIBLE CHANGE:** Docs: README/SPEC brought up to Zig 0.17.0 (version statements, snippets, measurement labels).

- **2026-10-18** — Ported to Zig 0.17.0. `tsig.Algorithm.fromName` iterates `field_values`; test-only `ReadCueIo` overrides `vtable.operate` and counts `.net_read` (`Io.VTable.netRead` is gone). No behaviour change.
- **2026-10-17** — The private `src/b64ct.zig` is gone: `tsig.decodeSecret` uses the new `b64ct` module (`standard.decode`), same accept set. No API change.
- **2026-10-16** — Docs: Backlog entry — `lookupIp` reads a SERVFAIL reply as "no addresses". No code change.

- **2026-10-16** — New: `tsig.decodeSecret` — a TSIG secret from the base64 BIND, `nsupdate -y` and
  `tsig-keygen` carry, decoded constant-time (`b64ct.zig`, a copy of acme's). The test server in
  `tools/update_server.py` now chases CNAME chains inside its zones (acmedns's Pebble interop needs it).

- **2026-10-16** — **New: RFC 2136 dynamic update + RFC 8945 TSIG (client side).** `dns.update.Builder`
  (every prerequisite and update form, uncompressed) + `dns.update.send` (fresh id, optional TSIG,
  signed reply required, rcode returned); `dns.tsig.sign`/`verify` (HMAC-SHA1/224/256/384/512,
  request→response chaining, peer BADSIG/BADKEY/BADTIME, under a dead-stack burn); new
  `Resolver.exchange` (send a caller-built message to one server) and `Options.recursion_desired`
  (query an authoritative server with RD clear). Vocabulary: `Opcode.update`/`.notify`,
  `Type.tsig`/`.any`, `Class.none`. Byte-identical to dnspython 2.8.0; live against a dnspython
  RFC 2136 server with `nsupdate`/`dig` as controls (`tools/update_server.py check`). For acme's
  RFC 2136 DNS-01 publisher.

- **2026-10-09** — tests: deterministic fuzz driver `DNS_FUZZ` over the existing harnesses (decoder on arbitrary bytes, decoder on damaged captures).

- **2026-10-07** — **Fix (behaviour change), `Resolver.query` asks the next server when one fails.**
  A reply with SERVFAIL, NOTIMP or REFUSED used to be returned as the answer, so one broken or
  refusing first nameserver failed every lookup that getaddrinfo still resolved. Now such a reply
  sends the query on to the next server and the next attempt, as glibc 2.43 does (the glibc oracle
  gained an `rcodes` section: those three move on through every server and attempt, FORMERR and
  NXDOMAIN end the lookup at the first). If every server fails, the last failed reply is returned,
  so its rcode can still be read. New `pub fn serverFailed(Rcode) bool`. Anchored end to end: three
  stubs on 127.0.0.1-3 and the Resolver itself must ask the servers glibc asked, per rcode.

- **2026-10-06** — **Fix (behaviour change), `config.parseResolvConf` now does what glibc 2.43 does
  with the same file** (found by the new glibc oracle, `tools/config_oracle.py` →
  `src/config_oracle_test.zig`):
  - a `#` or `;` is a comment only in the first column: `search a.example # x` used to drop
    everything from `#`, glibc searches `#` and `x` too; `nameserver 192.0.2.1;x` used to be the
    server 192.0.2.1, glibc (and Go) refuse it;
  - option values read as atoi: `ndots:junk` is 0 (was: kept 1, so names were tried in the other
    order), `ndots:2x` is 2 (was: ignored); `timeout` below 1 becomes 1 and `attempts` below 1 keeps
    the default, as Go does (glibc would send no query at all);
  - up to 32 search domains instead of 6 (`max_search`): glibc has had no fixed limit since 2.26 and
    queried all eight of an eight-domain list.
  The hosts-file functions already agreed with glibc on every case.

- **2026-10-05** — **Fix:** an OPT record whose EDNS options do not tile its RDATA (an option length
  running past the end) is now `error.BadRecord`; it was decoded with the malformed stream handed on as
  `Opt.options`. Found by a golang.org/x/net/dns/dnsmessage differential oracle (`tools/go_oracle/`,
  replayed by `src/go_oracle.zig`: 81 messages, plus `encodeQuery` byte-identical to dnsmessage's
  Builder on 18 parameter sets); dnspython 2.8.0 decided the 6 listed divergences.

- **2026-10-04** — **Tests:** mutation run (54 schemata mutants, all killed after 15 new
  tests). Decoder edges (253-char name, exactly 16 pointer jumps, the 11-byte record
  pre-check factor, SOA name past RDLENGTH), class-IN-only CNAME chains, ';' comments in
  resolv.conf, the 253-char search-candidate cap, and over loopback: wrong-id and
  wrong-source-port datagrams skipped, a fresh transaction id per retry, `resolve` past a
  NODATA candidate, `lookupIp` stopping at the first candidate with addresses, DoH non-200
  refused on the wire and JSON paths. No code change.

- **2026-10-01** — **BEHAVIOURAL:** `lookupIp` no longer reports an outage as
  "no addresses". When no address was found and a query failed (timeout,
  network failure, malformed or spoofed answer), it returns that error
  instead of an empty slice — Go's behaviour, which this resolver models. An
  empty slice now means the servers answered and the name has no addresses;
  one family failing while the other answers is still tolerated. Found by
  `simio`'s dns pilot (server crashed → `lookupIp` returned `{}`).
- **2026-09-15** — **NO CONSUMER-VISIBLE CHANGE:** tests only. The `tcpExchange` cancel test
  canceled after a fixed 100 ms sleep. On a loaded machine that could land in the connect instead,
  and the test then passed by a different `Canceled` arm. It now cancels once the transport is
  inside its length read (`ReadCueIo`, a `std.Io` double that counts `netRead` entries). It also runs
  unbounded (`timeout_ms = 0`): with the default, `runBounded` answered the cancel itself, and a
  mutated length-read arm stayed green.

- **2026-09-12** — **A1 fix campaign round 2, fixer slot `c`: F7, F10 closed (Q7).**
  - **F7 — additive:** `Record` gains `labels: []const []const u8 = &.{}`, the owner name's
    actual wire label boundaries as slices into `Record.name`, populated by `decode` for every
    record. Closes the audit's demonstrated collision: `\x01a\x01b\x01c\x00` (3 labels),
    `\x05a.b.c\x00` (1 label) and `\x03a.b\x01c\x00` (2 labels) all decode to the identical text
    `"a.b.c"`, but now carry `.labels` of length 3, 1 and 2 respectively — recoverable structure
    a consumer that needs true label counts (the sole consumer, `dnssec`) no longer has to guess
    at by counting dots. `Question.name` and RDATA-embedded names (CNAME/NS/PTR/MX/SOA/SRV
    targets) stay text-only — nothing reads their label structure, so nothing pays for it.
    New test "decode: Record.labels carries the wire structure text collapses (audit F7)"
    reproduces the exact three-record collision. RED (label-span write mutated to a no-op):
    compile succeeds, run crashes (`index out of bounds`, reading the never-initialized span
    buffer) — a legitimate failure, not a compile error. GREEN: `scripts/modtest dns`: 67/67
    (base 64; +2 F10's own tests below, +1 this one).
  - **F10 — BEHAVIOURAL, not breaking:** `config.ResolvConf.timeout_s`/`.attempts` were parsed,
    capped and tested but never read outside `config.zig` — an administrator's
    `options timeout:1 attempts:1`, written specifically to bound the F5 amplification (7
    minutes at the shipped defaults), was silently ignored. Q8 (round 2): chosen — honor
    resolv.conf when `Options.timeout_ms`/`.attempts` are left at their own struct defaults
    (now named `default_timeout_ms`/`default_attempts`) AND resolv.conf is in play (no explicit
    `Options.servers`); an explicit non-default value always wins. New
    `effectiveTimeoutMs`/`effectiveAttempts`, wired into `attemptDeadline` and `query`'s attempt
    loop — the one seam both the UDP receive bound and the TCP `runBounded` cancel already went
    through, so DoH (whose `total_timeout_ms` is set once at `init`, before resolv.conf is ever
    read) is deliberately untouched. RED: unit test on the two helpers, mutated to ignore `conf`
    entirely — `expected 1000, found 5000`; end-to-end test (a real bound-but-silent loopback
    UDP socket plus a resolv.conf fixture with `timeout:1 attempts:1`) — elapsed time exceeded
    the 5 s bound (old shape: 2 attempts × 5000 ms = 10 s). GREEN: both pass, `scripts/modtest
    dns`: 67/67, Debug and ReleaseFast.

- **2026-09-10** — **A1 fix campaign, F13.** A UDP reply bigger than the resolver's receive buffer
  used to be decoded truncated instead of retried over TCP whenever the server sent it without
  setting the TC bit — a real server does set TC when it knows a reply will not fit, but nothing
  stopped a broken or hostile one from sending an oversized reply and skipping it. `udpExchange` now
  also consults the kernel's own delivery flag (`IncomingMessage.flags.trunc`, `MSG_TRUNC`) and
  `query` retries over TCP on either signal — the TC bit the server set, or the kernel's own verdict
  that the datagram did not fit. Measured: a loopback stub sending a 1800-byte reply with TC clear
  against a 1232-byte `rbuf` — before the fix, `query` decoded the truncated bytes directly and
  never dialed TCP at all (confirmed by running the new test under the pre-fix code: `scripts/modtest
  dns -Dtest-filter=F13` timed out at its 25 s cap, `exit 124`, because the test's silent TCP peer was
  never connected to); after the fix the same scenario reaches TCP and the test passes in \<1 s.
  `test-dns`: 64/64 (was 63). SPEC's Backlog no longer lists this; the "consult `MSG_TRUNC`"
  bullet is done.

- **2026-09-09** — **NO CONSUMER-VISIBLE CHANGE:** the seven `test "live: …"` leave the module and
  become the program `tools/live.zig` (`zig build live-dns`). They talked to real resolvers —
  recursive UDP and TCP, reverse PTR of `8.8.8.8`, and the three DoH shapes against `dns.google` and
  `cloudflare-dns.com` — and each ended `catch |err| return skipLive(err)`, where `skipLive` printed
  `live dns test skipped: <error>` with `std.debug.print`, i.e. to stderr. `scripts/lib/test-lib.sh`
  treats stderr on an exit-0 step as a failure ("OK-but-stderr -> treated as FAIL"), so a slow DNS
  server turned `test-dns` red and took a 217-module run with it, with nothing in this module
  changed. ⭐ Silencing the print would have been the wrong fix and so would keeping the skip: a
  test that reports success for a run in which it did nothing is the defect, not the noise it makes.
  This is the third module to take the shape `Module.live`'s doc comment describes — `dtls` on
  2026-09-06, this module's own hostile-loopback anchor on 2026-09-07 — the anchor's VALUE replays
  hermetically in the lane that runs everywhere, the anchor's TAKING is a program. Nothing is lost:
  `zig build live-dns` runs all seven and reports which of the module or the network is suspected
  (7/7 green when this was written), and `zig build check-interop` compiles it so it cannot rot
  unnoticed. `test-dns` is now 63 tests, none of which reaches the network. Also here: the loopback
  listen in `test "tcpExchange: a canceled blocking read surfaces Canceled"` no longer skips with a
  stderr print — an ephemeral loopback bind that fails is a broken environment, and the honest
  report is a failure.

- **2026-09-08** — **NO CONSUMER-VISIBLE CHANGE:** the question-check anchor is split into a
  hermetic half and a live one (audit F20). `test "query: a reply whose question is not ours is
  not the answer, over loopback"` bound a UDP socket, spawned a stub on a second thread and then
  read that stub's `served` counter — from the test thread, while the stub was still runnable,
  because the joining `await` was a `defer`. It failed twice in the wild, always as
  `expected 1, found 0`, and reproduced here at **10 failures in 20 runs** on 8 cores under 32 busy
  loops. ⭐ The resolver was right every time: `found 0` on the counter means the datagram HAD been
  received and rejected, so what failed was the measurement, not `dns`. What the test asserted about
  parsing is now the test "decodeResponse: the replies interop-dns captured off a real socket",
  replaying `src/testdata/reply_wrong_question.bin`, `reply_no_question.bin` and — as the positive
  control — `reply_honest.bin`; it schedules nothing and passed 30 of 30 under the same load, as did
  the whole 70-test suite 10 of 10. What genuinely needs a socket is now the program
  `tools/interop.zig` (`zig build interop-dns`, no peer and no network; `-- --capture` re-takes the
  frames), compiled by `check-interop` and run by `scripts/test.sh interop`. The same
  read-before-join was fixed in the surviving TC-bit test, which had only ever been saved by the
  300 ms the resolver spends in the TCP path afterwards. `dns` was deliberately NOT added to the
  serial `live` set: an unsynchronised cross-thread read is not a scheduling accident, so serialising
  the module's other 69 tests would have bought a quieter race rather than a fixed one.

- **2026-09-07** — **NO CONSUMER-VISIBLE CHANGE:** the local `fuzzSeed` /
  `fuzzSeedInto` copies in this module's fuzz files are now `testkit.fuzz`. The
  helper existed **33 times across 12 modules in three shapes**, each carrying its
  own note about the same trap (the returned array has to be container-level or
  the slice dangles with the right length and garbage behind it). Proved
  byte-identical to the copies it replaces before they were deleted, and the
  comparison test was itself broken on purpose first to show it was not vacuous.
  `testkit` added to this module's `test_deps`; test-only, nothing a consumer
  imports changed.

- **2026-09-06** — A1 security audit, the four HIGH findings fixed. **Consumer-visible
  behaviour change (stricter acceptance, no new error values):** `Resolver` now refuses a
  reply that does not echo exactly our question — one question, our name (ASCII
  case-insensitive), our type, class IN — as `error.MalformedResponse` (RFC 5452 §9.1;
  before, id + QR bit was the whole check, so a reply whose question section named
  `attacker.example TXT`, or had no question section, was taken as the answer to
  `example.com A`). `lookupIp` and `reverse` return only records whose owner is the
  queried name or a CNAME target chained from it inside the same answer section (8 hops
  max; a reply to `example.com` carrying `victim.test A 203.0.113.66` used to yield that
  address). `resolve`/`query` are unchanged in what they return. `timeout_ms` now bounds
  each TCP attempt end to end — connect, write, length read, body read — by running the
  exchange on its own task and canceling it at the deadline (`runBounded`, the
  `http.Client` construction); before, only UDP was bounded, and a server that accepted
  the connection and never answered held the caller until the OS gave up (measured 45-60 s
  at `timeout_ms = 1000`), reachable on the default `.auto` transport by one TC-bit
  datagram. An `Io` with no unit of concurrency fails such an attempt as `NetworkFailed`
  rather than run it unbounded. `queryJson` validates `name` by the wire path's rule
  (`BadName`/`NameTooLong`) and percent-encodes it into the URL (`&`, `=`, CR, LF, space,
  `%` were passed through into the request line). A fresh transaction id is drawn for every
  datagram sent, not once per `query`. `Error.Timeout`'s doc now states the real budget
  (`timeout_ms × attempts × servers` per query, more for `lookupIp`) instead of
  `timeout_ms × attempts`. Tests: correlation, bailiwick (incl. out-of-order chain, loop,
  over-long chain), URL encoding, hostile section counts under a 4 KiB memory limit (the
  old test accepted `Truncated` from a decoder that had first allocated 8.6 MB), SOA/MX
  RDLENGTH shorter than their fields, and loopback stubs — a UDP server that lies about the
  question or slips in an off-bailiwick record, a TCP server that accepts and never
  answers, via both `.tcp` and the TC-bit path. The fuzz harness draws one `smith.slice`
  and is seeded with the six live captures (it had decoded the empty packet once per run).
- **2026-08-23** — **Breaking:** `reverseName` returns
  `ReverseNameError![]const u8` (`error{OutputTooSmall}`) instead of
  `[]const u8`. It used to guard `buf.len >= max_reverse_name_len` with
  `std.debug.assert`; the `std.Io.Writer.fixed` writes inside stay
  memory-safe regardless (they clamp to the buffer), but every one is
  `catch unreachable`, so ReleaseFast compiling the assert out turned a
  too-small `buf` into undefined behaviour (an `unreachable` hit) instead of
  a clean failure. Found by an audit sweep for this shape. `Resolver.reverse`
  and the example's `-x` path both size their buffer to exactly
  `max_reverse_name_len`, so the new error is provably unreachable there
  (`catch unreachable`).
- **2026-08-23** — `sortIps` no longer re-checks
  `netaddr.max_sort_candidates` before calling `sortDestinations`; the bound is
  enforced inside `netaddr` now that it returns an error, so the rule lives in
  one place. Behaviour is unchanged: an answer set larger than the bound is
  left in arrival order.

- **2026-08-22** — `tcpExchange` (the only place in this file that owns a TCP fd directly)
  used to fold every write (`writeInt`/`writeAll`/`flush`) and read (`takeInt`/
  `readSliceAll`) failure into `error.NetworkFailed`, including a canceled `std.Io` wait —
  `Io.Reader.Error`/`Io.Writer.Error` cannot carry `Canceled` at all, so the reason was gone
  by the time it reached the `catch`. Two new private helpers, `readFailure`/`writeFailure`,
  consult the concrete `Stream.Reader`/`Stream.Writer`'s out-of-band `err` field first and
  reuse the `Canceled` variant `Error` already carried — the surrounding `query()` callers
  already special-case `error.Canceled` on `tcpExchange`'s result, so no caller-side change
  was needed. `udpExchange` needed nothing: `Socket.Send`/`ReceiveTimeoutError` already carry
  `Io.Cancelable` intact, and every catch there already had an explicit `error.Canceled`
  arm. A new test drives `tcpExchange` against a loopback listener nobody ever accepts —
  `connect` and the length-prefixed write both still succeed (the kernel completes the
  handshake and buffers the write), so the read genuinely parks in `takeInt` (mutated:
  `expected error.Canceled, found error.NetworkFailed`; restored: green, 59/59). The write
  side (`writeFailure`) has no dedicated test, for the same reason a UDP send-side fix
  elsewhere in this collection has none: reliably parking a thread inside a blocking TCP
  write long enough for a cancel to land needs a full kernel send buffer, not reproducible
  here — it was made by inspection and symmetry with the read side instead.

  Audited but left alone: `acme`'s six `catch return error.X` sites named for this pass are
  all either over in-memory buffers (`std.Io.Writer.Allocating`, PEM/URL string encoding —
  no fd, nothing to lose) or already correctly widen `http.Client`'s errors through
  `mapHttpError`, which has an explicit `error.Canceled` arm; its one direct `Cancelable!void`
  call (`Client.sleepMs`'s `d.sleep`) already returns exactly `error.Canceled` on the only
  error it can produce. `dns`'s own `ensureConfig`/`readHosts` (local `/etc/hosts`/
  `resolv.conf` reads) were not touched either — a different site from the one named for this
  pass, local disk I/O rather than a TCP/UDP transport, and out of scope for this change.

  Found but out of module scope, not fixed here: `http.Client.Response.readAllAlloc`
  (`modules/http/src/Client.zig`) declares `Canceled` in its `Error` set but its own `catch
  |err| switch (err) { ..., else => error.ReadFailed }` never consults the concrete reader's
  `err` field, so a body-read cancellation cannot currently reach a caller through it at all —
  `dns`'s `dohExchange`/`queryJson` inherit this (their own `readAllAlloc` catches were left
  as `else => error.DohFailed` rather than given an `error.Canceled` arm, since one would be
  unreachable dead code against `readAllAlloc`'s current behavior and pure churn against
  CONVENTIONS.md's own "don't fix what can't see a cancel" guidance). Surfaced here since it
  was found auditing this module's DoH paths, but the fix belongs in `http`.
- **2026-08-18** — Re-export `message.max_query_len`, `message.QueryOptions` and
  `message.EncodeError` from the module root, so a codec-only consumer sizing/calling
  `encodeQuery` never has to name `dns.message` directly (which would put `Resolver`,
  and therefore the `http` dependency, in its import graph for no reason).
- **2026-07-19** — Security audit: one finding fixed (part of the collection-wide audit;
  the root changelog records no further detail than this). Live-tested against real
  UDP/TCP/DoH/DoH-JSON resolvers over the network (decode/encode vectors are
  self-authored, not captured).
- **2026-07-02** — New module: RFC 1035 resolver —
  A/AAAA/PTR/CNAME/NS/MX/TXT/SOA/SRV/CAA over UDP/TCP + DoH.
