const std = @import("std");
const builtin = @import("builtin");

// zig-libs — a curated collection of foundational Zig modules.
//
// Layout rationale: ONE build.zig at the repo root. `zig fetch` cannot target a
// subdirectory (ziglang/zig#23012), so a consumer fetches the whole repo and
// imports only the named module(s) it wants; the root build wires them up.
//
// Each module lives at modules/<name>/src/root.zig and is exposed as an
// importable module named <name>. `deps` lists sibling modules it imports.
// See CONVENTIONS.md for naming + the `meta` tag vocabulary.

pub const Module = struct {
    name: []const u8,
    deps: []const []const u8 = &.{},
    /// Modules this one imports ONLY from its tests (in practice: `testkit`).
    ///
    /// These are wired into the test binary and NOT into the module a
    /// downstream consumer imports, so `@import("frost")` does not drag a test
    /// harness along. That separation is the whole point of the field --
    /// putting testkit in `deps` would work and would also publish it.
    ///
    /// They DO appear in `module-graph`'s deps column, because that graph
    /// exists to tell `scripts/test.sh` what to re-test, and a change to
    /// testkit must re-test everything whose tests use it.
    test_deps: []const []const u8 = &.{},
    /// Modules ONLY its comparative benchmark (`tools/bench.zig`) imports,
    /// beside `deps` -- e.g. `kvtree`'s bench measures the production shape
    /// with a `pagecache` in front, and `pagecache` depends on `kvtree`, so it
    /// can be neither a dep nor a test dep. Never in the module, its tests or
    /// `module-graph`: the bench is run by hand, by no lane.
    bench_deps: []const []const u8 = &.{},
    /// This module ships `example/main.zig`: a consumer binary built by
    /// `zig build check-examples` against the PUBLISHED module — `deps` only,
    /// no `test_deps`, no reach into anything the module does not export.
    ///
    /// Declared here rather than probed from the tree so that both directions
    /// are checkable: an example that stops building is red, and so is one
    /// added without saying so (or a declaration whose file is gone).
    ///
    /// Scope survey 2026-08-21: 78 of 229 modules already have an in-repo
    /// consumer, and 93 more have a public surface under 25 functions (a third
    /// of those anchored to published vectors, where an internal vector test
    /// beats an example). The 57 with neither get one, widest surface first.
    /// Which logical library (or libraries) this module belongs to. The
    /// repository is `zig-libs`, plural: a `lib` is one of the six groupings a
    /// consumer actually shops in, and this is where that grouping is written
    /// down. FIRST entry is primary -- the section of the README catalog the
    /// module's row lives under, which `check-libs` holds to agreement.
    ///
    /// This is a hand-written note about where a module BELONGS, not a derived
    /// fact, and it lives here rather than in README prose or in 231 separate
    /// `meta` blocks for one reason: a taxonomy is reviewed as a list. You can
    /// only notice that something is filed wrong by seeing its neighbours.
    ///
    /// Extra entries are the point of the plural: a module can be worth
    /// reaching for from more than one library, and saying so is how a
    /// consumer on `net` finds out that `x509` is also theirs. Sixteen already
    /// have a dependency edge crossing a library boundary, which is where the
    /// initial second tags came from -- but the field is not limited to that
    /// evidence, because "would be useful for" is not the same relation as
    /// "is already imported by".
    ///
    /// No default: a new module has to be filed, and copying `_template`
    /// leaves a wrong answer rather than no answer, which the gate catches.
    libs: []const []const u8,
    /// Compute-bound: the tests are dominated by arithmetic (pairings,
    /// hash-based signatures, FHE, scrypt, RSA), which an unoptimized Debug
    /// build makes ~5x slower — `bls12_381` alone goes 35s -> 182s. These
    /// modules ARE the test suite's critical path, so they are built at
    /// ReleaseSafe when the requested mode is Debug. ReleaseSafe keeps every
    /// safety check; only Debug-specific behaviour (0xAA-poisoned undefined
    /// memory) is given up. Pass `-Dstrict-debug` to force real Debug — that
    /// is what the CI matrix does. Threshold: >15s measured serially.
    heavy: bool = false,
    /// This module's tests talk to a REAL external peer -- a running server, a
    /// foreign client -- not a fixture. Such tests are run serially, because
    /// four of them at once turned a module that passes 98/98 alone into 3/3
    /// failures: the contention is between the live peers, not the CPU.
    ///
    /// Declared rather than probed: nothing in the tree distinguishes a socket
    /// opened against a real peer from one opened against a fixture. It lives
    /// HERE, next to `heavy` and `example`, because it is the same kind of fact
    /// about the same thing, and `module-graph` publishes it so the shell
    /// scripts stop keeping their own copy of the list.
    ///
    /// `jinja` is deliberately absent: its live peer is a Python script it runs
    /// to completion, not a network peer with a clock.
    ///
    /// `dtls` LEFT this list on 2026-09-06 and the reason generalises: its
    /// wolfSSL peer moved to `tools/interop.zig`, so `test-dtls` no longer
    /// opens anything at all -- it replays a captured transcript. A module
    /// whose foreign peer lives under `tools/` is never `live`, because the
    /// thing this flag serialises has left the test binary. Declaring it
    /// anyway costs the serial run for nothing.
    live: bool = false,
    /// Run this module's tests inside `unshare -rn` (a fresh network
    /// namespace) when the host allows it. For modules doing netlink WRITES:
    /// on a bare development host they would attempt real changes that
    /// collide with host state. Moved here from a list in
    /// `scripts/lib/test-lib.sh` on 2026-09-18, so it is part of the module's
    /// fingerprint -- it changes how the module's tests run -- and the driver
    /// scripts no longer have to be. Published as `module-graph` column 7.
    netns: bool = false,
    /// Some test asserts an upper bound on MEASURED time -- wall-clock or CPU
    /// time, or a ratio of two timings -- so it passes or fails with what else
    /// the machine is doing. Such a module runs serially, alone, after the
    /// parallel step, like `live` (2026-09-22). Beside 217 other test binaries
    /// every such bound is a load test that picks a random loser: five full-gate
    /// attempts on 2026-09-15 each failed on different tests (`http`, `k256`,
    /// `whois`, `p256`, `ramcache`, `uci`, ...), almost none of them a defect.
    ///
    /// The rule for setting it is the assertion, not the module's topic: an
    /// UPPER bound on something measured (`elapsed < budget`, `ratio < k`,
    /// `avg_ns < c`). A lower bound ("did not fire before 50 ms") cannot be
    /// broken by load, and a bound on a COUNT (`checks < n * 4`) is not time.
    /// A test rewritten to count instead of time takes its module off the list.
    ///
    /// NOT in the fingerprint, unlike `netns`: `netns` changes what a test can
    /// see, this changes only what runs beside it. Marking a module must not
    /// re-test it. Published as `module-graph` column 8.
    timing: bool = false,
    /// The tests talk to 127.0.0.1 / ::1, and `scripts/test.sh` runs them under
    /// `scripts/lib/netns-run`: a private network namespace with its own `lo`,
    /// as the calling user, with `ZIGLIBS_NETNS=1` so a loopback that does not
    /// work FAILS instead of skipping (`testkit.loopbackSkip`). On the host the
    /// same loopback is subject to the host's conntrack, firewall and port
    /// space (2026-10-01). Optional isolation for this repo's own lanes only:
    /// `zig build test-<name>` itself never needs a namespace, so a consumer
    /// runs the tests on plain loopback, as before.
    ///
    /// The rule for setting it is measured, not guessed: the module's test
    /// binary changes outcome when run under `netns-run` with `lo` left DOWN.
    /// A `live` module is not marked -- its peer (a podman container, a
    /// system ssh) does not run inside the namespace, and it runs serially on
    /// the host anyway. In the fingerprint, like `netns`: it changes what a
    /// test can see. Published as `module-graph` column 9.
    loopback: bool = false,
};

pub const module_list = [_]Module{
    // Test-only harness. Consumers reach it through `test_deps`, never `deps`.
    .{ .name = "testkit", .libs = &.{"os"} },
    .{ .name = "fastmem", .libs = &.{"os"} },
    .{ .name = "netaddr", .libs = &.{ "net", "web" }, .test_deps = &.{"testkit"}, .loopback = true },
    // `workerpool` is a TEST-only dep: `h2_server.Options.dispatcher` is an
    // injectable seam (a function pointer + a context pointer), so the
    // published `http` module implements no pool at all — deliberately, since
    // `websocket`/`accesslog`/`grpc`/`mcp-http`/… all depend on `http` and
    // none of them should acquire threads by transitive accident. The tests
    // wire a real `workerpool.WorkerPool` into that seam because the five
    // concurrency invariants can only be exercised by real threads.
    // `zig build check-testonly` proves the published module never needs it.
    .{ .name = "http", .libs = &.{ "web", "crypto", "format", "net" }, .deps = &.{ "netaddr", "datefmt", "tlsclient", "crc32", "b64ct" }, .test_deps = &.{ "testkit", "workerpool" }, .loopback = true },
    .{ .name = "websocket", .libs = &.{"web"}, .deps = &.{"http"}, .test_deps = &.{"testkit"}, .loopback = true },
    .{ .name = "accesslog", .libs = &.{"web"}, .deps = &.{ "http", "router" }, .test_deps = &.{"testkit"} },
    .{ .name = "staticfiles", .libs = &.{"web"}, .deps = &.{"http"}, .test_deps = &.{"testkit"} },
    .{ .name = "brotli", .libs = &.{"web"}, .test_deps = &.{"testkit"} },
    .{ .name = "zstd", .libs = &.{ "format", "storage", "web" }, .test_deps = &.{"testkit"}, .heavy = true },
    .{ .name = "dns", .libs = &.{"net"}, .deps = &.{ "netaddr", "http", "b64ct" }, .test_deps = &.{"testkit"}, .loopback = true },
    .{ .name = "ramcache", .libs = &.{ "storage", "net" }, .test_deps = &.{"testkit"} },
    .{ .name = "router", .libs = &.{"web"}, .deps = &.{ "http", "regex" }, .timing = true, .test_deps = &.{"testkit"}, .loopback = true },
    .{ .name = "ratelimit", .libs = &.{"web"}, .deps = &.{ "router", "http", "netaddr" }, .test_deps = &.{"testkit"}, .loopback = true },
    .{ .name = "abuseguard", .libs = &.{"web"}, .deps = &.{ "http", "netaddr", "router" }, .test_deps = &.{"testkit"}, .loopback = true },
    .{ .name = "throttle", .libs = &.{"web"}, .deps = &.{ "router", "http" }, .test_deps = &.{"testkit"}, .loopback = true },
    // Importable as @import("security-headers") — module names are plain
    // strings, the hyphen is fine (cf. the community's "known-folders").
    .{ .name = "security-headers", .libs = &.{"web"}, .deps = &.{ "router", "http" }, .test_deps = &.{"testkit"}, .loopback = true },
    .{ .name = "cors", .libs = &.{"web"}, .deps = &.{ "router", "http" }, .test_deps = &.{"testkit"}, .loopback = true },
    .{ .name = "metrics", .libs = &.{"web"}, .deps = &.{ "router", "http", "procnet" }, .test_deps = &.{"testkit"}, .loopback = true },
    .{ .name = "validate", .libs = &.{"web"}, .deps = &.{ "router", "http", "netaddr", "datefmt" }, .test_deps = &.{"testkit"}, .loopback = true },
    .{ .name = "openapi", .libs = &.{"web"}, .deps = &.{ "router", "http" }, .test_deps = &.{"testkit"}, .loopback = true },
    .{ .name = "health", .libs = &.{"web"}, .deps = &.{ "router", "http" } },
    .{ .name = "requestid", .libs = &.{"web"}, .deps = &.{ "router", "http" } },
    .{ .name = "linkheader", .libs = &.{"format"}, .test_deps = &.{"testkit"} },
    .{ .name = "cookies", .libs = &.{"format"}, .deps = &.{ "http", "aesgcm", "datefmt" }, .test_deps = &.{"testkit"} },
    .{ .name = "idempotency", .libs = &.{"web"}, .deps = &.{ "router", "http", "ramcache", "kv" } },
    .{ .name = "webhooksig", .libs = &.{"web"}, .deps = &.{ "router", "http", "b64ct" }, .test_deps = &.{"testkit"} },
    .{ .name = "tracecontext", .libs = &.{"web"}, .deps = &.{ "router", "http" }, .test_deps = &.{"testkit"} },
    // Importable as @import("aaa-gate") — hyphen OK, like security-headers.
    .{ .name = "aaa-gate", .libs = &.{"web"}, .deps = &.{ "router", "http", "b64ct", "cookies" }, .test_deps = &.{"testkit"}, .loopback = true },
    .{ .name = "resilience", .libs = &.{ "web", "net" }, .test_deps = &.{"testkit"} },
    .{ .name = "acme", .libs = &.{"web"}, .deps = &.{ "http", "router", "entropy", "p256", "p384", "p521", "rsa", "netaddr", "x509", "datefmt", "b64ct" }, .test_deps = &.{"testkit"}, .loopback = true },
    // DNS-01 helpers + publishers for acme; a sibling so acme's consumers do not carry dns/procrun.
    .{ .name = "acmedns", .libs = &.{"web"}, .deps = &.{ "acme", "dns", "http", "netaddr", "procrun", "b64ct" }, .test_deps = &.{"testkit"} },
    .{ .name = "netlink", .libs = &.{"net"}, .test_deps = &.{"testkit"}, .netns = true },
    .{ .name = "genetlink", .libs = &.{"net"}, .deps = &.{"netlink"}, .test_deps = &.{"testkit"}, .netns = true },
    .{ .name = "nl80211", .libs = &.{"net"}, .deps = &.{ "genetlink", "netlink" }, .test_deps = &.{"testkit"}, .netns = true },
    .{ .name = "ethtool", .libs = &.{"net"}, .deps = &.{ "genetlink", "netlink" }, .test_deps = &.{"testkit"}, .netns = true },
    .{ .name = "devlink", .libs = &.{"net"}, .deps = &.{ "genetlink", "netlink" }, .test_deps = &.{"testkit"}, .netns = true },
    .{ .name = "decimal", .libs = &.{ "storage", "format" }, .test_deps = &.{"testkit"} },
    .{ .name = "seqmap", .libs = &.{"net"} },
    .{ .name = "icmp", .libs = &.{"net"}, .deps = &.{ "seqmap", "netaddr" }, .test_deps = &.{"testkit"}, .timing = true, .loopback = true },
    .{ .name = "mcp", .libs = &.{"os"}, .test_deps = &.{"testkit"} },
    .{ .name = "mcp-http", .libs = &.{"os"}, .deps = &.{ "router", "http", "mcp" }, .test_deps = &.{"testkit"} },
    .{ .name = "coap", .libs = &.{"net"}, .test_deps = &.{"testkit"} },
    .{ .name = "crc32", .libs = &.{ "format", "storage" }, .test_deps = &.{"testkit"} },
    .{ .name = "crc32c", .libs = &.{ "format", "storage" }, .test_deps = &.{"testkit"} },
    .{ .name = "kv", .libs = &.{"storage"} },
    .{ .name = "kvtree", .libs = &.{ "storage", "net" }, .deps = &.{ "kv", "crc32" }, .test_deps = &.{"testkit"}, .bench_deps = &.{"pagecache"} },
    .{ .name = "blobmsg", .libs = &.{"format"}, .test_deps = &.{"testkit"} },
    .{ .name = "tar", .libs = &.{"format"}, .test_deps = &.{"testkit"} },
    .{ .name = "latency-stats", .libs = &.{"net"} },
    .{ .name = "pping", .libs = &.{"net"}, .test_deps = &.{"testkit"} },
    .{ .name = "spf-ect", .libs = &.{"net"} },
    .{ .name = "ethfrag", .libs = &.{"net"}, .test_deps = &.{"testkit"} },
    .{ .name = "l2encap", .libs = &.{"net"}, .test_deps = &.{"testkit"} },
    .{ .name = "l2forward", .libs = &.{"net"}, .test_deps = &.{"testkit"} },
    .{ .name = "pbb", .libs = &.{"net"}, .test_deps = &.{"testkit"} },
    .{ .name = "bumtree", .libs = &.{"net"}, .deps = &.{"spf-ect"} },
    .{ .name = "spbfib", .libs = &.{"net"}, .deps = &.{"isis-spf"} },
    .{ .name = "isis", .libs = &.{"net"}, .test_deps = &.{"testkit"} },
    .{ .name = "isis-adj", .libs = &.{"net"}, .deps = &.{"isis"}, .test_deps = &.{"testkit"} },
    .{ .name = "isis-dis", .libs = &.{"net"}, .deps = &.{"isis"} },
    .{ .name = "isis-lsdb", .libs = &.{"net"}, .deps = &.{"isis"}, .test_deps = &.{"testkit"} },
    .{ .name = "isis-flood", .libs = &.{"net"}, .deps = &.{ "isis", "isis-lsdb" } },
    .{ .name = "isis-spf", .libs = &.{"net"}, .deps = &.{ "isis", "isis-lsdb", "spf-ect" }, .test_deps = &.{"testkit"} },
    .{ .name = "isis-sim", .libs = &.{"net"}, .deps = &.{ "netsim", "isis", "isis-lsdb", "isis-flood", "isis-spf", "isis-dis" } },
    .{ .name = "aeadframe", .libs = &.{"crypto"}, .deps = &.{"chachapoly"}, .test_deps = &.{"testkit"} },
    .{ .name = "tenantkex", .libs = &.{"crypto"}, .deps = &.{"noise"}, .test_deps = &.{"testkit"} },
    .{ .name = "netsim", .libs = &.{"net"} },
    .{ .name = "simio", .libs = &.{"net"}, .deps = &.{"netsim"}, .test_deps = &.{ "testkit", "sntp", "dns", "netaddr", "mqtt", "ssh", "kv", "http", "icmp", "modbus", "whois", "stun", "ocspcache", "llmclient", "staticfiles" }, .loopback = true },
    .{ .name = "loopfree-reconv", .libs = &.{"net"}, .deps = &.{ "netsim", "spf-ect" } },
    .{ .name = "df-elect", .libs = &.{"net"}, .deps = &.{"netsim"}, .test_deps = &.{"testkit"} },
    .{ .name = "raft", .libs = &.{"net"}, .deps = &.{"netsim"}, .test_deps = &.{"testkit"} },
    .{ .name = "liveness-hyst", .libs = &.{"net"}, .deps = &.{ "netsim", "latency-stats" } },
    .{ .name = "loopix", .libs = &.{"net"}, .deps = &.{ "netsim", "sphinx" }, .test_deps = &.{"testkit"} },
    .{ .name = "lockfree", .libs = &.{"net"} },
    .{ .name = "workerpool", .libs = &.{"net"}, .deps = &.{"lockfree"} },
    .{ .name = "shardstore", .libs = &.{"net"}, .deps = &.{"kvtree"} },
    .{ .name = "writebehind", .libs = &.{"net"}, .deps = &.{ "ramcache", "workerpool", "jobqueue", "kvtree" } },
    .{ .name = "pagecache", .libs = &.{"net"}, .deps = &.{ "kvtree", "ramcache" } },
    .{ .name = "tsdb", .libs = &.{"storage"}, .deps = &.{"kvtree"}, .test_deps = &.{"testkit"} },
    .{ .name = "entropy", .libs = &.{ "crypto", "web" } },
    .{ .name = "hashdigest", .libs = &.{ "crypto", "storage" } },
    .{ .name = "sealedbox", .libs = &.{"crypto"}, .deps = &.{"ct25519"}, .test_deps = &.{"testkit"} },
    .{ .name = "rsa", .libs = &.{ "crypto", "net", "web" }, .deps = &.{ "montint", "aescbc", "aes192", "b64ct" }, .test_deps = &.{"testkit"}, .heavy = true },
    .{ .name = "blindrsa", .libs = &.{"crypto"}, .deps = &.{"rsa"}, .test_deps = &.{"testkit"} },
    .{ .name = "ssh", .libs = &.{"net"}, .deps = &.{ "rsa", "montint", "aes192", "p521", "b64ct", "aesgcm" }, .test_deps = &.{"testkit"}, .heavy = true, .live = true },
    .{ .name = "netconf", .libs = &.{"net"}, .deps = &.{ "ssh", "xml" }, .test_deps = &.{"testkit"} },
    .{ .name = "nftables", .libs = &.{"net"}, .deps = &.{"netlink"}, .test_deps = &.{"testkit"}, .netns = true },
    .{ .name = "trie", .libs = &.{"storage"}, .test_deps = &.{"testkit"} },
    .{ .name = "fuzzysearch", .libs = &.{"storage"}, .deps = &.{"trie"}, .test_deps = &.{"testkit"} },
    .{ .name = "regex", .libs = &.{ "format", "web" }, .test_deps = &.{"testkit"} },
    .{ .name = "geoindex", .libs = &.{"storage"}, .test_deps = &.{"testkit"} },
    .{ .name = "readthrough", .libs = &.{"net"}, .deps = &.{"ramcache"} },
    .{ .name = "timelock_envelope", .libs = &.{"crypto"}, .deps = &.{ "tlock", "hqc", "chachapoly", "entropy" }, .test_deps = &.{"testkit"} },
    .{ .name = "drand", .libs = &.{"crypto"}, .deps = &.{ "bls12_381", "tlock" }, .test_deps = &.{"testkit"} },
    .{ .name = "tcplan", .libs = &.{"net"}, .deps = &.{"tc"} },
    .{ .name = "modbus", .libs = &.{"net"}, .test_deps = &.{"testkit"}, .loopback = true },
    .{ .name = "iec104", .libs = &.{"net"}, .test_deps = &.{"testkit"}, .loopback = true },
    .{ .name = "fleetsim", .libs = &.{"net"}, .deps = &.{ "modbus", "dnp3", "iec104", "s7comm", "bacnet", "enip", "opcua", "netsim" }, .test_deps = &.{"testkit"}, .loopback = true },
    .{ .name = "smtp", .libs = &.{"net"}, .deps = &.{ "netaddr", "b64ct" }, .test_deps = &.{"testkit"}, .timing = true },
    .{ .name = "imap", .libs = &.{"net"}, .test_deps = &.{"testkit"}, .live = true },
    .{ .name = "iec61850", .libs = &.{"net"}, .deps = &.{"xml"}, .test_deps = &.{"testkit"}, .loopback = true },
    .{ .name = "iec62351", .libs = &.{"net"}, .deps = &.{ "x509", "rsa", "p256", "aesgcm" }, .test_deps = &.{ "testkit", "iec61850" } },
    .{ .name = "s7comm", .libs = &.{"net"}, .test_deps = &.{"testkit"}, .loopback = true },
    .{ .name = "enip", .libs = &.{"net"}, .deps = &.{"netaddr"}, .test_deps = &.{"testkit"}, .loopback = true },
    .{ .name = "bacnet", .libs = &.{"net"}, .deps = &.{ "netaddr", "websocket" }, .test_deps = &.{"testkit"} },
    .{ .name = "whois", .libs = &.{"net"}, .deps = &.{"netaddr"}, .test_deps = &.{"testkit"}, .timing = true, .loopback = true },
    .{ .name = "uci", .libs = &.{"os"}, .test_deps = &.{"testkit"}, .timing = true },
    .{ .name = "mqtt", .libs = &.{"net"}, .deps = &.{"b64ct"}, .test_deps = &.{ "testkit", "websocket", "http", "tlsclient" }, .loopback = true }, // websocket/http: the MQTT-over-WebSocket recipe test; tlsclient: the TLS case of tools/interop.zig
    .{ .name = "snmp", .libs = &.{"net"}, .test_deps = &.{"testkit"}, .loopback = true },
    .{ .name = "wireguard", .libs = &.{"net"}, .deps = &.{ "netlink", "genetlink", "chachapoly", "entropy", "netaddr", "b64ct" }, .test_deps = &.{"testkit"}, .netns = true },
    .{ .name = "tc", .libs = &.{"net"}, .deps = &.{"netlink"}, .test_deps = &.{"testkit"}, .netns = true, .timing = true },
    .{ .name = "traceroute", .libs = &.{"net"}, .deps = &.{ "icmp", "netaddr", "latency-stats" }, .test_deps = &.{"testkit"} },
    .{ .name = "probe", .libs = &.{"net"}, .deps = &.{ "netaddr", "latency-stats" }, .test_deps = &.{"testkit"}, .loopback = true },
    .{ .name = "pathmtu", .libs = &.{"net"}, .deps = &.{ "icmp", "netaddr" }, .test_deps = &.{"testkit"}, .loopback = true },
    .{ .name = "l2disco", .libs = &.{"net"}, .deps = &.{"netaddr"}, .test_deps = &.{"testkit"} },
    .{ .name = "upstream", .libs = &.{"web"}, .deps = &.{ "resilience", "probe" } },
    .{ .name = "jwt", .libs = &.{"web"}, .deps = &.{ "http", "router", "p256", "p384", "p521", "rsa", "ct25519", "b64ct" }, .test_deps = &.{"testkit"}, .loopback = true },
    .{ .name = "rbac", .libs = &.{"web"} },
    .{ .name = "xml", .libs = &.{ "web", "net" }, .test_deps = &.{"testkit"} },
    .{ .name = "xmldsig", .libs = &.{"web"}, .deps = &.{ "xml", "rsa", "p256" }, .test_deps = &.{"testkit"} },
    .{ .name = "saml", .libs = &.{"web"}, .deps = &.{ "xmldsig", "xml", "xmlenc", "rsa", "x509", "datefmt" }, .heavy = true, .test_deps = &.{"testkit"} },
    .{ .name = "xmlenc", .libs = &.{"web"}, .deps = &.{ "xml", "rsa", "aescbc", "aeskw", "aes192", "aesgcm" }, .heavy = true, .test_deps = &.{"testkit"} },
    .{ .name = "aescbc", .libs = &.{ "web", "crypto" }, .test_deps = &.{ "testkit", "aes192" } }, // aes192: the AES-192 KAT/fuzz cases (the API is generic over the cipher type)
    .{ .name = "aeskw", .libs = &.{"web"}, .deps = &.{"aes192"}, .test_deps = &.{"testkit"} }, // aes192: the 24-byte KEK arm
    .{ .name = "aes192", .libs = &.{"crypto"}, .test_deps = &.{"testkit"} },
    .{ .name = "p521", .libs = &.{"crypto"}, .deps = &.{"entropy"}, .test_deps = &.{"testkit"} },
    .{ .name = "p384", .libs = &.{"crypto"}, .deps = &.{"entropy"}, .test_deps = &.{"testkit"} },
    .{ .name = "jwe", .libs = &.{"web"}, .deps = &.{ "rsa", "p256", "aescbc", "aeskw", "aes192", "aesgcm" }, .test_deps = &.{"testkit"} },
    .{ .name = "rdap", .libs = &.{"net"}, .deps = &.{ "http", "netaddr" }, .test_deps = &.{"testkit"}, .loopback = true },
    .{ .name = "blobstore", .libs = &.{"storage"}, .deps = &.{"hashdigest"} },
    .{ .name = "procnet", .libs = &.{"net"}, .deps = &.{"netaddr"}, .test_deps = &.{"testkit"} },
    .{ .name = "diskfree", .libs = &.{"os"}, .test_deps = &.{"testkit"} },
    .{ .name = "diskusage", .libs = &.{"os"}, .test_deps = &.{"testkit"} },
    .{ .name = "conntrack", .libs = &.{"net"}, .deps = &.{ "netlink", "netaddr" }, .test_deps = &.{"testkit"}, .netns = true },
    .{ .name = "procrun", .libs = &.{"os"}, .deps = &.{"argsafe"}, .timing = true },
    .{ .name = "dataset", .libs = &.{"storage"}, .test_deps = &.{"testkit"} },
    .{ .name = "tabular", .libs = &.{"storage"}, .deps = &.{"dataset"} },
    .{ .name = "jsonshape", .libs = &.{"storage"}, .deps = &.{"dataset"} },
    .{ .name = "finstats", .libs = &.{"storage"}, .deps = &.{"dataset"} },
    .{ .name = "filestore", .libs = &.{"storage"} },
    .{ .name = "framing", .libs = &.{ "format", "os" }, .test_deps = &.{"testkit"} },
    .{ .name = "datefmt", .libs = &.{"format"} },
    .{ .name = "diagnostics", .libs = &.{"os"} },
    .{ .name = "json5", .libs = &.{"format"}, .test_deps = &.{"testkit"} },
    .{ .name = "ini", .libs = &.{"format"}, .test_deps = &.{"testkit"} },
    .{ .name = "yaml", .libs = &.{"format"}, .test_deps = &.{"testkit"} },
    .{ .name = "jinja", .libs = &.{"format"}, .test_deps = &.{"testkit"} },
    .{ .name = "cbor", .libs = &.{"format"}, .test_deps = &.{"testkit"} },
    .{ .name = "protobuf", .libs = &.{ "format", "web" }, .test_deps = &.{"testkit"} },
    .{ .name = "grpc", .libs = &.{"web"}, .deps = &.{ "http", "protobuf", "b64ct" }, .test_deps = &.{"testkit"} },
    .{ .name = "webauthn", .libs = &.{"crypto"}, .deps = &.{ "cbor", "rsa", "p256", "x509" }, .test_deps = &.{"testkit"} },
    .{ .name = "zipstream", .libs = &.{"format"}, .test_deps = &.{"testkit"} },
    .{ .name = "qr", .libs = &.{"format"}, .test_deps = &.{"testkit"} },
    .{ .name = "qrscan", .libs = &.{"format"}, .deps = &.{"qr"}, .test_deps = &.{"testkit"} },
    .{ .name = "tz", .libs = &.{"format"}, .deps = &.{"datefmt"}, .test_deps = &.{"testkit"} },
    .{ .name = "pollworker", .libs = &.{"os"} },
    .{ .name = "ipcbus", .libs = &.{"os"}, .deps = &.{"framing"} },
    .{ .name = "csvstream", .libs = &.{"format"}, .test_deps = &.{"testkit"} },
    .{ .name = "csvsafe", .libs = &.{"format"} },
    .{ .name = "numparse", .libs = &.{"format"}, .deps = &.{"decimal"} },
    .{ .name = "argsafe", .libs = &.{"os"} },
    .{ .name = "sessions", .libs = &.{"web"}, .deps = &.{ "router", "http", "cookies", "ramcache", "entropy", "kv" }, .test_deps = &.{"testkit"} },
    .{ .name = "jobqueue", .libs = &.{"storage"}, .deps = &.{"kv"} },
    .{ .name = "reconcilable", .libs = &.{"net"}, .deps = &.{"resilience"} },
    .{ .name = "llmclient", .libs = &.{"web"}, .deps = &.{"http"}, .timing = true, .test_deps = &.{"testkit"}, .loopback = true },
    .{ .name = "rawsock", .libs = &.{"net"}, .deps = &.{"netaddr"}, .test_deps = &.{"testkit"}, .netns = true },
    .{ .name = "encoding", .libs = &.{"format"}, .test_deps = &.{"testkit"} },
    .{ .name = "base32", .libs = &.{"format"}, .test_deps = &.{"testkit"} },
    .{ .name = "syslog", .libs = &.{"net"}, .deps = &.{"datefmt"} },
    .{ .name = "sntp", .libs = &.{"net"}, .test_deps = &.{"testkit"} },
    .{ .name = "stun", .libs = &.{"net"}, .deps = &.{"netaddr"}, .test_deps = &.{"testkit"}, .loopback = true },
    .{ .name = "opcua", .libs = &.{"net"}, .deps = &.{ "rsa", "x509" }, .test_deps = &.{"testkit"}, .heavy = true, .live = true },
    .{ .name = "noise", .libs = &.{"crypto"}, .deps = &.{ "chachapoly", "aesgcm" }, .test_deps = &.{"testkit"} },
    .{ .name = "x509", .libs = &.{ "crypto", "net" }, .deps = &.{ "rsa", "slhdsa", "p521", "p256", "netaddr" }, .test_deps = &.{"testkit"} },
    .{ .name = "ocsp", .libs = &.{"crypto"}, .deps = &.{ "x509", "rsa", "p256" }, .heavy = true, .test_deps = &.{"testkit"} },
    .{ .name = "ocspcache", .libs = &.{"crypto"}, .deps = &.{ "ocsp", "http", "x509" }, .test_deps = &.{"testkit"}, .timing = true, .loopback = true },
    .{ .name = "dnssec", .libs = &.{"net"}, .deps = &.{ "dns", "rsa", "base32" }, .test_deps = &.{"testkit"} },
    .{ .name = "dnp3", .libs = &.{"net"}, .deps = &.{ "aeskw", "aesgcm" }, .test_deps = &.{"testkit"} },
    .{ .name = "slhdsa", .libs = &.{"crypto"}, .test_deps = &.{"testkit"}, .heavy = true },
    .{ .name = "falcon", .libs = &.{"crypto"}, .test_deps = &.{"testkit"} },
    .{ .name = "hqc", .libs = &.{"crypto"}, .test_deps = &.{"testkit"}, .heavy = true },
    .{ .name = "dtls", .libs = &.{"crypto"}, .deps = &.{ "rsa", "x509", "chachapoly", "aesgcm", "tls13" }, .test_deps = &.{"testkit"} },
    .{ .name = "tlsclient", .libs = &.{ "crypto", "net" }, .deps = &.{ "x509", "p256", "p384", "p521", "rsa", "tlsresume" }, .test_deps = &.{"testkit"}, .loopback = true }, // x509: RFC 5280 chain verification + DER guard
    .{ .name = "tls13", .libs = &.{"crypto"}, .deps = &.{"rsa"}, .test_deps = &.{"testkit"} }, // shared TLS 1.3 core of dtls and (planned) tlsserver
    .{ .name = "tlsresume", .libs = &.{"crypto"}, .deps = &.{"aesgcm"}, .test_deps = &.{"testkit"} },
    .{ .name = "quic-crypto", .libs = &.{"crypto"}, .deps = &.{ "chachapoly", "aesgcm" }, .test_deps = &.{"testkit"} },
    .{ .name = "sandbox", .libs = &.{"os"} },
    .{ .name = "bip340", .libs = &.{"crypto"}, .deps = &.{"k256"}, .test_deps = &.{"testkit"} },
    .{ .name = "taproot", .libs = &.{"crypto"}, .deps = &.{ "bip340", "k256" }, .test_deps = &.{"testkit"} },
    .{ .name = "bitcointx", .libs = &.{"crypto"}, .deps = &.{"bip340"}, .test_deps = &.{"testkit"} },
    .{ .name = "psbt", .libs = &.{"crypto"}, .deps = &.{ "bitcointx", "bitcoinscript", "ripemd160" }, .test_deps = &.{"testkit"} },
    .{ .name = "bitcoinscript", .libs = &.{"crypto"}, .deps = &.{ "bitcointx", "k256", "bip340", "ripemd160" }, .test_deps = &.{ "testkit", "taproot" } },
    .{ .name = "btcp2p", .libs = &.{"crypto"}, .deps = &.{"bitcointx"}, .test_deps = &.{"testkit"} },
    .{ .name = "lnwire", .libs = &.{"crypto"}, .test_deps = &.{"testkit"} },
    .{ .name = "lninvoice", .libs = &.{"crypto"}, .deps = &.{ "bech32", "k256", "lnwire", "bip340" }, .test_deps = &.{"testkit"} },
    .{ .name = "musig2", .libs = &.{"crypto"}, .deps = &.{ "bip340", "k256" }, .test_deps = &.{"testkit"} },
    .{ .name = "sphinx", .libs = &.{ "crypto", "net" }, .deps = &.{"k256"}, .test_deps = &.{"testkit"} },
    .{ .name = "bolt8", .libs = &.{"crypto"}, .deps = &.{ "noise", "k256" }, .test_deps = &.{"testkit"} },
    .{ .name = "bolt3", .libs = &.{"crypto"}, .deps = &.{"k256"}, .test_deps = &.{"testkit"} },
    .{ .name = "hpke", .libs = &.{"crypto"}, .deps = &.{ "p256", "chachapoly", "entropy", "p521", "aesgcm" }, .test_deps = &.{"testkit"} },
    .{ .name = "adaptor", .libs = &.{"crypto"}, .deps = &.{ "bip340", "k256" }, .test_deps = &.{"testkit"} },
    .{ .name = "frost", .libs = &.{"crypto"}, .deps = &.{ "bip340", "k256" }, .test_deps = &.{"testkit"} },
    .{ .name = "oscore", .libs = &.{"crypto"}, .test_deps = &.{"testkit"} },
    .{ .name = "spake2plus", .libs = &.{"crypto"}, .deps = &.{"p256"}, .test_deps = &.{"testkit"} },
    .{ .name = "ct25519", .libs = &.{"crypto"}, .deps = &.{"entropy"}, .test_deps = &.{"testkit"} },
    .{ .name = "voprf", .libs = &.{"crypto"}, .deps = &.{"ct25519"}, .test_deps = &.{"testkit"} },
    .{ .name = "opaque", .libs = &.{"crypto"}, .deps = &.{ "voprf", "ct25519" }, .test_deps = &.{"testkit"} },
    .{ .name = "bulletproofs", .libs = &.{"crypto"}, .deps = &.{"ct25519"}, .test_deps = &.{"testkit"} },
    .{ .name = "xmss", .libs = &.{"crypto"}, .test_deps = &.{"testkit"}, .heavy = true },
    .{ .name = "minisign", .libs = &.{"crypto"}, .deps = &.{ "entropy", "b64ct" }, .heavy = true, .test_deps = &.{"testkit"} },
    .{ .name = "otp", .libs = &.{"crypto"}, .deps = &.{"base32"}, .test_deps = &.{"testkit"} },
    .{ .name = "ctap2pin", .libs = &.{"crypto"}, .deps = &.{"p256"}, .test_deps = &.{"testkit"} },
    .{ .name = "ctap2", .libs = &.{"crypto"}, .deps = &.{ "cbor", "ctap2pin" }, .test_deps = &.{"testkit"} },
    .{ .name = "bls12_381", .libs = &.{"crypto"}, .deps = &.{ "entropy", "montint" }, .test_deps = &.{"testkit"}, .heavy = true },
    .{ .name = "bbs", .libs = &.{"crypto"}, .deps = &.{ "bls12_381", "entropy" }, .test_deps = &.{"testkit"} },
    .{ .name = "coconut", .libs = &.{"crypto"}, .deps = &.{"bls12_381"}, .heavy = true, .test_deps = &.{"testkit"} },
    .{ .name = "tlock", .libs = &.{"crypto"}, .deps = &.{ "bls12_381", "entropy", "chachapoly" }, .test_deps = &.{"testkit"} },
    // `tlock` is a TEST-only dep: `ibe/src/kat_test.zig` drives `ibe`'s own
    // encrypt/decrypt through `ibe.Scheme` with drand's ciphersuite, to
    // byte-compare against the genuine drand-Go-produced ciphertext `tlock`
    // already has frozen. The published `ibe` module never imports it --
    // `zig build check-testonly` proves that.
    .{ .name = "ibe", .libs = &.{"crypto"}, .deps = &.{ "bls12_381", "entropy" }, .test_deps = &.{ "tlock", "testkit" }, .heavy = true },
    .{ .name = "bn254", .libs = &.{"crypto"}, .deps = &.{"montint"}, .test_deps = &.{"testkit"}, .heavy = true },
    .{ .name = "ed448", .libs = &.{"crypto"}, .deps = &.{"entropy"}, .test_deps = &.{"testkit"} },
    .{ .name = "decaf448", .libs = &.{"crypto"}, .deps = &.{"ed448"}, .test_deps = &.{"testkit"} },
    .{ .name = "paillier", .libs = &.{"crypto"}, .deps = &.{"montint"}, .test_deps = &.{"testkit"}, .heavy = true },
    .{ .name = "threshold_ecdsa", .libs = &.{"crypto"}, .deps = &.{ "paillier", "montint" }, .heavy = true, .test_deps = &.{"testkit"} },
    .{ .name = "dkg", .libs = &.{"crypto"}, .deps = &.{ "threshold_ecdsa", "paillier" }, .heavy = true, .test_deps = &.{"testkit"} },
    .{ .name = "vdf", .libs = &.{"crypto"}, .deps = &.{"montint"}, .test_deps = &.{"testkit"} },
    .{ .name = "signal", .libs = &.{"crypto"}, .deps = &.{ "chachapoly", "ct25519", "entropy" }, .test_deps = &.{"testkit"} },
    .{ .name = "mls", .libs = &.{"crypto"}, .deps = &.{ "hpke", "aesgcm" }, .test_deps = &.{"testkit"} },
    .{ .name = "megolm", .libs = &.{"crypto"}, .deps = &.{ "aescbc", "entropy", "chachapoly", "b64ct" }, .test_deps = &.{"testkit"} },
    .{ .name = "ebpf", .libs = &.{"net"}, .deps = &.{"netlink"}, .test_deps = &.{"testkit"} },
    .{ .name = "xdp-classifier", .libs = &.{"net"}, .deps = &.{"ebpf"}, .test_deps = &.{"testkit"} },
    .{ .name = "ecvrf", .libs = &.{"crypto"}, .deps = &.{"ct25519"}, .test_deps = &.{"testkit"} },
    .{ .name = "fss", .libs = &.{"crypto"}, .test_deps = &.{"testkit"} },
    .{ .name = "pir", .libs = &.{"crypto"}, .deps = &.{"fss"}, .test_deps = &.{"testkit"} },
    .{ .name = "bfv", .libs = &.{"crypto"}, .deps = &.{"entropy"}, .test_deps = &.{"testkit"} },
    .{ .name = "groth16", .libs = &.{"crypto"}, .deps = &.{"bn254"}, .test_deps = &.{"testkit"} },
    // Not heavy: the parameter derivation + all 30 tests run in 5s under
    // -Dstrict-debug, well under the >15s threshold (and a Debug compile of
    // this module is ~1s against ~27s at ReleaseSafe, so marking it heavy
    // would cost more than it saves).
    .{ .name = "poseidon", .libs = &.{"crypto"}, .deps = &.{ "bn254", "bls12_381" }, .test_deps = &.{"testkit"} },
    // Not heavy, despite the inverse S-box (72 multiplies per element per
    // half-round). Measured serially on this host: strict-Debug compile ~8.5s
    // + run ~1.0s = 9.5s, under the >15s threshold — and a ReleaseSafe compile
    // of this module is ~46s (comptime SHAKE256 derivation + heavily unrolled
    // field code), so marking it heavy would cost 5x what it saves.
    .{ .name = "rescue", .libs = &.{"crypto"}, .test_deps = &.{"testkit"} },
    .{ .name = "tfhe", .libs = &.{"crypto"}, .deps = &.{"entropy"}, .test_deps = &.{"testkit"}, .heavy = true },
    .{ .name = "montint", .libs = &.{"crypto"}, .heavy = true, .test_deps = &.{"testkit"} },
    .{ .name = "chachapoly", .libs = &.{"crypto"}, .test_deps = &.{"testkit"} },
    .{ .name = "aesgcm", .libs = &.{ "crypto", "net" }, .deps = &.{"aes192"}, .test_deps = &.{"testkit"} }, // aes192: Aes192Gcm's generic backend
    .{ .name = "k256", .libs = &.{"crypto"}, .test_deps = &.{"testkit"} },
    .{ .name = "p256", .libs = &.{ "crypto", "web" }, .test_deps = &.{"testkit"} },
    .{ .name = "ripemd160", .libs = &.{"crypto"}, .test_deps = &.{"testkit"} },
    .{ .name = "b64ct", .libs = &.{"crypto"}, .test_deps = &.{"testkit"} },
    .{ .name = "sha2", .libs = &.{"crypto"}, .test_deps = &.{"testkit"} },
    .{ .name = "bech32", .libs = &.{"crypto"}, .deps = &.{"ripemd160"}, .test_deps = &.{"testkit"} },
    .{ .name = "bip32", .libs = &.{"crypto"}, .deps = &.{ "k256", "ripemd160", "bech32" }, .test_deps = &.{"testkit"} },
    .{ .name = "btcaddr", .libs = &.{"crypto"}, .deps = &.{ "bech32", "ripemd160" }, .test_deps = &.{"testkit"} },
    .{ .name = "lms", .libs = &.{"crypto"}, .test_deps = &.{"testkit"}, .heavy = true },
    // Scaffold more here (copy modules/_template) — see CONVENTIONS.md
    // "How to add a module" and the README "Roadmap / Non-goals" sections.
};

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const test_step = b.step("test", "Run every module's tests");

    // `heavy` modules (see the Module doc comment) are compute-bound: Debug
    // makes their tests ~5x slower and they are the suite's critical path, so
    // a Debug request builds them at ReleaseSafe instead — same safety checks,
    // a fraction of the wall clock. `-Dstrict-debug` opts back into real Debug
    // for the CI matrix. Any explicit non-Debug mode is honoured as-is.
    const strict_debug = b.option(
        bool,
        "strict-debug",
        "Build compute-heavy modules at Debug too (much slower; the CI matrix uses this)",
    ) orelse false;
    const heavy_optimize: std.builtin.OptimizeMode =
        if (optimize == .debug and !strict_debug) .safe else optimize;

    // Every compile step uses LLVM unless `-Dselfhosted` asks otherwise. The
    // self-hosted x86_64 backend (Zig 0.16's Debug default on x86_64 Linux)
    // compiles 2-6x faster but its code runs 2-3x slower, and its encoder
    // accepts only instructions the target CPU model has, so a Debug build of
    // a runtime-dispatched asm path fails for a baseline CPU (crc32, crc32c,
    // aesgcm, 2026-09-29). It is for the edit loop only; no gate or CI lane
    // uses it. `use_llvm = true` is a no-op in the release modes.
    const selfhosted = b.option(
        bool,
        "selfhosted",
        "Use Zig's self-hosted backend in Debug (edit loop only; no gate uses it)",
    ) orelse false;
    const use_llvm: ?bool = if (selfhosted) null else true;

    // `-Dtest-filter=<substring>` — compile only the tests whose name contains
    // one of these. Added for `scripts/fuzz-sweep.sh`: `--fuzz` puts every fuzz
    // test of a module in ONE process, so the first harness to crash takes the
    // rest of that module's harnesses down with it and they are reported as
    // though they had run. The sweep re-runs a crashed module one harness at a
    // time through this option, which is the only way to give the survivors a
    // process (and a budget) of their own. Useful by hand too:
    // `zig build test-http -Dtest-filter="fuzz: ChunkedReader"`.
    const test_filters = b.option(
        []const []const u8,
        "test-filter",
        "Only build tests whose name contains this substring (repeatable)",
    ) orelse &.{};

    // `-Dgroup=<lib>` (repeatable) — narrow the whole-collection steps
    // (`zig build`, `check-pubfn-reach`, `check-examples`, `run-examples`) to
    // the modules whose PRIMARY lib (`libs[0]`) is one of these. It exists so
    // CI can split one lane across several runners: compiling every module is
    // the bulk of a lane (`build (all modules)` 2428 s of 48 min on the
    // 2026-09-02 tag), and the groups share little compilation. Dependencies
    // outside the group are still compiled -- a module needs them -- but not
    // tested. Per-module steps (`test-<m>`) ignore it. A name matching no
    // module is refused, so a typo cannot turn a lane into one that tests
    // nothing and passes.
    const groups = b.option(
        []const []const u8,
        "group",
        "Only compile/check modules whose primary lib is this (repeatable; CI sharding)",
    ) orelse &.{};
    for (groups) |g| {
        const known = for (module_list) |m| {
            if (std.mem.eql(u8, m.libs[0], g)) break true;
        } else false;
        if (!known) std.debug.panic("-Dgroup={s}: no module has this primary lib", .{g});
    }
    // `-Dmodule=<name>` (repeatable) — narrow the same steps further, to named
    // modules. `scripts/test.sh` passes the modules of a lane that have no
    // green stamp for their current fingerprint, so a lane compiles only what
    // it has not already proven. Combined with `-Dgroup` by AND.
    const only_modules = b.option(
        []const []const u8,
        "module",
        "Only compile/check these modules (repeatable; set by test.sh from its stamps)",
    ) orelse &.{};
    for (only_modules) |name| {
        if (moduleIndex(name) == null) std.debug.panic("-Dmodule={s}: no such module", .{name});
    }
    selected_modules = only_modules;

    // Consumer build options — see `Profile` and CONVENTIONS.md § "Consumer
    // build options". Per-module knobs are `<module>-<knob>`; `null` = the
    // module derives the value from `profile`.
    const zl_options = b.addOptions();
    zl_options.addOption(Profile, "profile", b.option(
        Profile,
        "profile",
        "Consumer build profile: default (speed+security, as graded) | small (code size)",
    ) orelse .default);
    zl_options.addOption(?u32, "rsa_max_modulus_bits", b.option(
        u32,
        "rsa-max-modulus-bits",
        "rsa: largest supported modulus, 4096..8192 (default 8192; profile=small 4096)",
    ));
    zl_options.addOption(?bool, "ct25519_base_comb", b.option(
        bool,
        "ct25519-base-comb",
        "ct25519: fixed-base comb table for mulBase/X25519 keygen (default true; profile=small false, ~3x slower keygen, -43 KB table)",
    ));
    zl_options.addOption(?bool, "montint_asm_unroll", b.option(
        bool,
        "montint-asm-unroll",
        "montint: straight-line asm per limb count from 1024 bits up (default true; profile=small false = one looped asm kernel, slower modexp, much less code on ADX/BMI2 CPUs)",
    ));
    zl_options.addOption(?u32, "ssh_gex_max_bits", b.option(
        u32,
        "ssh-gex-max-bits",
        "ssh: largest DH group-exchange prime the client accepts, 4096..8192 (default 8192; profile=small 4096)",
    ));
    zl_options_mod = zl_options.createModule();

    // Gate for the "a body nothing references is never analysed" class — see
    // the `force_mod` block in pass 2 for what it compiles and why.
    const check_pubfn_reach = b.step("check-pubfn-reach", "Analyse every non-generic public declaration, including the ones no test reaches");

    // `check-examples` — build `modules/<name>/example/main.zig` as a real
    // consumer binary. See the `example` block in pass 2 for the one class it
    // covers that no test in this repository can.
    const check_examples = b.step("check-examples", "Build each module's example as an outside consumer would");

    // `run-examples` — the same set, LINKED AND RUN. Compiling an example
    // cannot see the class of defect examples exist to find: on 2026-08-23 a
    // single sweep of this step found a dangling stack slice in `btcp2p`
    // (whose own tests passed because they read the slice in the same
    // expression), a leak in `ethfrag`, a wrong-tag union read in `iec104`,
    // and twelve examples that had never run at all. It is a separate step
    // from `check-examples` only because it costs a link plus a process per
    // module; both are wired into the full lane.
    const run_examples = b.step("run-examples", "Build AND run every module's example");

    // CONVENTIONS.md 7.2: a module over either trigger must have an example.
    // This used to also reconcile a `.example` bool in `module_list` against
    // the tree -- a declaration that could drift, and did: eight example files
    // sat unbuilt for an afternoon with `check-examples` green. The bool is
    // gone; the file on disk is the declaration, so that class cannot recur
    // and only the rule itself is left to check.
    const check_example_rule = gateRun(b, "check-example-rule", &.{});
    check_examples.dependOn(check_example_rule);
    // Also reachable on its own: which modules OWE an example has nothing to
    // do with whether the existing ones compile, and it answers in
    // milliseconds where the sweep takes minutes.
    b.step("check-example-rule", "Check CONVENTIONS 7.2: every module over a trigger has an example").dependOn(check_example_rule);

    // The `own_files` list `scripts/lib/force-pubfn-reach.zig` needs, built ONCE per
    // module and looked up by name. Shared rather than rebuilt at each use so
    // the native gate and every cross-compiled pair cannot be handed different
    // lists -- two copies of a derived fact is the shape this repository keeps
    // finding to have drifted.
    var own_files_mods = std.StringHashMap(*std.Build.Module).init(b.allocator);
    for (module_list) |m| own_files_mods.put(m.name, ownFilesModule(b, m.name)) catch @panic("OOM");

    // Pass 1: create each module so inter-module deps can be wired in pass 2.
    var mods = std.StringHashMap(*std.Build.Module).init(b.allocator);
    for (module_list) |m| {
        const mod = b.addModule(m.name, .{
            .root_source_file = b.path(b.fmt("modules/{s}/src/root.zig", .{m.name})),
            .target = target,
            .optimize = if (m.heavy) heavy_optimize else optimize,
        });
        mod.addImport("zl_options", zl_options_mod);
        mods.put(m.name, mod) catch @panic("OOM");
    }

    // ReleaseFast copies of the module graph for the bench programs, created
    // on demand (see `fastModuleGraph`).
    var fast_mods = std.StringHashMap(*std.Build.Module).init(b.allocator);

    // Aggregates for the interop programs created inside the loop below.
    const interop_all = b.step("interop", "Run every module's interop program (needs the foreign peers)");
    const check_interop = b.step("check-interop", "Compile every interop, live and bench program -- rot guard, runs no peer");
    // `live-<m>` is a SECOND kind of tools program, added 2026-09-09 for `dns`:
    // one that genuinely needs the internet. It is deliberately not folded into
    // `interop-<m>`, because every interop program promises the opposite --
    // "needs no peer and no network" is what lets `scripts/test.sh interop` run
    // them everywhere. Both are compiled by `check-interop`; only `interop` is
    // run by a lane.
    const live_all = b.step("live", "Run every module's live-network program (NEEDS the internet)");
    // `sizeprobes` — every `modules/<m>/tools/sizeprobe.zig` as an installed
    // executable (zig-out/sizeprobe/). `scripts/checks/small-sizes.sh` builds
    // it at ReleaseSmall under each profile and compares (CONVENTIONS §4.2).
    const sizeprobes = b.step("sizeprobes", "Build every module's size probe (consumer build options, CONVENTIONS 4.2)");

    // Pass 2: wire deps + register a test build per module.
    for (module_list) |m| {
        const mod = mods.get(m.name).?;
        for (m.deps) |dep| mod.addImport(dep, mods.get(dep).?);
        const in_group = inGroups(m, groups) and inList(m.name, only_modules);

        // A module with test-only deps gets a SECOND module object over the
        // same source, carrying the extra imports. `mod` -- the one
        // `b.addModule` published above, and the one a consumer gets -- never
        // sees them. Modules without test_deps test `mod` directly, so the
        // common path is unchanged.
        const test_root = if (m.test_deps.len == 0) mod else blk: {
            const t = b.createModule(.{
                .root_source_file = b.path(b.fmt("modules/{s}/src/root.zig", .{m.name})),
                .target = target,
                .optimize = if (m.heavy) heavy_optimize else optimize,
            });
            t.addImport("zl_options", zl_options_mod);
            for (m.deps) |dep| t.addImport(dep, mods.get(dep).?);
            for (m.test_deps) |dep| t.addImport(dep, mods.get(dep).?);
            break :blk t;
        };

        // ⭐ `.name` defaults to "test", which made all 225 compilations
        // indistinguishable in every place zig names a step: the progress tree
        // said `compile test` whichever module was building, and so did
        // `--summary`. Naming them after the module is what makes a build or a
        // hang self-identifying — without it no amount of log plumbing can say
        // WHICH module is the slow one.
        const unit_tests = b.addTest(.{
            .name = m.name,
            .root_module = test_root,
            .use_llvm = use_llvm,
            .filters = test_filters,
        });
        const run = b.addRunArtifact(unit_tests);
        test_step.dependOn(&run.step);

        // ⭐ `zig build` COMPILES every module's tests and runs none of them.
        //
        // The default step used to be empty — nothing in this file installed an
        // artifact, so `zig build` succeeded in milliseconds having done
        // nothing, which is a confusing thing for the top-level command of a
        // library collection to do.
        //
        // Giving it the Compile steps splits the gate's one opaque number in
        // two. `zig build` is then the compile of all 225 test binaries and
        // `zig build test` is, with that cache warm, close to pure test
        // execution — and on 2026-08-14 nobody could say which of the two spent
        // the five hours that got a tag's matrix killed by GitHub's 6h job cap.
        //
        // Deliberately NOT `installArtifact`: that adds a Step.InstallArtifact
        // which COPIES each binary into zig-out/ (225 of them, for nothing) and
        // it is the copy, not the build, that the install step then names. The
        // dependency is on the Compile step itself, the same shape
        // `check-testonly` already uses below for its probe objects.
        if (in_group) b.getInstallStep().dependOn(&unit_tests.step);

        // Per-module test step: `zig build test-<name>`.
        const one = b.step(b.fmt("test-{s}", .{m.name}), b.fmt("Test the {s} module", .{m.name}));
        one.dependOn(&run.step);

        // ⭐ INTEROP PROGRAMS LIVE OUTSIDE THE MODULE, AND OUTSIDE ITS TESTS.
        //
        // A module is standalone Zig with no external dependency. An anchor
        // against a foreign implementation is a different thing: it needs a C
        // compiler, a Python, a container, a system library. Until 2026-09-06
        // those two lived in one file -- `modules/dtls/src/wolfssl_interop.zig`
        // `@embedFile`d a 555-line C peer and shelled out to `cc -lwolfssl`
        // from inside `test-dtls`, and five more modules did the same with
        // `python3` -- so every consumer of the library carried foreign source,
        // and `test-<m>` could not run without a toolchain it had no business
        // needing. It "skipped loudly" instead, and CI's peer install is
        // `continue-on-error`, so a failed install degraded to a silent skip:
        // the mess was paid for and the anchor still might not run.
        //
        // The split: `modules/<m>/tools/interop.zig` is a standalone PROGRAM.
        // It may spawn anything. It is never compiled into the module and
        // never into `test-<m>`. What it produces -- a transcript of the
        // exchange, committed under `src/testdata/` -- is what the module's own
        // hermetic tests replay, so the anchor's VALUE runs in the lane that
        // runs everywhere while the anchor's TAKING stays here.
        //
        // Discovered by existence, not declared in a table: a module either has
        // the file or does not, and a table would be a second place to forget.
        if (moduleHasInterop(b, m.name)) {
            const interop_mod = b.createModule(.{
                .root_source_file = b.path(b.fmt("modules/{s}/tools/interop.zig", .{m.name})),
                .target = target,
                .optimize = if (m.heavy) heavy_optimize else optimize,
            });
            interop_mod.addImport(m.name, mod);
            for (m.deps) |dep| interop_mod.addImport(dep, mods.get(dep).?);
            for (m.test_deps) |dep| interop_mod.addImport(dep, mods.get(dep).?);

            const interop_exe = b.addExecutable(.{
                .name = b.fmt("interop-{s}", .{m.name}),
                .root_module = interop_mod,
                .use_llvm = use_llvm,
            });
            const interop_run = b.addRunArtifact(interop_exe);
            interop_run.addPassthruArgs();
            const interop_one = b.step(
                b.fmt("interop-{s}", .{m.name}),
                b.fmt("Run the {s} interop program against a real foreign peer (needs that peer)", .{m.name}),
            );
            interop_one.dependOn(&interop_run.step);
            interop_all.dependOn(&interop_run.step);

            // Rot guard, the same shape `check-ctgrind` uses for its harnesses:
            // COMPILE every interop program on a lane that has no peers at all.
            // An instrument nothing builds is an instrument that stops building
            // without anyone hearing, and this repository has lost an anchor
            // that way before.
            check_interop.dependOn(&interop_exe.step);
        }

        // The live-network program, discovered by existence exactly like the
        // interop one. Its checks USED to be `test "live: …"` inside the
        // module; see `modules/dns/tools/live.zig`'s header for why a network
        // test that skips is worse than no test at all, and why the skip's
        // stderr narration was turning a slow resolver into a 217-module FAIL.
        if (moduleHasLive(b, m.name)) {
            const live_mod = b.createModule(.{
                .root_source_file = b.path(b.fmt("modules/{s}/tools/live.zig", .{m.name})),
                .target = target,
                .optimize = if (m.heavy) heavy_optimize else optimize,
            });
            live_mod.addImport(m.name, mod);
            for (m.deps) |dep| live_mod.addImport(dep, mods.get(dep).?);
            for (m.test_deps) |dep| live_mod.addImport(dep, mods.get(dep).?);

            const live_exe = b.addExecutable(.{
                .name = b.fmt("live-{s}", .{m.name}),
                .root_module = live_mod,
                .use_llvm = use_llvm,
            });
            const live_run = b.addRunArtifact(live_exe);
            live_run.addPassthruArgs();
            const live_one = b.step(
                b.fmt("live-{s}", .{m.name}),
                b.fmt("Run the {s} live-network checks against real servers (NEEDS the internet)", .{m.name}),
            );
            live_one.dependOn(&live_run.step);
            live_all.dependOn(&live_run.step);

            // Same rot guard, and it is the whole reason this is wired at all:
            // an instrument nothing builds is one that stops building without
            // anyone hearing.
            check_interop.dependOn(&live_exe.step);
        }

        // The comparative benchmark (grading v2, 2026-10-07): the program behind
        // a maturity card's `**Performance:**` ratios and `**Ahead:** speed`
        // claims, kept under CONVENTIONS.md §9 kind 3. Discovered by existence
        // like the two above. Always ReleaseFast -- a ratio measured in Debug
        // says nothing about either side -- and never run by any lane: it
        // spawns the foreign implementation and takes minutes of quiet CPU.
        if (moduleHasBench(b, m.name)) {
            const bench_mod = b.createModule(.{
                .root_source_file = b.path(b.fmt("modules/{s}/tools/bench.zig", .{m.name})),
                .target = target,
                .optimize = .fast,
            });
            // The module under test and its whole dependency closure are built
            // ReleaseFast too: the graph in `mods` follows -Doptimize, and a
            // ReleaseFast driver over a Debug module measures Debug.
            bench_mod.addImport(m.name, fastModuleGraph(b, target, &fast_mods, m.name));
            for (m.deps) |dep| bench_mod.addImport(dep, fastModuleGraph(b, target, &fast_mods, dep));
            for (m.bench_deps) |dep| bench_mod.addImport(dep, fastModuleGraph(b, target, &fast_mods, dep));
            // `fastmem` for every bench driver (2026-10-11): a bench that
            // exercises std code which memsets large blocks installs
            // `fastmem.exportSymbols()`, as this collection's libc-free
            // executables do (qap's), so the ratio measures the module and
            // not Zig 0.16's byte-wise compiler_rt memset. A bench that does
            // so says it on its card; the module itself never imports it.
            if (!std.mem.eql(u8, m.name, "fastmem")) bench_mod.addImport("fastmem", fastModuleGraph(b, target, &fast_mods, "fastmem"));
            // `testkit` for every bench driver (2026-10-17): `testkit.bench` is
            // the timing/ratio skeleton 38 benches had copied by hand.
            if (!std.mem.eql(u8, m.name, "testkit")) bench_mod.addImport("testkit", fastModuleGraph(b, target, &fast_mods, "testkit"));

            const bench_exe = b.addExecutable(.{
                .name = b.fmt("bench-{s}", .{m.name}),
                .root_module = bench_mod,
                .use_llvm = true,
            });
            const bench_run = b.addRunArtifact(bench_exe);
            bench_run.has_side_effects = true;
            bench_run.addPassthruArgs();
            b.step(
                b.fmt("bench-{s}", .{m.name}),
                b.fmt("Benchmark {s} against the foreign implementations its maturity card compares with (needs them)", .{m.name}),
            ).dependOn(&bench_run.step);
            check_interop.dependOn(&bench_exe.step);
        }

        // The size probe (CONVENTIONS §4.2, 2026-10-17): a minimal consumer of a
        // module that has consumer build options, over the PUBLISHED module, so
        // `-Dprofile` / `-D<module>-<knob>` reach it exactly as they reach an
        // application. Discovered by existence; `check-build-options` requires
        // one for every module that reads `zl_options`. Compiled by
        // `check-interop` too, so it cannot rot between `small` lane runs.
        if (moduleHasSizeprobe(b, m.name)) {
            const sp_mod = b.createModule(.{
                .root_source_file = b.path(b.fmt("modules/{s}/tools/sizeprobe.zig", .{m.name})),
                .target = target,
                .optimize = optimize,
            });
            sp_mod.addImport(m.name, mod);
            const sp_exe = b.addExecutable(.{
                .name = b.fmt("sizeprobe-{s}", .{m.name}),
                .root_module = sp_mod,
                .use_llvm = true,
            });
            sizeprobes.dependOn(&b.addInstallArtifact(sp_exe, .{
                .dest_dir = .{ .override = .{ .custom = "sizeprobe" } },
            }).step);
            check_interop.dependOn(&sp_exe.step);
        }

        // `check-pubfn-reach`: compile a second root over the SAME module graph
        // whose only job is to take a reference to every public declaration.
        //
        // ⭐ This is not redundant with `unit_tests` above, and that is the
        // entire point. Zig analyses a function body only when something
        // references it, so `unit_tests` — an `addTest` over the module root —
        // walks straight past any `pub fn` no test calls. Proven by mutation on
        // 2026-08-21: a deliberate type error injected into `nftables`
        // `RuleBuilder.reject()` compiled AND linked a 20 MB test binary that
        // exited 0 green, while this step went red on it.
        //
        // Measured the same day: 403 of 9626 public functions are unreachable
        // from any test, spread over 106 modules, 90 of them declared in a
        // module's own `root.zig` — i.e. on the published surface. All 403
        // compile today, so this is a standing guard over a risk surface, not a
        // burn-down of known breakage.
        //
        // Compile-only, like `check-testonly`'s probes: the forcing test has no
        // behaviour to run, and a reference that reaches code generation has
        // already proven what the step exists to prove.
        const force_mod = b.createModule(.{
            .root_source_file = b.path("scripts/lib/force-pubfn-reach.zig"),
            .target = target,
            .optimize = if (m.heavy) heavy_optimize else optimize,
        });
        force_mod.addImport("m", test_root);
        force_mod.addImport("own_files", own_files_mods.get(m.name).?);
        const force_tests = b.addTest(.{
            .name = b.fmt("force-{s}", .{m.name}),
            .root_module = force_mod,
            .use_llvm = use_llvm,
        });
        if (in_group) check_pubfn_reach.dependOn(&force_tests.step);

        // ⭐ The one class nothing else here can cover: **is the published API
        // sufficient to do the job?**
        //
        // Every test in this collection lives in the same file as the code it
        // tests, so it reads private declarations freely and its build carries
        // `test_deps` the published module never gets. It can therefore pass
        // while a function is unreachable from outside, a type needed to call
        // it is not exported, or an error is not nameable. That is not a
        // hypothetical either — it is exactly how `diskfree` shipped two
        // functions that did not compile: nothing had ever imported it.
        //
        // So the example is wired to `mod` — the module `b.addModule`
        // published, with `deps` only and NO `test_deps`, exactly what
        // `@import("<name>")` hands a downstream project.
        //
        // Demonstrated on `l2disco`, 2026-08-21, by dropping the `pub` from a
        // type its public API needs: `zig build test-l2disco` stayed green
        // (the tests are inside, they never cross the boundary) and so did
        // `check-pubfn-reach` (the declaration still exists, it is just no
        // longer public, so the walk silently covers less) — only this step
        // went red. The three gates are complements, not overlaps.
        //
        // ⭐ NO LONGER compile-only, and the difference matters. Each example
        // now also carries a `run-example-<name>` step (below), and a run step
        // forces the artifact to be emitted and LINKED -- so this compile no
        // longer passes `-fno-emit-bin`, and consumer-BINARY facts that used to
        // sit outside it (link-time reach: a MIPS `PC16` fixup overflows at
        // ±128 KB) are inside it now. What is still outside is what a module
        // DRAGS IN by size (`http`'s TLS-vs-plaintext split was 334 KB), which
        // needs a measured binary; `scripts/checks/check-http-sizeprobe.sh` is the one
        // place this repository does that.
        //
        // The comment this replaces said the opposite, and had said it since
        // the run steps landed: a gate whose documented scope is narrower than
        // its real one is the same defect as the reverse, just the lucky way
        // round -- someone reads it and builds a second gate for a class this
        // one already covers.
        //
        // Scoped, not universal (survey 2026-08-21): 78 of 229 modules already
        // have an in-repo consumer, so their boundary is exercised by real
        // code; 93 more have a public surface under 25 functions, a third of
        // them anchored to published test vectors, where an internal vector
        // test is strictly stronger than an example. The 57 that are left have
        // no consumer AND a wide surface — those get examples, largest first.
        if (moduleHasExample(b, m.name)) {
            const example_mod = b.createModule(.{
                .root_source_file = b.path(b.fmt("modules/{s}/example/main.zig", .{m.name})),
                .target = target,
                .optimize = optimize,
            });
            example_mod.addImport(m.name, mod);
            // Its declared `deps` too — they are published modules, so a real
            // consumer can depend on them exactly as this example does. What
            // an example must NOT get is `test_deps` or any private
            // declaration, and it gets neither. `conntrack` and `wireguard`
            // are the honest case: their own docs describe `netlink` as the
            // shared transport a caller reaches for, so forcing them to
            // re-export its attribute codec would invent API to satisfy a
            // rule rather than a consumer.
            //
            // ⚠ What that argument costs, measured 2026-08-23 rather than left
            // implied: it was made about two modules and it applies to 151 —
            // every module with any `.deps` — of which 65 examples really do
            // import one. For those 65 this step no longer answers "is THIS
            // module's published API sufficient?" but "is this module PLUS its
            // published deps sufficient?", which is a weaker question. It is
            // still the right trade (the alternative invents API), but the
            // claim above should not be read as covering the other 63.
            //
            // ⚠ And the boundary is enforced at USE, not at declaration: a
            // top-level `const x = @import("testkit");` an example never uses
            // is not resolved, so it compiles. Only a used import goes red.
            for (m.deps) |dep| example_mod.addImport(dep, mods.get(dep).?);
            const example = b.addExecutable(.{
                .name = b.fmt("example-{s}", .{m.name}),
                .root_module = example_mod,
                .use_llvm = use_llvm,
            });
            if (in_group) check_examples.dependOn(&example.step);
            // Per-module entry point, so one example can be compiled on its
            // own: `zig build example-<name>`. Without it the only way to
            // check a single new example is the whole `check-examples` sweep,
            // which fails on every OTHER module still missing one.
            const one_example = b.step(b.fmt("example-{s}", .{m.name}), b.fmt("Build the {s} example", .{m.name}));
            one_example.dependOn(&example.step);
            // `zig build run-example-<name>` — and this one links and RUNS it.
            // Worth its own step because compiling an example is not what
            // examples are for: every leak this repository has found through
            // one was found by running it under a leak-checking allocator
            // (14 in `finstats` alone, 2026-08-23), and a compile cannot see
            // any of them. Deliberately NOT wired into `check-examples`: some
            // examples want a socket, a daemon or root, and the moment the
            // sweep runs them it either fails on a laptop with no network or
            // grows a hand-kept list of which ones are safe -- a declaration
            // that would drift the way `.example` did.
            const run_example = b.addRunArtifact(example);
            b.step(b.fmt("run-example-{s}", .{m.name}), b.fmt("Build AND run the {s} example", .{m.name})).dependOn(&run_example.step);
            if (in_group) run_examples.dependOn(&run_example.step);
        }
    }

    // `zig build check-portable` — compile every module's TESTS for each
    // real target it declares in `meta.targets` (CONVENTIONS.md §4), checked
    // against a known-failures baseline keyed by (module, target).
    //
    // SCHEMA (2026-08-18). This gate used to sweep every `platform = .any`
    // module for wasm32 alone -- one field conflating two different claims,
    // where a module's AUTHOR intends it to run versus where anyone has
    // PROVEN it runs, that a consumer reads as the latter. `meta.targets`
    // replaces the guess with a set of concrete per-target claims
    // (`PortableTarget` below); a module that never intended wasm32 (`http`,
    // `aaa-gate`, `ratelimit`, `bbs` -- real std.Thread/libc/std.os.linux use,
    // not portability defects) simply does not declare it and stops being
    // swept for it -- the false-alarm shape this schema exists to remove.
    // `meta.platform` is UNCHANGED and stays on every module: it is still the
    // informal one-line claim behind ~40 prose references across
    // SPEC.md/README.md/root.zig doc comments (grepped 2026-08-18; all prose,
    // no other machine reader -- the only one was `declaresAnyPlatform`,
    // replaced below by `parseMetaTargets`), but it is no longer
    // gate-enforced. `meta.targets` is the enforceable claim from here on.
    //
    // WHY A BUILD STEP AND NOT A COMPTIME CHECK. The obvious idea is a
    // `comptime` assertion inside the module, and it cannot work: comptime is
    // evaluated FOR the target being built, so on an x86_64 build `usize` is 64
    // bits at comptime too and there is nothing for an assertion to notice. The
    // bug this catches -- `qr`'s BitWriter shifting a `usize` by a `u6`, legal
    // on a 64-bit target and a compile error on a 32-bit one -- is invisible
    // until something actually compiles for 32 bits. Nothing did: every lane in
    // the CI matrix is 64-bit, arm64 included, so a module can claim a target
    // for months while being unbuildable on half of what that claim covers.
    //
    // ⭐ `addTest`, NOT `addObject`. This gate originally used `zig build-obj`,
    // and that was a structural blind spot: Zig analyses a container's function
    // BODIES lazily, only once something calls them, and `build-obj` never
    // calls anything -- it type-checks signatures and stops. Measured
    // 2026-08-18: `modules/http/src/Server.zig`'s `formatHttpDate` indexes
    // `day_names[day.day % 7]` where `day.day` is a `u47` -- a real compile
    // error on any 32-bit target, since a `u47` cannot implicitly narrow to a
    // 32-bit `usize` -- and `check-portable` reported 196/196 green anyway,
    // because nothing in an object build ever CALLS `formatHttpDate`. A `zig
    // build-obj` of the whole module can be 100% green while every public
    // function in it is unbuildable. `addTest` compiles the module's own test
    // binary -- the real entry point that calls the module's real functions --
    // which is what forces the bodies to be analysed. It is deliberately NOT
    // run (`--test-no-exec` shape: depend on the `Compile` step, never wrap it
    // in `addRunArtifact`) -- none of the cross-compiled targets below have a
    // host to run on anyway, and the gate only ever needed the compile+link to
    // happen, not the result.
    //
    // wasm32-**wasi**, not wasm32-freestanding. `usize`/pointer width -- the
    // property this axis exists to probe -- comes from the CPU arch
    // (`wasm32`), not the OS tag, so this does not weaken the check. Freestanding
    // has no OS at all, and the default Zig test runner needs one (it reaches
    // `std.Io.Threaded` for its RNG seed, `posix.STDIN_FILENO`, argv, ...);
    // `addObject` never instantiated that runner, so freestanding was never
    // exercised against it before. Measured: an `addTest` at wasm32-freestanding
    // fails to compile the STD TEST RUNNER itself (`posix.system` has no
    // `getrandom`/`IOV_MAX`/`STDIN_FILENO` for freestanding) on a trivial module
    // with no bug at all -- that is a gap in `std`'s freestanding surface, not a
    // finding about any module here, and it would drown every real result.
    // wasi gives the runner the OS surface it needs while keeping 32-bit
    // pointers, which is the only property that axis measures.
    //
    // The declared set is read from each module's own source rather than
    // repeated here. `pub const meta` is the canonical declaration
    // (CONVENTIONS.md), and a second list in this file would drift from it
    // silently -- the failure mode being a module that quietly stops being
    // checked.
    const portable_measure_all = b.option(
        bool,
        "portable-measure-all",
        "check-portable: create a portable-<name>-<target> compile step for every module x cross-compiled target, regardless of meta.targets -- probe a target's true status before declaring it",
    ) orelse false;
    const portable = b.step(
        "check-portable",
        "Compile every module's tests for each target in its meta.targets, checked against scripts/checks/portable-known-failures.tsv",
    );

    // Pass 1: parse every module's declared set once, in module_list order,
    // at graph-build time -- step CREATION below (pass 3) needs it to decide
    // which `portable-<name>-<target>` steps to make. A module whose
    // declaration cannot be read (no `meta` block, no `.targets` field, an
    // unknown/duplicate token, or a set missing the mandatory `.linux64`)
    // contributes no entry to `module_targets`; the gate tool's
    // `check-portable` re-reads the same declarations with the same parser
    // and fails on it -- this is what makes "a module missing its
    // declaration" a gate failure (bolt3, before this commit, had a `meta`
    // block with no platform claim at all and nothing noticed).
    var module_targets = std.StringHashMap([]const PortableTarget).init(b.allocator);
    for (module_list) |m| {
        const parsed = parseMetaTargets(b, b.graph.io, m.name);
        if (parsed.err != null) continue;
        module_targets.put(m.name, parsed.targets) catch @panic("OOM");
    }

    // Pass 2: one Module graph per cross-compiled target -- same shape as
    // pass 1 in `build()` above (the native `mods` map), just once per
    // `PortableTarget.query()`.
    var cross_mods: [cross_compile_targets.len]std.StringHashMap(*std.Build.Module) = undefined;
    var cross_resolved: [cross_compile_targets.len]std.Build.ResolvedTarget = undefined;
    for (cross_compile_targets, 0..) |ct, ti| {
        const rt = b.resolveTargetQuery(ct.query().?);
        cross_resolved[ti] = rt;
        var map = std.StringHashMap(*std.Build.Module).init(b.allocator);
        for (module_list) |m| {
            map.put(m.name, b.createModule(.{
                .root_source_file = b.path(b.fmt("modules/{s}/src/root.zig", .{m.name})),
                .target = rt,
                .optimize = .small,
            })) catch @panic("OOM");
        }
        cross_mods[ti] = map;
    }
    for (cross_compile_targets, 0..) |_, ti| {
        for (module_list) |m| {
            const mod = cross_mods[ti].get(m.name).?;
            mod.addImport("zl_options", zl_options_mod);
            for (m.deps) |dep| mod.addImport(dep, cross_mods[ti].get(dep).?);
        }
    }

    // Pass 3: `portable-<name>-<target>` per (module, target) pair the
    // module DECLARES (or, with `-Dportable-measure-all`, every pair --
    // that flag is how this schema's own seed data was measured: create
    // every step, sweep it by hand, THEN write `meta.targets` from the
    // result instead of from optimism). Same shape as the old single-target
    // gate's per-module step: deliberately UNGATED by the baseline below --
    // this is the module's true, unmasked status, for
    // `zig build portable-<name>-<target>` by hand.
    for (cross_compile_targets, 0..) |ct, ti| {
        for (module_list) |m| {
            const declared = module_targets.get(m.name) orelse &.{};
            var is_declared = false;
            for (declared) |t| {
                if (t == ct) {
                    is_declared = true;
                    break;
                }
            }
            if (!is_declared and !portable_measure_all) continue;

            const step_name = b.fmt("portable-{s}-{s}", .{ m.name, ct.label() });
            // Same shape as the per-module `test-<name>` step in pass 2
            // above: a module with `test_deps` gets a second module object
            // carrying the extra imports, so the compile forces analysis of
            // exactly the same test bodies `zig build test-<name>` does.
            const test_root = if (m.test_deps.len == 0) cross_mods[ti].get(m.name).? else blk: {
                const t = b.createModule(.{
                    .root_source_file = b.path(b.fmt("modules/{s}/src/root.zig", .{m.name})),
                    .target = cross_resolved[ti],
                    .optimize = .small,
                });
                t.addImport("zl_options", zl_options_mod);
                for (m.deps) |dep| t.addImport(dep, cross_mods[ti].get(dep).?);
                for (m.test_deps) |dep| t.addImport(dep, cross_mods[ti].get(dep).?);
                break :blk t;
            };
            const cross_test = b.addTest(.{ .name = step_name, .root_module = test_root, .use_llvm = use_llvm });
            const one = b.step(
                step_name,
                b.fmt("Compile {s}'s tests and public surface for {s} (true status, not baseline-checked)", .{ m.name, ct.label() }),
            );
            one.dependOn(&cross_test.step);

            // ⭐ The cross compile above is an `addTest` over the module root,
            // and therefore carries the SAME blind spot `check-pubfn-reach`
            // exists to close on the native target: Zig analyses a function
            // body only when something references it, so a `pub fn` no test
            // reaches is never checked against this target at all. Measured
            // 2026-08-21 on native: 403 of 9626 public functions are in that
            // position. Without this, "module X compiles for Windows" means
            // "the part of X some test happens to call compiles for Windows",
            // which is exactly the kind of claim this repository keeps finding
            // to be weaker than it reads.
            //
            // So each declared (module, target) pair also compiles the forcing
            // root. Deliberately part of `portable-<name>-<target>` rather than
            // a new gate: the pair is the unit `scripts/checks/portable-known-failures.tsv`
            // is keyed by, so a pair that already fails stays one row, and a
            // pair that starts failing BECAUSE of this fails as itself rather
            // than under a second baseline that would have to be kept in sync.
            const cross_force_mod = b.createModule(.{
                .root_source_file = b.path("scripts/lib/force-pubfn-reach.zig"),
                .target = cross_resolved[ti],
                .optimize = .small,
            });
            cross_force_mod.addImport("m", test_root);
            cross_force_mod.addImport("own_files", own_files_mods.get(m.name).?);
            const cross_force = b.addTest(.{
                .name = b.fmt("force-{s}", .{step_name}),
                .root_module = cross_force_mod,
                .use_llvm = use_llvm,
            });
            one.dependOn(&cross_force.step);
        }
    }
    // The gate itself does NOT `dependOn` the per-pair compile steps above --
    // doing so would make `check-portable` red for every (module, target)
    // already on the known-failures baseline, which is the opposite of what
    // a baseline is for (CONVENTIONS.md has no baseline precedent for a
    // whole-module failure, but `check-global-alloc`'s `global-alloc-ok:`
    // markers set the standard this follows: an entry means "seen and
    // accounted for", not "ignored", and a STALE entry -- one that now
    // passes -- is itself a failure). Instead `PortableBaselineStep`
    // re-invokes `zig build portable-<name>-<target>...` as a subprocess (the
    // same shape `DarkTestsStep` uses to shell out to `dark-tests.sh`), reads
    // the per-pair PASS/FAIL from `--summary all`, and diffs that against
    // `scripts/checks/portable-known-failures.tsv` itself.
    //
    // Zig 0.17: the gate is the `check-portable` command of the gate tool,
    // which recomputes the same pairs from `meta.targets` (one shared parser,
    // `parseMetaTargetsSrc`) and the `-Dmodule` list, and runs the sub-build
    // with the zig and the local cache of THIS build (both resolved at make
    // time, so a restored configuration cache cannot hand it a stale path).
    {
        const run = gateRunStep(b, "check-portable", &.{});
        run.addPrefixedFileArg("--zig=", b.graph.path(.zig_exe, ""));
        run.addPrefixedDirectoryArg("--cache-dir=", b.graph.path(.local_cache, ""));
        portable.dependOn(&run.step);
    }

    // `zig build check-portable-table` / `zig build gen-portable-table` — the
    // consumer-facing half of the schema above. `check-portable` proves a
    // claim; nothing until now let a consumer SEE it without reading 228
    // `root.zig` files and a TSV. This renders the README's "Portability"
    // table from exactly the two sources `check-portable` itself reads --
    // the declared `meta.targets` sets (the gate tool's `portableInputs`, same
    // parser as `module_targets` above) and `scripts/checks/portable-known-failures.tsv` -- so the table can
    // never assert a status the gate did not itself check, and a stale table
    // (edited by hand, or left behind after a module's `.targets` changed)
    // fails the build exactly as a stale baseline row does. Two named steps
    // sharing one `make`: `check-portable-table` (the gate; `.write = false`)
    // and `gen-portable-table` (the fix; `.write = true`), so "verify" and
    // "regenerate" can never drift into two different rendering paths.
    b.step(
        "check-portable-table",
        "Verify README.md's generated Portability table matches meta.targets + the known-failures baseline",
    ).dependOn(gateRun(b, "check-portable-table", &.{}));

    b.step(
        "gen-portable-table",
        "Regenerate README.md's Portability table from meta.targets + the known-failures baseline",
    ).dependOn(gateRun(b, "gen-portable-table", &.{}));

    // `zig build check-libs-table` / `zig build gen-libs-table` — the
    // consumer-facing half of `Module.libs`. `check-catalog` proves each
    // module's PRIMARY library matches the section its row is printed under;
    // this renders the six-library overview from the same field, so the
    // cross-tags (the whole point of the plural) are visible without reading
    // module_list, and a table left behind after a `.libs` edit fails the
    // build exactly as a stale portability table does.
    inline for (.{ .{ false, "check-libs-table", "Verify README.md's generated Libraries table matches module_list's `.libs`" }, .{ true, "gen-libs-table", "Regenerate README.md's Libraries table from module_list's `.libs`" } }) |cfg| {
        b.step(cfg[1], cfg[2]).dependOn(gateRun(b, cfg[1], &.{}));
    }

    // `zig build gen-catalog` — the fix half of the grouping check
    // inside `check-catalog`. Edit a module's `.libs`, run this, commit: the
    // catalog row moves to the section the field names. Row TEXT is never
    // generated (see CatalogSectionsStep's doc comment for the measurement
    // that settled that), so this is a formatter for arrangement, not a
    // renderer for content.
    inline for (.{
        .{ false, "check-catalog-table", "Verify README.md's module catalog (and each maturity card's Grade line) matches module_list + meta.doc/meta.platform_note + the maturity cards" },
        .{ true, "gen-catalog", "Regenerate README.md's module catalog and each maturity card's Grade line from module_list + meta.doc/meta.platform_note + the maturity cards" },
    }) |cfg| {
        b.step(cfg[1], cfg[2]).dependOn(gateRun(b, cfg[1], &.{}));
    }

    // `zig build maturity-report` — the maintainer's view of the maturity
    // cards: one TSV line per module, worst grade first, with the axis that
    // caps it. The README shows a consumer the grade; this shows us what to
    // work on (survey the scope, add an external anchor, run the audit).
    {
        const st = gateRun(b, "maturity-report", &.{});
        b.step("maturity-report", "Print every module's maturity grade as TSV, worst first (grade, module, profile, limited by, scope, audit, current src hash, whether the audited src is fresh, whether P was measured on the current toolchain, consumer)").dependOn(st);
    }

    // `zig build app-list` — the names in `example_apps`, one per line, so
    // `scripts/check-apps.sh` reads the registry instead of globbing (a glob
    // would silently include a directory nobody declared).
    {
        const st = gateRun(b, "app-list", &.{});
        b.step("app-list", "Print the example-apps/ projects declared in build.zig, one per line").dependOn(st);
    }

    // `zig build check-package` — see `checkPackagePaths`.
    {
        const st = gateRun(b, "check-package", &.{});
        b.step("check-package", "Verify build.zig.zon's .paths ships LICENSE and NOTICE").dependOn(st);
    }

    // `zig build check-scripts-doc` — see `checkScriptsDoc`.
    {
        const st = gateRun(b, "check-scripts-doc", &.{});
        b.step("check-scripts-doc", "Verify scripts/README.md names every file in scripts/").dependOn(st);
    }

    // `zig build check-testonly` — prove a test-only dep really is test-only.
    //
    // The claim `test_deps` makes is that the PUBLISHED module never needs
    // them. Nothing checked it, and no ordinary build could: Zig analyses
    // container-level decls lazily, so an `@import("testkit")` sitting unused
    // in a module's non-test code is simply never looked at. Verified by
    // planting `pub const leaked_probe = testkit.verbose_skip_env;` in
    // `netlink` -- every dependent still built green.
    //
    // So force the analysis: for each such module, compile a consumer-shaped
    // probe that imports ONLY the published module (deps, no test_deps) and
    // calls `refAllDeclsRecursive` on it. A leak into public non-test code is
    // then a compile error naming the missing module.
    const testonly = b.step("check-testonly", "Prove each test_deps module isn't needed by the published module");
    for (module_list) |m| {
        if (m.test_deps.len == 0) continue;
        if (!inList(m.name, only_modules)) continue;
        const wf = b.addWriteFiles();
        const src = wf.add(b.fmt("probe_{s}.zig", .{m.name}), b.fmt(
            \\// Generated by build.zig's check-testonly step. See it for why.
            \\//
            \\// The reference walk is hand-rolled because `std.testing.refAllDecls`
            \\// opens with `if (!builtin.is_test) return;` -- in a non-test build,
            \\// which is exactly this probe, it does nothing at all. Using it here
            \\// would have produced a check that always passes.
            \\const published = @import("{s}");
            \\
            \\fn refAll(comptime T: type, comptime depth: u8) void {{
            \\    @setEvalBranchQuota(200_000);
            \\    switch (@typeInfo(T)) {{
            \\        .@"struct", .@"enum", .@"union", .@"opaque" => {{}},
            \\        else => return,
            \\    }}
            \\    inline for (comptime std.meta.declarations(T)) |d| {{
            \\        const f = @field(T, d);
            \\        _ = &f;
            \\        if (depth > 0 and @TypeOf(f) == type and !isStd(f)) refAll(f, depth - 1);
            \\    }}
            \\}}
            \\
            \\// A `std` type a module re-exports (`pub const Secp256k1 =
            \\// std.crypto.ecc.Secp256k1;` in threshold_ecdsa) is not the module's
            \\// code: walking into it only analyses std, and std's
            \\// `secp256k1.scalar.Scalar.sqrt` is a deliberate `@compileError`
            \\// (2026-10-09, red CI once threshold_ecdsa entered the closure).
            \\// `@typeName` of a std type is its FILE path under std
            \\// (`crypto.pcurves.secp256k1.Secp256k1`), so: the first segment names
            \\// a std namespace and NOT one of the published module's own
            \\// declarations (mls exports its own `crypto`).
            \\fn isStd(comptime T: type) bool {{
            \\    comptime {{
            \\        const name = @typeName(T);
            \\        const first = name[0 .. std.mem.findScalar(u8, name, '.') orelse return false];
            \\        return @hasDecl(std, first) and !@hasDecl(published, first);
            \\    }}
            \\}}
            \\
            \\const std = @import("std");
            \\comptime {{
            \\    refAll(published, 3);
            \\}}
            \\
        , .{m.name}));
        const probe = b.createModule(.{
            .root_source_file = src,
            .target = target,
            .optimize = .debug,
        });
        // Exactly what a consumer gets: the published module and nothing else.
        probe.addImport(m.name, mods.get(m.name).?);
        const obj = b.addObject(.{ .name = b.fmt("testonly-{s}", .{m.name}), .root_module = probe, .use_llvm = use_llvm });
        testonly.dependOn(&obj.step);
    }
    test_step.dependOn(testonly);

    // Machine-readable module graph: `zig build module-graph`.
    // One TSV line per module — `name<TAB>heavy<TAB>dep,dep,...` (deps empty
    // when there are none). `scripts/test.sh` reads this to work out which
    // modules a change affects, so build.zig stays the single source of truth
    // for the graph and nothing has to parse Zig source.
    const graph = b.step("module-graph", "Print the module dependency graph as TSV (name, heavy, deps)");
    const graph_inner = gateRun(b, "module-graph", &.{});
    graph.dependOn(graph_inner);

    // `zig build module-fingerprints` — one line per module,
    // `name<TAB>fingerprint`. The key `scripts/test.sh` keeps its stamps under:
    // a module whose fingerprint has a green stamp for a lane need not run in
    // that lane again. See `printModuleFingerprints` for what goes in.
    const fps = b.step("module-fingerprints", "Print each module's content fingerprint as TSV (name, fingerprint)");
    const fps_inner = gateRun(b, "module-fingerprints", &.{});
    fps.dependOn(fps_inner);

    // Catalog consistency gate: `zig build check-catalog` (CI runs it).
    // Verifies module_list ↔ modules/ ↔ the README catalog table agree, so a
    // module can't ship without a catalog row (6 rows had drifted before this
    // existed) and the README's module count can't go stale. Also verifies
    // the README catalog row's Deps column and each module's root.zig
    // `meta.deps` field against module_list's `.deps` -- the field that
    // actually wires `mod.addImport` in pass 2 above, i.e. what really gates
    // compilation. 26 README rows and 7 meta.deps blocks (plus 4 more
    // meta.deps blocks mixing std-usage notes into the tuple, since fixed
    // to keep the tuple sibling-names-only) were found to have drifted
    // before this existed -- e.g. `hpke` really depends on `p256` via
    // DHKEM(P-256), but its README row said "—" and its own
    // modules/hpke/README.md said "Deps: none".
    // The fix half of `check-catalog`'s `meta.deps` agreement check: edit
    // `module_list`'s `.deps`, run this, commit. See `genMetaDeps`.
    {
        const gmd = gateRun(b, "gen-meta-deps", &.{});
        b.step("gen-meta-deps", "Regenerate every module's `meta.deps` from module_list's `.deps`").dependOn(gmd);
    }

    const check = b.step("check-catalog", "Verify module_list matches modules/ and the README catalog");
    const check_inner = gateRun(b, "check-catalog", &.{});
    check.dependOn(check_inner);

    // Changelog gate: `zig build check-changelog`. Every module carries a
    // `modules/<m>/CHANGELOG.md`, it is really a changelog, and its entries are
    // dated. (It also policed a per-module index in the root CHANGELOG.md,
    // which had drifted by 16 of 55 entries before this existed; that index was
    // removed on 2026-08-14 -- see `checkChangelog`.) A SEPARATE step
    // rather than a section of `check-catalog` for one reason: `check-catalog`
    // is driven by `module_list` and reads README/NOTICE, and the change signal
    // that should run THIS one is editing a CHANGELOG -- which `scripts/test.sh`
    // classified as a root doc "with no module impact" and used to run nothing
    // at all for. Its own step is what let that trigger be wired (see
    // `trigger_changelog` there) without widening `check-catalog`'s.
    const check_changelog = b.step("check-changelog", "Verify every module has a dated, well-formed CHANGELOG.md");
    const check_changelog_inner = gateRun(b, "check-changelog", &.{});
    check_changelog.dependOn(check_changelog_inner);

    // Pure-MIT gate: `zig build check-copyleft`. The teeth on root NOTICE §1's
    // rule (owner's decision, 2026-09-06): copyleft in shipped code or data is
    // a DEFECT to be removed, not an entry to be added. It landed with the same
    // policy change that retired root §1's per-module list -- with no list left
    // saying which modules carry third-party material, the question "is the
    // whole library still plain MIT?" needed an answer that is derived from the
    // files rather than maintained by hand. See `checkCopyleft`.
    const check_copyleft = b.step("check-copyleft", "Verify no shipped file declares itself under a copyleft licence");
    const check_copyleft_inner = gateRun(b, "check-copyleft", &.{});
    check_copyleft.dependOn(check_copyleft_inner);

    // Module-purity gate: `zig build check-module-purity`. The teeth on the
    // owner's rule of 2026-09-06 -- a module is standalone Zig with no external
    // dependency, and an anchor against a foreign implementation belongs in
    // `modules/<m>/tools/`. Six modules were migrated that day; nothing stopped
    // the seventh from being written the old way tomorrow. Deliberately NOT a
    // section of `check-catalog` (change signal: source, not docs) and
    // deliberately not derived from `moduleHasInterop` -- having a `tools/`
    // program is no evidence that `src/` stopped spawning. See
    // `checkModulePurity`.
    const check_module_purity = b.step("check-module-purity", "Verify no module's own code runs a foreign toolchain");
    const check_module_purity_inner = gateRun(b, "check-module-purity", &.{});
    check_module_purity.dependOn(check_module_purity_inner);

    // Fuzz-coverage gate: `zig build check-fuzz`. Deliberately a SEPARATE step
    // from `check-catalog` rather than a section of it -- see `checkFuzz` for
    // why, and for the one-line change that folds it in once the tree is green.
    const check_fuzz = b.step("check-fuzz", "Verify every module with an untrusted byte surface has a fuzz harness");
    const check_fuzz_inner = gateRun(b, "check-fuzz", &.{});
    check_fuzz.dependOn(check_fuzz_inner);

    // Global-allocator gate: `zig build check-global-alloc`. CONVENTIONS.md
    // §1.2 says "caller-supplied allocators, no hidden globals" for the whole
    // collection; nothing enforced it until a caller-supplied-allocator bug
    // in `filestore.readExpiry` reached for `std.heap.page_allocator` instead
    // of the allocator its own caller had already passed in. The fix guarded
    // that ONE call site; nothing stopped the same shortcut from reappearing
    // there or anywhere else, because no test can observe which allocator a
    // function reached for -- only a source-level gate can.
    //
    // Ground truth (measured 2026-08-18 across every `modules/*/src/*.zig`,
    // `bench.zig` files excluded from the scan entirely): 30 process-global
    // allocator uses. 9 sit lexically inside a `test { ... }` block -- always
    // fine, a test's own allocator choice is the test's business, and this
    // gate does not even look at those. The remaining 21 needed a human
    // verdict: 16 are legitimate but NOT inside a literal `test` block (a
    // detached thread body a test spawns, a fork()'d child that never returns
    // to the parent's test state, a fixture cache deliberately outliving
    // `testing.allocator`'s per-test teardown, or -- `bls12_381`'s trusted-
    // setup cache and `bulletproofs`' allocator-less-by-signature verifiers --
    // a documented, deliberate part of the module's own API) and now carry an
    // inline `global-alloc-ok:` marker recording why, right next to the call
    // it exempts. The other 5 were bench-file uses, exempted by filename
    // rather than by marker since a benchmark is never the published module.
    //
    // Deliberately NOT gating `std.testing.allocator`'s location: unlike
    // `std.heap.page_allocator`, `std.testing.allocator` carries its own
    // `@compileError("testing allocator used when not testing")` inside `std`
    // itself (see `lib/std/testing.zig`) -- it is physically impossible to
    // compile a reference to it outside `builtin.is_test`, so there is no
    // production code path for this gate to catch. What IS common is fuzz
    // harnesses (`fn fuzzFoo(...)`, called via `testing.fuzz(fuzzFoo)` from an
    // actual `test` block) reading `testing.allocator` from a plain top-level
    // `fn`, not literal `test` syntax -- measured at 85 such sites across
    // ~40 modules. That is the repo's own blessed idiom for fuzz-harness
    // leak-checking (`check-fuzz`, above, already audits harness coverage),
    // not a hidden-global bug class, and 85 sites is exactly the "large,
    // scattered, and impossible to distinguish mechanically from a violation"
    // shape CONVENTIONS says not to gate -- so it stays out of this gate.
    const check_global_alloc = b.step("check-global-alloc", "Verify every process-global allocator use outside a test/bench is marked and justified");
    const check_global_alloc_inner = gateRun(b, "check-global-alloc", &.{});
    check_global_alloc.dependOn(check_global_alloc_inner);

    // Kernel-UAPI constant-drift gate: `zig build check-uapi` (campaign
    // C-09, wave-2 audit K3). `conntrack`/`devlink`/`ethtool`/`nl80211` each
    // transcribe hundreds of kernel netlink constants by hand; the audit
    // diffed every one of them against this host's `/usr/include/linux`
    // headers ONCE and proved with a fault injection that nothing else in
    // the repo would notice a wrong value (a mutated constant compiled and
    // `zig build test-<module>` stayed green, because each module's own
    // goldens read the same mutated symbol on both the encode and the
    // decode side). `scripts/checks/check-uapi-consts.py` is the standing version
    // of that diff. It is a SEPARATE step, not folded into `check-catalog`
    // or `test`, because unlike those it depends on host state this build
    // does not control: a machine without `python3` or without the kernel
    // headers installed can still build and test every module normally, so
    // this step SKIPS (does not fail the build) whenever either is missing
    // -- see `checkUapi` below and the script's own header-missing handling.
    // It is in the gate now (`scripts/test.sh`). Being host-dependent was the
    // reason it is not folded into `check-catalog`; it was never a reason not
    // to RUN it, and for months nothing did -- an audit found it reachable
    // only by typing the step name, with no record of when it last passed. It
    // skips rather than fails when python3 or the headers are missing, which
    // is exactly what makes it safe to run everywhere.
    //
    // `scripts/gen/check-citations.py` has the same host-dependency shape but is
    // NOT gated, for a different reason: measured on `dns`, it pairs an `RFC
    // NNNN` mention with any nearby quoted string, so a quoted SPEC.md heading
    // reports as a citation mismatch. It stays a manual tool until its
    // precision is gate-grade.
    const check_uapi = b.step("check-uapi", "Diff hardcoded kernel UAPI constants against installed kernel headers");
    const check_uapi_inner = gateRun(b, "check-uapi", &.{});
    check_uapi.dependOn(check_uapi_inner);

    // Dark-test gate: `zig build check-dark-tests`. Proves every test block on
    // disk is a test the compiler actually built. See `checkDarkTests` for why
    // this shells out, why it is not part of `zig build test`, and what it
    // costs.
    const dark_modules = b.option(
        []const []const u8,
        "dark-module",
        "Limit check-dark-tests to this module (repeatable; default: every module)",
    ) orelse &.{};
    const check_dark = b.step("check-dark-tests", "Verify every declared test block is one the test binary actually ran");
    {
        var args: std.ArrayList([]const u8) = .empty;
        for (dark_modules) |m| args.append(b.allocator, b.fmt("--dark-module={s}", .{m})) catch @panic("OOM");
        check_dark.dependOn(gateRun(b, "check-dark-tests", args.items));
    }

    // ── Constant-time (ctgrind) harnesses ───────────────────────────────
    //
    // `zig build ctgrind` builds every `modules/<m>/src/ctgrind_harness.zig`
    // into `<prefix>/ctgrind/ctgrind-<m>`; `scripts/checks/ctgrind.sh` drives them
    // under `valgrind --tool=memcheck` and prints the control table. They are
    // NOT tests and are NOT run by `zig build test`: memcheck's context count
    // is valgrind's own verdict, not something a Zig test can assert on.
    //
    // WHY THEY ARE COMPILED BY THE GATE ANYWAY (`check-ctgrind`, below). A
    // harness that nothing builds decays into an unbuildable recipe the first
    // time the module's API moves, and then the SPEC table it backs becomes
    // exactly the unfalsifiable claim the harness was written to end. The gate
    // therefore compiles them — cheap, needs no valgrind installed — while
    // leaving the measurement itself out of the critical path.
    //
    // `-Dctgrind-valgrind=false` builds with `-fno-valgrind`. That is not a
    // convenience: `std.valgrind.doClientRequest` opens with
    // `if (!builtin.valgrind_support) return default;`, which the release
    // optimize modes turn off, so a ReleaseFast binary built without the
    // switch is a SILENT no-op under valgrind and reports a clean 0 whatever
    // the code does. The driver builds both ways and prints the no-switch run
    // as its own row, so that trap is a measurement rather than an
    // unstated assumption.
    const ctgrind_valgrind = b.option(
        bool,
        "ctgrind-valgrind",
        "Build the ctgrind harnesses with -fvalgrind (default true; false reproduces the silent-no-op trap)",
    ) orelse true;
    const ctgrind_only = b.option(
        []const []const u8,
        "ctgrind-module",
        "Limit `zig build ctgrind` to this module (repeatable; default: every harness)",
    ) orelse &.{};

    const ctgrind = b.step("ctgrind", "Build the constant-time harnesses into <prefix>/ctgrind/ (run them with scripts/checks/ctgrind.sh)");
    const check_ctgrind = b.step("check-ctgrind", "Compile every ctgrind harness — rot guard, runs no valgrind");
    for (ctgrindHarnesses(b)) |name| {
        const src = b.path(b.fmt("modules/{s}/src/ctgrind_harness.zig", .{name}));
        const deps = blk: {
            for (module_list) |m| {
                if (std.mem.eql(u8, m.name, name)) break :blk m.deps;
            }
            unreachable; // derived FROM module_list
        };

        var selected = ctgrind_only.len == 0;
        for (ctgrind_only) |want| {
            if (std.mem.eql(u8, want, name)) selected = true;
        }
        if (selected) {
            // The harness's root module compiles the module under test from
            // its own sources (`@import("root.zig")`, a sibling path), so the
            // code being measured is built at exactly the optimize mode the
            // driver asked for — `-Doptimize` reaches it directly and the
            // `heavy` flag does NOT, because `heavy_optimize` is substituted
            // only when a module is taken from `mods`. That distinction is
            // load-bearing now that `montint` (which IS heavy) has a harness:
            // a heavy substitution here would silently move the measurement
            // to a different optimize mode than the row claims. Only
            // cross-module deps come from `mods`, and none of the seven
            // modules with a harness has any.
            const hmod = b.createModule(.{
                .root_source_file = src,
                .target = target,
                .optimize = optimize,
                .valgrind = ctgrind_valgrind,
                // Symbol names are how `scripts/checks/ctgrind.sh` attributes a
                // memcheck context to a file; a stripped binary reports
                // `???` and the whole table becomes unreadable.
                .strip = false,
            });
            hmod.addImport("zl_options", zl_options_mod);
            for (deps) |dep| hmod.addImport(dep, mods.get(dep).?);
            const exe = b.addExecutable(.{ .name = b.fmt("ctgrind-{s}", .{name}), .root_module = hmod, .use_llvm = use_llvm });
            const inst = b.addInstallArtifact(exe, .{
                .dest_dir = .{ .override = .{ .custom = "ctgrind" } },
            });
            ctgrind.dependOn(&inst.step);
        }
        // `-Dctgrind-module` narrows the rot guard too (2026-10-10): the push
        // lane compiles only the harnesses of the modules it is testing.
        if (!selected) continue;

        // The rot guard compiles at Debug (fastest) with `-fvalgrind` forced
        // on. The switch matches what the real run uses -- a harness that
        // compiles only with the switch off would otherwise pass the guard and
        // fail the moment anyone ran it.
        //
        // ⚠ THE MODE DOES NOT MATCH, and since 2026-09-08 it cannot: nothing is
        // measured in Debug any more (ctgrind-expected.tsv is 18 ReleaseFast +
        // 2 ReleaseSafe, 0 Debug) because valgrind cannot read the
        // `.debug_line` Zig's self-hosted backend emits, and that backend is
        // the default for Debug alone. See `scripts/checks/ctgrind.sh` § MODES. Debug
        // stays here because this guard is a COMPILE and Debug is the cheapest
        // mode to compile in; Zig's semantic analysis is mode-independent
        // except for explicit comptime branches on `builtin.mode`, and no
        // harness has one (checked 2026-09-08). What compiles the harnesses in
        // the modes they are actually measured in is the `ctgrind` lane, which
        // builds them as part of taking the measurement.
        //
        // ⛔ AND THIS GUARD IS NOT THE MEASUREMENT, which is the whole of audit
        // finding R14 item 1. It compiles; it asserts nothing about a single
        // context count. A harness can build perfectly and report a leak. Until
        // 2026-09-08 no lane ran `scripts/checks/ctgrind.sh --check` at all, so the 20
        // pinned rows were verified by nothing; `scripts/test.sh ctgrind` and
        // the CI lane of the same name exist to close that, and this step stays
        // exactly what it always was -- a rot guard that needs no valgrind.
        //
        // It is NOT what makes the taint calls visible to the guard, and the
        // tempting version of this comment ("the client-request bodies are
        // behind a comptime `builtin.valgrind_support` check, so without the
        // switch they go unanalysed") is wrong. `doClientRequest`'s guard is a
        // runtime early return, so the call and its arguments are analysed
        // either way. Measured 2026-08-11: a type error inside
        // `makeMemUndefined`'s argument fails this step with `.valgrind = true`
        // AND with `.valgrind = false`, both exit 1.
        //
        // `addExecutable`, not `addObject`: Zig analyses container-level
        // decls lazily, and only an executable forces `main` -- and therefore
        // everything the harness calls -- to be analysed at all. THAT is the
        // load-bearing choice here.
        const cmod = b.createModule(.{
            .root_source_file = src,
            .target = target,
            .optimize = .debug,
            .valgrind = true,
        });
        cmod.addImport("zl_options", zl_options_mod);
        for (deps) |dep| cmod.addImport(dep, mods.get(dep).?);
        const cexe = b.addExecutable(.{ .name = b.fmt("check-ctgrind-{s}", .{name}), .root_module = cmod, .use_llvm = use_llvm });
        check_ctgrind.dependOn(&cexe.step);
    }
    test_step.dependOn(check_ctgrind);
}

// ── Repo gates (Zig 0.17) ───────────────────────────────────────────────
//
// Zig 0.17 removed custom build steps (`std.Build.Step` is a closed set of
// tags; no `makeFn`). The checks that used to be make functions in this file
// -- module-graph, module-fingerprints, the catalog/changelog/copyleft/purity/
// fuzz/global-alloc/uapi gates, the generated README tables, check-portable,
// check-dark-tests -- are now ONE host program, `scripts/gates/`, built with
// LLVM for the host and run as a `Run` step per gate: `zl-gates <gate>
// [--module=<m>]...`. It imports this file (`build_zig`) for `module_list`
// and the other shared data, so the graph is still declared exactly once.
//
// Every gate step has side effects: it reads the tree at MAKE time and always
// runs, so neither the run cache nor the cached configuration can answer for
// it -- a gate that "passed" without looking is the false green this design
// exists to rule out. It runs with the build root as its cwd, whatever
// directory `zig build` was invoked from. `scripts/` is outside the package's
// `.paths`, so a consumer that fetched zig-libs has these steps but cannot run
// them -- as before, the gates are this repository's, not a consumer's.

var gate_tool: ?*std.Build.Step.Compile = null;

fn gateTool(b: *std.Build) *std.Build.Step.Compile {
    if (gate_tool) |t| return t;
    const defs = b.createModule(.{
        .root_source_file = b.path("build.zig"),
        .target = b.graph.host,
        .optimize = .safe,
    });
    const root = b.createModule(.{
        .root_source_file = b.path("scripts/gates/main.zig"),
        .target = b.graph.host,
        .optimize = .safe,
    });
    root.addImport("build_zig", defs);
    const exe = b.addExecutable(.{ .name = "zl-gates", .root_module = root, .use_llvm = true });
    gate_tool = exe;
    return exe;
}

/// `zl-gates <gate> <args> [--module=<m>]...` as a Run step, cwd = build root.
fn gateRunStep(b: *std.Build, gate: []const u8, args: []const []const u8) *std.Build.Step.Run {
    const run = b.addRunArtifact(gateTool(b));
    run.setName(gate);
    run.addArg(gate);
    run.addArgs(args);
    for (selected_modules) |m| run.addArg(b.fmt("--module={s}", .{m}));
    run.setCwd(b.path("."));
    run.has_side_effects = true;
    return run;
}

fn gateRun(b: *std.Build, gate: []const u8, args: []const []const u8) *std.Build.Step {
    return &gateRunStep(b, gate, args).step;
}

// ── Configure-time reads (Zig 0.17) ─────────────────────────────────────
//
// 0.17 CACHES the configure phase: `build()` is re-run only when an input it
// declared changes. A read this file does not declare is answered from the
// stale configuration -- a new `tools/interop.zig` gets no step, a new
// `src/*.zig` is missing from `own_files`, and nothing says so. Every read
// `build()` makes therefore goes through one of these, which declare it:
// a file's existence through its parent directory's listing (or the nearest
// ancestor that exists, so a directory created later is seen too), a walked
// tree through every directory in it (`dependOnDirectoryContents` is not
// recursive), and a parsed file through its contents. The gates do their
// reading at make time instead, in `scripts/gates/`, so they need none of it.

/// Directories already declared, so a module's five `tools/` probes add one
/// configure dependency, not five.
var declared_dirs: std.StringHashMapUnmanaged(void) = .empty;

fn declareDir(b: *std.Build, sub: []const u8) void {
    const gop = declared_dirs.getOrPut(b.allocator, sub) catch @panic("OOM");
    if (gop.found_existing) return;
    gop.key_ptr.* = b.dupe(sub);
    b.dependOnDirectoryContents(b.path(sub));
}

/// Declare the listing that decides whether `sub` exists: its nearest
/// existing ancestor directory.
fn declareExistence(b: *std.Build, sub: []const u8) void {
    var dir = std.fs.path.dirnamePosix(sub);
    while (dir) |d| : (dir = std.fs.path.dirnamePosix(d)) {
        if (b.root.access(b.graph.io, d, .{})) |_| {
            declareDir(b, d);
            return;
        } else |_| {}
    }
    declareDir(b, ".");
}

/// Whether `sub` (relative to the build root) exists, as a DECLARED read.
fn configureExists(b: *std.Build, sub: []const u8) bool {
    declareExistence(b, sub);
    return if (b.root.access(b.graph.io, sub, .{})) |_| true else |_| false;
}

/// Standalone consumer projects under `example-apps/`. Each has its own
/// `build.zig`/`build.zig.zon` and pins zig-libs by dated tag, so a copy taken
/// out of the repo builds on its own -- that is the point: they are what a new
/// user downloads, and `init.sh` is the one command that gets them running.
///
/// We get two more uses out of the same directory, and both are arranged from
/// OUTSIDE the app so its manifest stays the customer's:
///
///   1. `zig build --fork=../..` builds it against the commit under test, so a
///      published API this collection breaks is caught by something shaped
///      like a consumer rather than like a test.
///   2. Two builds of the SAME source at two versions can be run against each
///      other -- a server from the previous tag against a client from the
///      commit under test -- which is a wire-compatibility check no in-repo
///      test can be. That needs the source to compile against BOTH, so an app
///      is written against the TAGGED API and never against unreleased work.
///
/// `modules` is what the app imports. An app importing exactly one module is a
/// consumer-shaped build of that module's published API, so it discharges that
/// module's example obligation (CONVENTIONS.md §7.2) exactly as
/// `modules/<m>/example/` does.
pub const example_apps = [_]struct {
    name: []const u8,
    modules: []const []const u8,
}{
    .{ .name = "ssh-demo", .modules = &.{"ssh"} },
    .{ .name = "mls-chat", .modules = &.{ "mls", "framing", "lockfree" } },
    .{ .name = "timecapsule", .modules = &.{ "timelock_envelope", "drand", "hqc", "http", "datefmt" } },
    .{ .name = "raft-kv", .modules = &.{ "raft", "kv", "framing", "lockfree" } },
    .{ .name = "zstd-cli", .modules = &.{"zstd"} },
    .{ .name = "http-service", .modules = &.{
        "http",       "router",    "cors",        "security-headers",
        "ratelimit",  "requestid", "health",      "throttle",
        "abuseguard", "aaa-gate",  "idempotency", "tracecontext",
        "webhooksig", "openapi",   "ramcache",    "accesslog",
        "metrics",    "netaddr",
    } },
};

/// Which modules own a constant-time harness. DERIVED, never listed: the fact
/// is `modules/<m>/src/ctgrind_harness.zig` existing, and that file is its own
/// declaration. It used to be written out three times — here, and twice in
/// `scripts/checks/ctgrind.sh` — so a harness added without editing all three was
/// simply never measured, with every gate still green. `module-graph` publishes
/// the derived set so the script reads it instead of keeping a fourth copy.
fn ctgrindHarnesses(b: *std.Build) []const []const u8 {
    var out: std.ArrayList([]const u8) = .empty;
    for (module_list) |m| {
        if (!configureExists(b, b.fmt("modules/{s}/src/ctgrind_harness.zig", .{m.name}))) continue;
        out.append(b.allocator, m.name) catch @panic("OOM");
    }
    return out.items;
}

pub fn moduleIndex(name: []const u8) ?usize {
    for (module_list, 0..) |m, i| if (std.mem.eql(u8, m.name, name)) return i;
    return null;
}

/// The top-level declarations `module-fingerprints` leaves out of the
/// machinery hash (2026-10-10): declarations only the repo checks and
/// generators use -- since Zig 0.17 those checks live in `scripts/gates/`, so
/// what is left here is the data the gate tool reads from this file and no
/// module wiring touches. Editing one used to re-key all ~240 modules and
/// turn the push lane into a cold run of the collection. Computed, not chosen:
/// `scripts/checks/fingerprint-exempt.py --write` regenerates it and the
/// default (`--check`, in every gate) fails when a listed name has become
/// reachable from module wiring.
pub const fingerprint_exempt = [_][]const u8{
    "PortableDecl",
    "PortablePair",
    "example_apps",
    "fingerprint_exempt",
};

/// `-Dmodule` as given, for the source-scanning steps whose make functions
/// cannot see `build()`'s locals. Empty = every module.
var selected_modules: []const []const u8 = &.{};

/// Consumer build profile (`-Dprofile`, or `.profile` in a consumer's
/// `b.dependency("zig_libs", .{ ... })`). `.default` is what every grade is
/// measured on — speed and security; `.small` trades speed or capability for
/// code size, never safety. Each module decides what `.small` means for itself
/// and documents it in its SPEC § "Build options"; a module without such a
/// trade-off ignores it. See CONVENTIONS.md § "Consumer build options".
pub const Profile = enum { default, small };

/// The `zl_options` module: the consumer's build options as comptime values.
/// Imported by every compilation of a module's OWN sources (published module,
/// test root, cross-compiles, bench graph, ctgrind harnesses) — a module that
/// reads an option must see the same value in every one of them.
var zl_options_mod: *std.Build.Module = undefined;

/// `-Dmodule` membership: every module when the list is empty.
pub fn inList(name: []const u8, list: []const []const u8) bool {
    if (list.len == 0) return true;
    for (list) |x| if (std.mem.eql(u8, x, name)) return true;
    return false;
}

/// `-Dgroup` membership: every module when no group is given, else the ones
/// whose primary lib (`libs[0]`) is listed.
pub fn inGroups(m: Module, groups: []const []const u8) bool {
    if (groups.len == 0) return true;
    for (groups) |g| if (std.mem.eql(u8, m.libs[0], g)) return true;
    return false;
}

/// Whether a module ships an example. The file on disk IS the declaration --
/// there is no flag to keep in step with it, and so no way for the two to
/// disagree. Called at configure time, once per module.
/// A module's own source files, named the way `@typeName` spells them:
/// `modules/<m>/src/wire.zig` is `wire`. Handed to `scripts/lib/force-pubfn-reach.zig`
/// so its `declaredHere` can tell a container declared in a sibling FILE of the
/// module under test (walk it -- nothing else ever will) from one re-exported
/// out of std or a sibling MODULE (skip it -- that tests its owner, not us).
///
/// Derived, never listed: the files ARE the declaration. It cannot be a name
/// heuristic instead, because this collection owns files called `os.zig`,
/// `json.zig`, `atomic.zig` and `crypto.zig` -- the same first path segment
/// means "ours" in one module and "std's" in the next.
fn moduleFileNamespaces(b: *std.Build, io: std.Io, name: []const u8) []const []const u8 {
    var out: std.ArrayList([]const u8) = .empty;
    const src_sub = b.fmt("modules/{s}/src", .{name});
    var dir = b.root.openDir(io, src_sub, .{ .iterate = true }) catch {
        // Declared anyway: a `src/` that appears later must re-run configure.
        declareExistence(b, src_sub);
        return &.{};
    };
    defer dir.close(io);
    // Zig 0.17 caches the configure phase: the walk below is only re-done
    // when one of these directory listings changes, so EVERY directory of the
    // tree is declared (`dependOnDirectoryContents` is not recursive).
    declareDir(b, src_sub);
    var walker = dir.walk(b.allocator) catch @panic("OOM");
    defer walker.deinit();
    while (walker.next(io) catch @panic("walk failed")) |entry| {
        if (entry.kind == .directory) declareDir(b, b.fmt("{s}/{s}", .{ src_sub, entry.path }));
        if (entry.kind != .file) continue;
        if (!std.mem.endsWith(u8, entry.basename, ".zig")) continue;
        const rel = entry.path[0 .. entry.path.len - ".zig".len];
        const ns = b.allocator.dupe(u8, rel) catch @panic("OOM");
        for (ns) |*c| if (c.* == '/') {
            c.* = '.';
        };
        out.append(b.allocator, ns) catch @panic("OOM");
    }
    return out.toOwnedSlice(b.allocator) catch @panic("OOM");
}

/// The options module `scripts/lib/force-pubfn-reach.zig` imports as `own_files`.
/// Built once per module and shared by the native gate and every cross-compile,
/// so the two can never be handed different lists.
fn ownFilesModule(b: *std.Build, name: []const u8) *std.Build.Module {
    const opts = b.addOptions();
    opts.addOption([]const []const u8, "names", moduleFileNamespaces(b, b.graph.io, name));
    return opts.createModule();
}

/// Whether a module carries a LIVE-NETWORK program — `modules/<name>/tools/live.zig`.
///
/// Separate from `moduleHasInterop` and separate on purpose: an interop program
/// asserts it needs no network, a live program asserts it needs one. A module
/// may have either, both, or neither.
fn moduleHasLive(b: *std.Build, name: []const u8) bool {
    const path = b.fmt("modules/{s}/tools/live.zig", .{name});
    return configureExists(b, path);
}

/// Whether a module carries an interop PROGRAM — `modules/<name>/tools/interop.zig`.
/// Existence is the declaration: a table listing which modules have one would be
/// a second place to forget, and this repository retired two such tables in
/// August for exactly that reason.
fn moduleHasInterop(b: *std.Build, name: []const u8) bool {
    const path = b.fmt("modules/{s}/tools/interop.zig", .{name});
    return configureExists(b, path);
}

/// A ReleaseFast copy of module `name` with its dependency closure, memoised
/// in `fast` -- what a bench program links, whatever -Doptimize says.
fn fastModuleGraph(b: *std.Build, target: std.Build.ResolvedTarget, fast: *std.StringHashMap(*std.Build.Module), name: []const u8) *std.Build.Module {
    if (fast.get(name)) |existing| return existing;
    const entry = for (module_list) |e| {
        if (std.mem.eql(u8, e.name, name)) break e;
    } else @panic("fastModuleGraph: unknown module");
    const mod = b.createModule(.{
        .root_source_file = b.path(b.fmt("modules/{s}/src/root.zig", .{name})),
        .target = target,
        .optimize = .fast,
    });
    fast.put(name, mod) catch @panic("OOM");
    mod.addImport("zl_options", zl_options_mod);
    for (entry.deps) |dep| mod.addImport(dep, fastModuleGraph(b, target, fast, dep));
    return mod;
}

/// Whether a module carries a comparative BENCHMARK — `modules/<name>/tools/bench.zig`.
/// Whether a module carries a SIZE PROBE — `modules/<name>/tools/sizeprobe.zig`.
fn moduleHasSizeprobe(b: *std.Build, name: []const u8) bool {
    const path = b.fmt("modules/{s}/tools/sizeprobe.zig", .{name});
    return configureExists(b, path);
}

fn moduleHasBench(b: *std.Build, name: []const u8) bool {
    const path = b.fmt("modules/{s}/tools/bench.zig", .{name});
    return configureExists(b, path);
}

fn moduleHasExample(b: *std.Build, name: []const u8) bool {
    const path = b.fmt("modules/{s}/example/main.zig", .{name});
    return configureExists(b, path);
}

/// `zig build check-dark-tests` — every test block on disk must be a test the
/// compiler actually built.
///
/// ⭐ THE FAILURE THIS EXISTS TO CATCH HAS NO OTHER SYMPTOM. Zig collects tests
/// only from the files it ANALYSES. A re-export (`pub const conn =
/// @import("conn.zig");`) does not analyse anything on its own, so unless some
/// analysed code references a decl of that file — in practice a
/// `test { _ = conn; }` aggregator — the file's tests are never compiled and
/// never run. There is no failure, no skip, no warning, and the suite total is
/// computed from what ran, so it agrees with itself. `websocket` shipped running
/// ZERO of its 52 tests (one did not even compile); `ratelimit` reported
/// `18/18 passed`, exit 0, with `conn.zig`'s entire suite absent.
///
/// WHY IT SHELLS OUT. Same reason as `check-uapi`: the script is the artifact.
/// It is also the only place that CAN do this — the quantity it needs,
/// `(N total)`, exists only in the build runner's `--summary all` output, which
/// a step inside that same build cannot read.
///
/// WHY IT IS NOT FOLDED INTO `zig build test` OR INTO `check-catalog`.
/// Measured, not assumed: Zig does not cache test RUN steps. The same
/// `zig build test-bech32 test-decimal test-seqmap test-kv test-tar test-mcp
/// --summary all` takes 13.3 s twice in a row, `compile test … cached` on both,
/// with every run step re-executing. So a step that reruns the suites in order
/// to count their tests costs a second full test run — it would roughly double
/// the ~367 s gate. `scripts/test.sh` therefore does NOT call this step: it
/// passes `--summary all` to the run it was going to make anyway, keeps the
/// output, and hands it to `scripts/lib/dark-tests.sh --summary <file>`, which
/// builds nothing. That path is the gate; this step is the standalone entry
/// point for a CI shape that does not go through the driver, and for running
/// the check by hand. `-Ddark-module=<name>` narrows it.
/// The declared-target vocabulary for `meta.targets` (CONVENTIONS.md §4).
/// Each tag is a real, checkable claim.
pub const PortableTarget = enum {
    /// Linux, amd64 or arm64 -- the collection's baseline. Every module in
    /// `module_list` already proves this by existing (CONVENTIONS.md §6/§7:
    /// tests green in all three release lanes on the native x86_64 runner,
    /// plus the CI matrix's separate arm64 lane), so it is MANDATORY in every
    /// module's declared set (`parseMetaTargets` rejects a set without it)
    /// and it is the one tag `query()` returns `null` for -- proven by the
    /// default test suite, never cross-compiled by this gate.
    linux64,
    /// 32-bit, BIG-ENDIAN Linux, soft-float. Representative target
    /// `mips-linux-musl` + `mips32,soft_float` -- a downstream device agent's
    /// real cross-compile query, taken verbatim from its own probe (an ath79
    /// 24Kc has no FPU, so soft-float is load-bearing, not incidental --
    /// `musleabihf` would silently pick a hard-float ABI that hardware cannot
    /// run). Named as that
    /// specific architecture rather than "any 32-bit Linux" because
    /// endianness is exactly the defect class a little-endian 32-bit probe
    /// (wasm32, i686, mipsel, arm) cannot catch: a module that reads/writes a
    /// multi-byte wire field with an implicit little-endian assumption passes
    /// every OTHER lane in this collection (every one of them little-endian,
    /// and all but this one 64-bit) and only breaks here. Folding `.linux32`
    /// into a wider "any 32-bit" class would let a module pass on a
    /// little-endian 32-bit target (say, mipsel or i686) and claim readiness
    /// for the actual big-endian target it was never built for -- an
    /// unverified claim wearing a verified one's label, the exact
    /// bait-and-switch this schema replaces.
    linux32,
    /// `x86_64-windows-gnu` -- a downstream GUI bridge ships a DLL there, and
    /// spawns a CLI child on the same platform.
    windows,
    /// `wasm32-wasi`. The pointer-width probe this gate originally shipped
    /// with (see the long comment at `check-portable`'s call site in
    /// `build()` for why wasi and not freestanding) -- unchanged, just no
    /// longer tied to a single `platform = .any` sweep.
    wasm32,

    pub fn label(self: PortableTarget) []const u8 {
        return @tagName(self);
    }

    /// The real cross-compile query for this target, or `null` for
    /// `.linux64` (see its doc comment: proven elsewhere, never
    /// cross-compiled here).
    fn query(self: PortableTarget) ?std.Target.Query {
        return switch (self) {
            .linux64 => null,
            .linux32 => .{
                .cpu_arch = .mips,
                .os_tag = .linux,
                .abi = .musl, // static musl, NOT musleabihf -- the target hardware has no FPU
                .cpu_features_add = std.Target.mips.featureSet(&.{ .mips32, .soft_float }),
            },
            .windows => .{ .cpu_arch = .x86_64, .os_tag = .windows, .abi = .gnu },
            .wasm32 => .{ .cpu_arch = .wasm32, .os_tag = .wasi },
        };
    }
};

/// The cross-compiled subset of `PortableTarget` -- everything `check-portable`
/// can actually sweep (`.linux64` is deliberately excluded; see its doc
/// comment on the enum above).
pub const cross_compile_targets = [_]PortableTarget{ .wasm32, .windows, .linux32 };

/// One (module, target) pair `check-portable` is responsible for -- either
/// because the module declares that target in `meta.targets`, or (with
/// `-Dportable-measure-all`) because every pair is being probed regardless of
/// declaration.
pub const PortablePair = struct { module: []const u8, target: PortableTarget };

/// A module's full declared set, as read from `meta.targets` -- the raw
/// material `check-portable-table`'s generator groups into rows. Distinct
/// from `PortablePair` (one declared (module, target) pair each): this is
/// one entry per MODULE, carrying its whole declared set including the
/// mandatory `.linux64`.
pub const PortableDecl = struct { module: []const u8, targets: []const PortableTarget };

/// A module's `meta.targets` declaration, or the reason it could not be read.
/// `err == null` iff `targets` is a valid, non-empty, duplicate-free set that
/// includes `.linux64` (CONVENTIONS.md §4). Read from the module's own source
/// because that block is the canonical declaration; a duplicate list in this
/// file would be a second thing to keep in step (this replaces the old
/// `declaresAnyPlatform`, which only ever answered "is it `.any`").
pub const ParsedTargets = struct {
    targets: []const PortableTarget = &.{},
    err: ?[]const u8 = null,
};

fn parseMetaTargets(b: *std.Build, io: std.Io, name: []const u8) ParsedTargets {
    const path = b.fmt("modules/{s}/src/root.zig", .{name});
    const full = b.root.join(b.allocator, path) catch @panic("OOM");
    const src = full.root_dir.handle.readFileAlloc(io, full.sub_path, b.allocator, .limited(4 * 1024 * 1024)) catch |err| {
        declareExistence(b, path);
        return .{ .err = b.fmt("cannot read {s}: {t}", .{ path, err }) };
    };
    // Configure-time read (Zig 0.17 caches configure): which
    // `portable-<m>-<t>` steps exist depends on this file's text.
    b.dependOnFileContents(b.path(path));
    return parseMetaTargetsSrc(b.allocator, src);
}

/// The pure half of `parseMetaTargets`, shared with the gate tool
/// (`scripts/gates/`), so the steps `build()` creates and the tables the gates
/// render are derived by one parser.
pub fn parseMetaTargetsSrc(gpa: std.mem.Allocator, src: []const u8) ParsedTargets {
    const meta_idx = std.mem.find(u8, src, "pub const meta") orelse
        return .{ .err = "has no `pub const meta` block" };
    const meta_end = std.mem.findPos(u8, src, meta_idx, "\n};") orelse src.len;
    const block = src[meta_idx..meta_end];

    // Match the compound literal, not bare `.targets` -- a doc comment can
    // say `` `meta.targets = .{.wasm32}` `` in prose ahead of the real field
    // (`metaDepsFromRoot` has the identical guard for `.deps`, for the same
    // reason: a bare-word search would land on the prose instead).
    const targets_idx = std.mem.find(u8, block, ".targets = .{") orelse
        return .{ .err = "`meta` block has no `.targets = .{...}` field" };
    const open = std.mem.findScalarPos(u8, block, targets_idx, '{').?;
    const close = std.mem.findScalarPos(u8, block, open, '}') orelse
        return .{ .err = "`.targets` list has no closing `}`" };
    const inner = block[open + 1 .. close];

    var out: std.ArrayList(PortableTarget) = .empty;
    var i: usize = 0;
    while (std.mem.findScalarPos(u8, inner, i, '.')) |dot| {
        var j = dot + 1;
        while (j < inner.len and (std.ascii.isAlphanumeric(inner[j]) or inner[j] == '_')) j += 1;
        const tok = inner[dot + 1 .. j];
        i = j;
        if (tok.len == 0) continue;
        const t = std.meta.stringToEnum(PortableTarget, tok) orelse
            return .{ .err = gpa.print("meta.targets names unknown target `.{s}`", .{tok}) catch @panic("OOM") };
        for (out.items) |seen| if (seen == t)
            return .{ .err = gpa.print("meta.targets lists `.{s}` twice", .{tok}) catch @panic("OOM") };
        out.append(gpa, t) catch @panic("OOM");
    }
    if (out.items.len == 0) return .{ .err = "meta.targets is empty" };
    for (out.items) |t| {
        if (t == .linux64) return .{ .targets = out.toOwnedSlice(gpa) catch @panic("OOM") };
    }
    return .{ .err = "meta.targets does not include `.linux64` -- every module claims the collection's baseline target (CONVENTIONS.md §4)" };
}
