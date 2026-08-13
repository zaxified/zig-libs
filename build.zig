const std = @import("std");

// zig-libs — a curated collection of foundational Zig modules.
//
// Layout rationale: ONE build.zig at the repo root. `zig fetch` cannot target a
// subdirectory (ziglang/zig#23012), so a consumer fetches the whole repo and
// imports only the named module(s) it wants; the root build wires them up.
//
// Each module lives at modules/<name>/src/root.zig and is exposed as an
// importable module named <name>. `deps` lists sibling modules it imports.
// See CONVENTIONS.md for naming + the `meta` tag vocabulary.

const Module = struct {
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
    /// Compute-bound: the tests are dominated by arithmetic (pairings,
    /// hash-based signatures, FHE, scrypt, RSA), which an unoptimized Debug
    /// build makes ~5x slower — `bls12_381` alone goes 35s -> 182s. These
    /// modules ARE the test suite's critical path, so they are built at
    /// ReleaseSafe when the requested mode is Debug. ReleaseSafe keeps every
    /// safety check; only Debug-specific behaviour (0xAA-poisoned undefined
    /// memory) is given up. Pass `-Dstrict-debug` to force real Debug — that
    /// is what the CI matrix does. Threshold: >15s measured serially.
    heavy: bool = false,
};

const module_list = [_]Module{
    // Test-only harness. Consumers reach it through `test_deps`, never `deps`.
    .{ .name = "testkit" },
    .{ .name = "netaddr" },
    // `workerpool` is a TEST-only dep: `h2_server.Options.dispatcher` is an
    // injectable seam (a function pointer + a context pointer), so the
    // published `http` module implements no pool at all — deliberately, since
    // `websocket`/`accesslog`/`grpc`/`mcp-http`/… all depend on `http` and
    // none of them should acquire threads by transitive accident. The tests
    // wire a real `workerpool.WorkerPool` into that seam because the five
    // concurrency invariants can only be exercised by real threads.
    // `zig build check-testonly` proves the published module never needs it.
    .{ .name = "http", .deps = &.{"netaddr"}, .test_deps = &.{ "testkit", "workerpool" } },
    .{ .name = "websocket", .deps = &.{"http"} },
    .{ .name = "accesslog", .deps = &.{"http"} },
    .{ .name = "staticfiles", .deps = &.{"http"} },
    .{ .name = "brotli", .test_deps = &.{"testkit"} },
    .{ .name = "dns", .deps = &.{ "netaddr", "http" } },
    .{ .name = "ramcache" },
    .{ .name = "router", .deps = &.{"http"} },
    .{ .name = "ratelimit", .deps = &.{ "router", "http", "netaddr" } },
    .{ .name = "abuseguard", .deps = &.{ "http", "netaddr", "router" } },
    .{ .name = "throttle", .deps = &.{ "router", "http" } },
    // Importable as @import("security-headers") — module names are plain
    // strings, the hyphen is fine (cf. the community's "known-folders").
    .{ .name = "security-headers", .deps = &.{ "router", "http" } },
    .{ .name = "cors", .deps = &.{ "router", "http" } },
    .{ .name = "metrics", .deps = &.{ "router", "http" } },
    .{ .name = "validate", .deps = &.{ "router", "http", "netaddr" } },
    .{ .name = "openapi", .deps = &.{ "router", "http" } },
    .{ .name = "health", .deps = &.{ "router", "http" } },
    .{ .name = "requestid", .deps = &.{ "router", "http" } },
    .{ .name = "linkheader" },
    .{ .name = "cookies", .deps = &.{"http"} },
    .{ .name = "idempotency", .deps = &.{ "router", "http", "ramcache" } },
    .{ .name = "webhooksig", .deps = &.{ "router", "http" } },
    .{ .name = "tracecontext", .deps = &.{ "router", "http" } },
    // Importable as @import("aaa-gate") — hyphen OK, like security-headers.
    .{ .name = "aaa-gate", .deps = &.{ "router", "http" } },
    .{ .name = "resilience" },
    .{ .name = "acme", .deps = &.{ "http", "router", "entropy" } },
    .{ .name = "netlink", .test_deps = &.{"testkit"} },
    .{ .name = "genetlink", .deps = &.{"netlink"} },
    .{ .name = "nl80211", .deps = &.{ "genetlink", "netlink" }, .test_deps = &.{"testkit"} },
    .{ .name = "ethtool", .deps = &.{ "genetlink", "netlink" }, .test_deps = &.{"testkit"} },
    .{ .name = "devlink", .deps = &.{ "genetlink", "netlink" }, .test_deps = &.{"testkit"} },
    .{ .name = "decimal" },
    .{ .name = "seqmap" },
    .{ .name = "icmp", .deps = &.{ "seqmap", "netaddr" } },
    .{ .name = "mcp" },
    .{ .name = "mcp-http", .deps = &.{ "router", "http", "mcp" } },
    .{ .name = "coap" },
    .{ .name = "kv" },
    .{ .name = "kvtree", .deps = &.{"kv"} },
    .{ .name = "blobmsg" },
    .{ .name = "tar" },
    .{ .name = "latency-stats" },
    .{ .name = "pping" },
    .{ .name = "spf-ect" },
    .{ .name = "ethfrag" },
    .{ .name = "l2encap" },
    .{ .name = "l2forward" },
    .{ .name = "pbb" },
    .{ .name = "bumtree", .deps = &.{"spf-ect"} },
    .{ .name = "spbfib", .deps = &.{"isis-spf"} },
    .{ .name = "isis" },
    .{ .name = "isis-adj", .deps = &.{"isis"} },
    .{ .name = "isis-dis", .deps = &.{"isis"} },
    .{ .name = "isis-lsdb", .deps = &.{"isis"} },
    .{ .name = "isis-flood", .deps = &.{ "isis", "isis-lsdb" } },
    .{ .name = "isis-spf", .deps = &.{ "isis", "isis-lsdb", "spf-ect" } },
    .{ .name = "isis-sim", .deps = &.{ "netsim", "isis", "isis-lsdb", "isis-flood", "isis-spf" } },
    .{ .name = "aeadframe", .deps = &.{"chachapoly"} },
    .{ .name = "tenantkex", .deps = &.{"noise"} },
    .{ .name = "netsim" },
    .{ .name = "loopfree-reconv", .deps = &.{ "netsim", "spf-ect" } },
    .{ .name = "df-elect", .deps = &.{"netsim"} },
    .{ .name = "raft", .deps = &.{"netsim"} },
    .{ .name = "liveness-hyst", .deps = &.{ "netsim", "latency-stats" } },
    .{ .name = "loopix", .deps = &.{ "netsim", "sphinx" } },
    .{ .name = "lockfree" },
    .{ .name = "workerpool", .deps = &.{"lockfree"} },
    .{ .name = "shardstore", .deps = &.{"kvtree"} },
    .{ .name = "writebehind", .deps = &.{ "ramcache", "workerpool", "jobqueue", "kvtree" } },
    .{ .name = "pagecache", .deps = &.{ "kvtree", "ramcache" } },
    .{ .name = "tsdb", .deps = &.{"kvtree"} },
    .{ .name = "entropy" },
    .{ .name = "hashdigest" },
    .{ .name = "sealedbox" },
    .{ .name = "rsa", .deps = &.{"montint"}, .heavy = true },
    .{ .name = "blindrsa", .deps = &.{"rsa"} },
    .{ .name = "ssh", .deps = &.{"rsa"}, .heavy = true },
    .{ .name = "netconf", .deps = &.{ "ssh", "xml" }, .test_deps = &.{"testkit"} },
    .{ .name = "nftables", .deps = &.{"netlink"}, .test_deps = &.{"testkit"} },
    .{ .name = "trie" },
    .{ .name = "fuzzysearch", .deps = &.{"trie"} },
    .{ .name = "geoindex" },
    .{ .name = "readthrough", .deps = &.{"ramcache"} },
    .{ .name = "timelock_envelope", .deps = &.{ "tlock", "hqc", "chachapoly", "entropy" } },
    .{ .name = "drand", .deps = &.{ "bls12_381", "tlock" } },
    .{ .name = "tcplan", .deps = &.{"tc"} },
    .{ .name = "modbus" },
    .{ .name = "iec104", .test_deps = &.{"testkit"} },
    .{ .name = "fleetsim", .deps = &.{ "modbus", "dnp3", "iec104", "s7comm", "bacnet", "enip", "opcua", "netsim" }, .test_deps = &.{"testkit"} },
    .{ .name = "smtp", .deps = &.{"netaddr"}, .test_deps = &.{"testkit"} },
    .{ .name = "imap", .test_deps = &.{"testkit"} },
    .{ .name = "iec61850", .deps = &.{"xml"}, .test_deps = &.{"testkit"} },
    .{ .name = "iec62351", .deps = &.{ "x509", "rsa" } },
    .{ .name = "s7comm", .test_deps = &.{"testkit"} },
    .{ .name = "enip", .deps = &.{"netaddr"}, .test_deps = &.{"testkit"} },
    .{ .name = "bacnet", .deps = &.{ "netaddr", "websocket" }, .test_deps = &.{"testkit"} },
    .{ .name = "whois", .deps = &.{"netaddr"} },
    .{ .name = "uci" },
    .{ .name = "mqtt" },
    .{ .name = "snmp", .test_deps = &.{"testkit"} },
    .{ .name = "wireguard", .deps = &.{ "netlink", "genetlink", "chachapoly", "entropy" } },
    .{ .name = "tc", .deps = &.{"netlink"}, .test_deps = &.{"testkit"} },
    .{ .name = "traceroute", .deps = &.{ "icmp", "netaddr", "latency-stats" } },
    .{ .name = "probe", .deps = &.{ "netaddr", "latency-stats" }, .test_deps = &.{"testkit"} },
    .{ .name = "l2disco", .deps = &.{"netaddr"} },
    .{ .name = "upstream", .deps = &.{ "resilience", "probe" } },
    .{ .name = "jwt", .deps = &.{ "http", "router", "p256" } },
    .{ .name = "rbac" },
    .{ .name = "xml" },
    .{ .name = "xmldsig", .deps = &.{ "xml", "rsa", "p256" } },
    .{ .name = "saml", .deps = &.{ "xmldsig", "xml", "xmlenc", "rsa", "x509", "datefmt" }, .heavy = true },
    .{ .name = "xmlenc", .deps = &.{ "xml", "rsa", "aescbc", "aeskw" }, .heavy = true },
    .{ .name = "aescbc" },
    .{ .name = "aeskw" },
    .{ .name = "jwe", .deps = &.{ "rsa", "p256", "aescbc", "aeskw" } },
    .{ .name = "rdap", .deps = &.{ "http", "netaddr" } },
    .{ .name = "blobstore", .deps = &.{"hashdigest"} },
    .{ .name = "procnet", .deps = &.{"netaddr"} },
    .{ .name = "conntrack", .deps = &.{ "netlink", "netaddr" }, .test_deps = &.{"testkit"} },
    .{ .name = "procrun", .deps = &.{"argsafe"} },
    .{ .name = "dataset" },
    .{ .name = "tabular", .deps = &.{"dataset"} },
    .{ .name = "jsonshape", .deps = &.{"dataset"} },
    .{ .name = "finstats", .deps = &.{"dataset"} },
    .{ .name = "filestore" },
    .{ .name = "framing" },
    .{ .name = "datefmt" },
    .{ .name = "diagnostics" },
    .{ .name = "json5" },
    .{ .name = "yaml" },
    .{ .name = "jinja", .test_deps = &.{"testkit"} },
    .{ .name = "cbor" },
    .{ .name = "protobuf", .test_deps = &.{"testkit"} },
    .{ .name = "grpc", .deps = &.{ "http", "protobuf" }, .test_deps = &.{"testkit"} },
    .{ .name = "webauthn", .deps = &.{ "cbor", "rsa", "p256", "x509" } },
    .{ .name = "zipstream" },
    .{ .name = "tz", .deps = &.{"datefmt"} },
    .{ .name = "pollworker" },
    .{ .name = "ipcbus", .deps = &.{"framing"} },
    .{ .name = "csvstream" },
    .{ .name = "csvsafe" },
    .{ .name = "numparse", .deps = &.{"decimal"} },
    .{ .name = "argsafe" },
    .{ .name = "sessions", .deps = &.{ "router", "http", "cookies", "ramcache", "entropy" } },
    .{ .name = "jobqueue", .deps = &.{"kv"} },
    .{ .name = "reconcilable", .deps = &.{"resilience"} },
    .{ .name = "llmclient", .deps = &.{"http"} },
    .{ .name = "rawsock", .deps = &.{"netaddr"} },
    .{ .name = "encoding" },
    .{ .name = "syslog" },
    .{ .name = "sntp" },
    .{ .name = "stun", .deps = &.{"netaddr"} },
    .{ .name = "opcua", .deps = &.{ "rsa", "x509" }, .test_deps = &.{"testkit"}, .heavy = true },
    .{ .name = "noise", .deps = &.{"chachapoly"} },
    .{ .name = "x509", .deps = &.{"rsa"} },
    .{ .name = "ocsp", .deps = &.{ "x509", "rsa", "p256" }, .heavy = true },
    .{ .name = "ocspcache", .deps = &.{ "ocsp", "http", "x509" } },
    .{ .name = "dnssec", .deps = &.{ "dns", "rsa" } },
    .{ .name = "dnp3", .deps = &.{"aeskw"} },
    .{ .name = "slhdsa", .heavy = true },
    .{ .name = "falcon" },
    .{ .name = "hqc", .heavy = true },
    .{ .name = "dtls", .deps = &.{ "rsa", "x509", "chachapoly" }, .test_deps = &.{"testkit"} },
    .{ .name = "tlsresume" },
    .{ .name = "quic-crypto", .deps = &.{"chachapoly"} },
    .{ .name = "sandbox" },
    .{ .name = "bip340", .deps = &.{"k256"} },
    .{ .name = "taproot", .deps = &.{ "bip340", "k256" } },
    .{ .name = "bitcointx", .deps = &.{"bip340"} },
    .{ .name = "psbt", .deps = &.{ "bitcointx", "bitcoinscript" } },
    .{ .name = "bitcoinscript", .deps = &.{ "bitcointx", "k256", "bip340", "ripemd160" } },
    .{ .name = "btcp2p", .deps = &.{"bitcointx"} },
    .{ .name = "lnwire" },
    .{ .name = "lninvoice", .deps = &.{ "bech32", "k256", "lnwire", "bip340" } },
    .{ .name = "musig2", .deps = &.{ "bip340", "k256" } },
    .{ .name = "sphinx", .deps = &.{"k256"} },
    .{ .name = "bolt8", .deps = &.{ "noise", "k256" } },
    .{ .name = "bolt3", .deps = &.{"k256"} },
    .{ .name = "hpke", .deps = &.{ "p256", "chachapoly", "entropy" } },
    .{ .name = "adaptor", .deps = &.{ "bip340", "k256" } },
    .{ .name = "frost", .deps = &.{ "bip340", "k256" } },
    .{ .name = "oscore" },
    .{ .name = "spake2plus", .deps = &.{"p256"} },
    .{ .name = "ct25519" },
    .{ .name = "voprf", .deps = &.{"ct25519"} },
    .{ .name = "opaque", .deps = &.{ "voprf", "ct25519" } },
    .{ .name = "bulletproofs", .deps = &.{"ct25519"} },
    .{ .name = "xmss", .heavy = true },
    .{ .name = "minisign", .deps = &.{"entropy"}, .heavy = true },
    .{ .name = "otp" },
    .{ .name = "ctap2pin", .deps = &.{"p256"} },
    .{ .name = "bls12_381", .deps = &.{"entropy"}, .heavy = true },
    .{ .name = "bbs", .deps = &.{ "bls12_381", "entropy" } },
    .{ .name = "coconut", .deps = &.{"bls12_381"}, .heavy = true },
    .{ .name = "tlock", .deps = &.{ "bls12_381", "entropy" } },
    // `tlock` is a TEST-only dep: `ibe/src/kat_test.zig` drives `ibe`'s own
    // encrypt/decrypt through `ibe.Scheme` with drand's ciphersuite, to
    // byte-compare against the genuine drand-Go-produced ciphertext `tlock`
    // already has frozen. The published `ibe` module never imports it --
    // `zig build check-testonly` proves that.
    .{ .name = "ibe", .deps = &.{ "bls12_381", "entropy" }, .test_deps = &.{"tlock"}, .heavy = true },
    .{ .name = "bn254", .heavy = true },
    .{ .name = "ed448", .deps = &.{"entropy"} },
    .{ .name = "decaf448", .deps = &.{"ed448"} },
    .{ .name = "paillier", .deps = &.{"montint"}, .heavy = true },
    .{ .name = "threshold_ecdsa", .deps = &.{ "paillier", "montint" }, .heavy = true },
    .{ .name = "dkg", .deps = &.{ "threshold_ecdsa", "paillier" }, .heavy = true },
    .{ .name = "vdf", .deps = &.{"montint"} },
    .{ .name = "signal", .deps = &.{ "chachapoly", "ct25519", "entropy" } },
    .{ .name = "mls", .deps = &.{"hpke"} },
    .{ .name = "megolm", .deps = &.{ "aescbc", "entropy" } },
    .{ .name = "ebpf", .deps = &.{"netlink"}, .test_deps = &.{"testkit"} },
    .{ .name = "xdp-classifier", .deps = &.{"ebpf"} },
    .{ .name = "ecvrf", .deps = &.{"ct25519"} },
    .{ .name = "fss" },
    .{ .name = "pir", .deps = &.{"fss"} },
    .{ .name = "bfv", .deps = &.{"entropy"} },
    .{ .name = "groth16", .deps = &.{"bn254"} },
    // Not heavy: the parameter derivation + all 30 tests run in 5s under
    // -Dstrict-debug, well under the >15s threshold (and a Debug compile of
    // this module is ~1s against ~27s at ReleaseSafe, so marking it heavy
    // would cost more than it saves).
    .{ .name = "poseidon", .deps = &.{ "bn254", "bls12_381" }, .test_deps = &.{"testkit"} },
    // Not heavy, despite the inverse S-box (72 multiplies per element per
    // half-round). Measured serially on this host: strict-Debug compile ~8.5s
    // + run ~1.0s = 9.5s, under the >15s threshold — and a ReleaseSafe compile
    // of this module is ~46s (comptime SHAKE256 derivation + heavily unrolled
    // field code), so marking it heavy would cost 5x what it saves.
    .{ .name = "rescue" },
    .{ .name = "tfhe", .deps = &.{"entropy"}, .heavy = true },
    .{ .name = "montint", .heavy = true },
    .{ .name = "chachapoly" },
    .{ .name = "k256" },
    .{ .name = "p256" },
    .{ .name = "ripemd160" },
    .{ .name = "bech32", .deps = &.{"ripemd160"} },
    .{ .name = "bip32", .deps = &.{ "k256", "ripemd160", "bech32" } },
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
        if (optimize == .Debug and !strict_debug) .ReleaseSafe else optimize;

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

    // Pass 1: create each module so inter-module deps can be wired in pass 2.
    var mods = std.StringHashMap(*std.Build.Module).init(b.allocator);
    for (module_list) |m| {
        const mod = b.addModule(m.name, .{
            .root_source_file = b.path(b.fmt("modules/{s}/src/root.zig", .{m.name})),
            .target = target,
            .optimize = if (m.heavy) heavy_optimize else optimize,
        });
        mods.put(m.name, mod) catch @panic("OOM");
    }

    // Pass 2: wire deps + register a test build per module.
    for (module_list) |m| {
        const mod = mods.get(m.name).?;
        for (m.deps) |dep| mod.addImport(dep, mods.get(dep).?);

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
            for (m.deps) |dep| t.addImport(dep, mods.get(dep).?);
            for (m.test_deps) |dep| t.addImport(dep, mods.get(dep).?);
            break :blk t;
        };

        const unit_tests = b.addTest(.{ .root_module = test_root, .filters = test_filters });
        const run = b.addRunArtifact(unit_tests);
        test_step.dependOn(&run.step);

        // Per-module test step: `zig build test-<name>`.
        const one = b.step(b.fmt("test-{s}", .{m.name}), b.fmt("Test the {s} module", .{m.name}));
        one.dependOn(&run.step);
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
            \\        const f = @field(T, d.name);
            \\        _ = &f;
            \\        if (depth > 0 and @TypeOf(f) == type) refAll(f, depth - 1);
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
            .optimize = .Debug,
        });
        // Exactly what a consumer gets: the published module and nothing else.
        probe.addImport(m.name, mods.get(m.name).?);
        const obj = b.addObject(.{ .name = b.fmt("testonly-{s}", .{m.name}), .root_module = probe });
        testonly.dependOn(&obj.step);
    }
    test_step.dependOn(testonly);

    // Machine-readable module graph: `zig build module-graph`.
    // One TSV line per module — `name<TAB>heavy<TAB>dep,dep,...` (deps empty
    // when there are none). `scripts/test.sh` reads this to work out which
    // modules a change affects, so build.zig stays the single source of truth
    // for the graph and nothing has to parse Zig source.
    const graph = b.step("module-graph", "Print the module dependency graph as TSV (name, heavy, deps)");
    const graph_inner = b.allocator.create(std.Build.Step) catch @panic("OOM");
    graph_inner.* = std.Build.Step.init(.{
        .id = .custom,
        .name = "module-graph",
        .owner = b,
        .makeFn = printModuleGraph,
    });
    graph.dependOn(graph_inner);

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
    const check = b.step("check-catalog", "Verify module_list matches modules/ and the README catalog");
    const check_inner = b.allocator.create(std.Build.Step) catch @panic("OOM");
    check_inner.* = std.Build.Step.init(.{
        .id = .custom,
        .name = "check-catalog",
        .owner = b,
        .makeFn = checkCatalog,
    });
    check.dependOn(check_inner);

    // Changelog-index gate: `zig build check-changelog`. The root CHANGELOG.md
    // is, by its own first line, an INDEX -- one pointer line per module that
    // has a `modules/<m>/CHANGELOG.md`. Nothing checked that it was one, and it
    // had drifted by 16 of 55 entries before this existed. A SEPARATE step
    // rather than a section of `check-catalog` for one reason: `check-catalog`
    // is driven by `module_list` and reads README/NOTICE, and the change signal
    // that should run THIS one is editing a CHANGELOG -- which `scripts/test.sh`
    // classified as a root doc "with no module impact" and used to run nothing
    // at all for. Its own step is what let that trigger be wired (see
    // `trigger_changelog` there) without widening `check-catalog`'s.
    const check_changelog = b.step("check-changelog", "Verify the root CHANGELOG index matches the per-module changelogs");
    const check_changelog_inner = b.allocator.create(std.Build.Step) catch @panic("OOM");
    check_changelog_inner.* = std.Build.Step.init(.{
        .id = .custom,
        .name = "check-changelog",
        .owner = b,
        .makeFn = checkChangelog,
    });
    check_changelog.dependOn(check_changelog_inner);

    // Fuzz-coverage gate: `zig build check-fuzz`. Deliberately a SEPARATE step
    // from `check-catalog` rather than a section of it -- see `checkFuzz` for
    // why, and for the one-line change that folds it in once the tree is green.
    const check_fuzz = b.step("check-fuzz", "Verify every module with an untrusted byte surface has a fuzz harness");
    const check_fuzz_inner = b.allocator.create(std.Build.Step) catch @panic("OOM");
    check_fuzz_inner.* = std.Build.Step.init(.{
        .id = .custom,
        .name = "check-fuzz",
        .owner = b,
        .makeFn = checkFuzz,
    });
    check_fuzz.dependOn(check_fuzz_inner);

    // Kernel-UAPI constant-drift gate: `zig build check-uapi` (campaign
    // C-09, wave-2 audit K3). `conntrack`/`devlink`/`ethtool`/`nl80211` each
    // transcribe hundreds of kernel netlink constants by hand; the audit
    // diffed every one of them against this host's `/usr/include/linux`
    // headers ONCE and proved with a fault injection that nothing else in
    // the repo would notice a wrong value (a mutated constant compiled and
    // `zig build test-<module>` stayed green, because each module's own
    // goldens read the same mutated symbol on both the encode and the
    // decode side). `scripts/check-uapi-consts.py` is the standing version
    // of that diff. It is a SEPARATE step, not folded into `check-catalog`
    // or `test`, because unlike those it depends on host state this build
    // does not control: a machine without `python3` or without the kernel
    // headers installed can still build and test every module normally, so
    // this step SKIPS (does not fail the build) whenever either is missing
    // -- see `checkUapi` below and the script's own header-missing handling.
    // Run it explicitly (or from whatever wires `scripts/check-citations.py`
    // into CI, which has the same host-dependency shape).
    const check_uapi = b.step("check-uapi", "Diff conntrack/devlink/ethtool/nl80211 constants against installed kernel headers");
    const check_uapi_inner = b.allocator.create(std.Build.Step) catch @panic("OOM");
    check_uapi_inner.* = std.Build.Step.init(.{
        .id = .custom,
        .name = "check-uapi",
        .owner = b,
        .makeFn = checkUapi,
    });
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
    const check_dark_inner = b.allocator.create(DarkTestsStep) catch @panic("OOM");
    check_dark_inner.* = .{
        .step = std.Build.Step.init(.{
            .id = .custom,
            .name = "check-dark-tests",
            .owner = b,
            .makeFn = DarkTestsStep.make,
        }),
        .modules = dark_modules,
    };
    check_dark.dependOn(&check_dark_inner.step);

    // ── Constant-time (ctgrind) harnesses ───────────────────────────────
    //
    // `zig build ctgrind` builds every `modules/<m>/src/ctgrind_harness.zig`
    // into `<prefix>/ctgrind/ctgrind-<m>`; `scripts/ctgrind.sh` drives them
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

    const ctgrind = b.step("ctgrind", "Build the constant-time harnesses into <prefix>/ctgrind/ (run them with scripts/ctgrind.sh)");
    const check_ctgrind = b.step("check-ctgrind", "Compile every ctgrind harness — rot guard, runs no valgrind");
    for (ctgrind_harnesses) |name| {
        const src = b.path(b.fmt("modules/{s}/src/ctgrind_harness.zig", .{name}));
        const deps = blk: {
            for (module_list) |m| {
                if (std.mem.eql(u8, m.name, name)) break :blk m.deps;
            }
            @panic("ctgrind_harnesses names a module that is not in module_list");
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
                // Symbol names are how `scripts/ctgrind.sh` attributes a
                // memcheck context to a file; a stripped binary reports
                // `???` and the whole table becomes unreadable.
                .strip = false,
            });
            for (deps) |dep| hmod.addImport(dep, mods.get(dep).?);
            const exe = b.addExecutable(.{ .name = b.fmt("ctgrind-{s}", .{name}), .root_module = hmod });
            const inst = b.addInstallArtifact(exe, .{
                .dest_dir = .{ .override = .{ .custom = "ctgrind" } },
            });
            ctgrind.dependOn(&inst.step);
        }

        // The rot guard compiles at Debug (fastest) with `-fvalgrind` forced
        // on, so the guard builds the same configuration the real run uses --
        // a harness that compiles only with the switch off would otherwise
        // pass the guard and fail the moment anyone ran it.
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
            .optimize = .Debug,
            .valgrind = true,
        });
        for (deps) |dep| cmod.addImport(dep, mods.get(dep).?);
        const cexe = b.addExecutable(.{ .name = b.fmt("check-ctgrind-{s}", .{name}), .root_module = cmod });
        check_ctgrind.dependOn(&cexe.step);
    }
    test_step.dependOn(check_ctgrind);
}

/// Modules carrying a `src/ctgrind_harness.zig` — a standalone program that
/// taints a secret with valgrind's `MAKE_MEM_UNDEFINED` client request and
/// drives it through the code whose constant-time property that module's
/// SPEC.md claims. Adding a row here is what puts the new harness into
/// `zig build ctgrind` and into the `check-ctgrind` rot guard.
const ctgrind_harnesses = [_][]const u8{
    "chachapoly",
    "ct25519",
    "decaf448",
    "ecvrf",
    "ed448",
    "k256",
    "montint",
};

/// `zig build module-graph` — dump module_list as TSV so tooling does not have
/// to parse Zig source. One line per module:
///
///     name<TAB>heavy|light<TAB>dep,dep,...
///
/// The deps column is empty for a module with no siblings. Consumed by
/// `scripts/test.sh` to map changed files onto the modules they affect,
/// including reverse dependencies.
fn printModuleGraph(step: *std.Build.Step, options: std.Build.Step.MakeOptions) anyerror!void {
    _ = options;
    const b = step.owner;

    var out: std.Io.Writer.Allocating = .init(b.allocator);
    defer out.deinit();
    const w = &out.writer;

    for (module_list) |m| {
        try w.print("{s}\t{s}\t", .{ m.name, if (m.heavy) "heavy" else "light" });
        // deps + test_deps: this graph answers "what must be re-tested when X
        // changes", and a test-only import is a real answer to that question
        // even though it is not part of the published module.
        var n: usize = 0;
        for (m.deps) |dep| {
            if (n != 0) try w.writeAll(",");
            try w.writeAll(dep);
            n += 1;
        }
        for (m.test_deps) |dep| {
            if (n != 0) try w.writeAll(",");
            try w.writeAll(dep);
            n += 1;
        }
        try w.writeAll("\n");
    }

    // Straight to stdout: this step's whole purpose is its output, and the
    // build runner reserves stderr for genuine problems (see the skip-print
    // rule in the module test helpers).
    var buf: [4096]u8 = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(b.graph.io, &buf);
    try stdout.interface.writeAll(out.written());
    try stdout.interface.flush();
}

fn checkCatalog(step: *std.Build.Step, options: std.Build.Step.MakeOptions) anyerror!void {
    _ = options;
    const b = step.owner;
    const io = b.graph.io;
    const readme = try b.build_root.handle.readFileAlloc(io, "README.md", b.allocator, .limited(4 * 1024 * 1024));

    var failed = false;
    for (module_list) |m| {
        const root_path = b.fmt("modules/{s}/src/root.zig", .{m.name});
        var root_ok = true;
        b.build_root.handle.access(io, root_path, .{}) catch {
            std.log.err("module_list entry '{s}' has no modules/{s}/src/root.zig", .{ m.name, m.name });
            failed = true;
            root_ok = false;
        };

        if (std.mem.indexOf(u8, readme, b.fmt("| `{s}` |", .{m.name})) == null) {
            std.log.err("module '{s}' has no README catalog row (`| \\`{s}\\` |`)", .{ m.name, m.name });
            failed = true;
        } else if (readmeDepsCell(readme, m.name, b)) |readme_deps| {
            checkDepsMatch(m.name, "README catalog row's Deps column", m.deps, readme_deps, b, &failed);
        }

        // meta.deps cross-check: only readable once we know root.zig exists.
        if (root_ok) {
            const root_src = try b.build_root.handle.readFileAlloc(io, root_path, b.allocator, .limited(2 * 1024 * 1024));
            if (metaDepsFromRoot(root_src, b)) |meta_deps| {
                checkDepsMatch(m.name, "root.zig's meta.deps", m.deps, meta_deps, b, &failed);
            } else if (m.deps.len > 0) {
                // Two modules (brotli, aeskw) currently have no `meta` block
                // at all; both are zero-dep in module_list, so they never
                // reach here. Any module_list entry that DOES declare deps
                // must have somewhere to document them.
                std.log.err(
                    "module '{s}' declares deps ({s}) in build.zig but modules/{s}/src/root.zig has no `meta.deps` field to document them",
                    .{ m.name, std.mem.join(b.allocator, ", ", m.deps) catch @panic("OOM"), m.name },
                );
                failed = true;
            }
        }
    }

    var dir = try b.build_root.handle.openDir(io, "modules", .{ .iterate = true });
    defer dir.close(io);
    var it = dir.iterate();
    while (try it.next(io)) |e| {
        if (e.kind != .directory or std.mem.eql(u8, e.name, "_template")) continue;
        const known = for (module_list) |m| {
            if (std.mem.eql(u8, m.name, e.name)) break true;
        } else false;
        if (!known) {
            std.log.err("modules/{s}/ exists but is not in build.zig's module_list", .{e.name});
            failed = true;
        }
    }

    if (std.mem.indexOf(u8, readme, b.fmt("{d} modules", .{module_list.len})) == null) {
        std.log.err("README status line does not say \"{d} modules\"", .{module_list.len});
        failed = true;
    }

    checkNonGoals(readme, b, &failed);
    try checkProvenance(b, io, &failed);
    try checkAnchors(b, io, &failed);

    if (failed) return step.fail("catalog drift — see errors above", .{});
}

/// `zig build check-changelog` — the root CHANGELOG.md is an index, and this
/// makes it one.
///
/// CONVENTIONS §8 splits the changelog: detail lives in
/// `modules/<m>/CHANGELOG.md`, and the root file carries one pointer line per
/// module that has one, so a consumer of three modules reads three files. That
/// split moved the root file from 678 lines to 113 -- and then nothing checked
/// it. By the time this was written 16 of 55 module changelogs (`acme`, `bbs`,
/// `bls12_381`, `cookies`, `cors`, `ed448`, `entropy`, `ibe`, `ratelimit`,
/// `router`, `sessions`, `signal`, `throttle`, `timelock_envelope`, `tlock`,
/// `wireguard`) had no index line at all, which is the failure mode an index
/// has: it is silently incomplete, and a consumer who reads it concludes their
/// module did not change.
///
/// Five claims:
///
///  0. Every entry in a `modules/<m>/CHANGELOG.md` carries its landing date.
///     See `checkEntryDates` for the format and its calibration.
///  1. Every module in `module_list` HAS a `modules/<m>/CHANGELOG.md`, and it is
///     linked from the root index. Driven from `module_list`; a `modules/<x>/`
///     that is not in `module_list` is `check-catalog`'s error, not this one,
///     and `modules/_template/` -- which is not in `module_list` -- is outside
///     the requirement by construction.
///  1b. That file is a CHANGELOG and not merely a file at that path. See
///     `checkChangelogShape` for the two landmarks and their calibration.
///  2. Every `modules/<m>/CHANGELOG.md` link IN the root index resolves to a
///     file that exists. Driven from the root file's text, so -- unlike (1) --
///     it can see an entry that corresponds to nothing. Both directions are
///     needed for the same reason `checkProvenance`'s claim 4 is: a check
///     driven only from `module_list` is structurally blind to a stale row.
///  3. The `BREAKING` tag agrees between the two files.
///
/// WHY (1) DEMANDS THE FILE, NOT JUST ITS INDEX LINE. The first version of this
/// loop read each module changelog with `catch continue`, so a module with NO
/// `CHANGELOG.md` was skipped entirely and every claim below it was skipped with
/// it. That is fail-open in exactly the shape a new module arrives in. Measured
/// on the real tree, not reasoned about: deleting `modules/tlock/CHANGELOG.md`
/// ALONE is caught -- by (2), as a dangling index link, EXIT=1 -- but deleting
/// the file AND its one root-index bullet, which is the state of a module added
/// today, gave EXIT=0. So the root index's own promise ("Every module now
/// carries a `CHANGELOG.md`, not only the ones with a code change to record")
/// held over 225 of 225 modules as a fact about that morning and not as an
/// invariant, and the one case where a gate is worth having -- a module being
/// added -- was the one case it did not cover. A read failure that is not
/// `FileNotFound` fails too: the gate cannot verify what it cannot read, and
/// "skip whatever you could not read" is the exact reflex that produced the
/// hole in the first place. That fix left the same reflex one layer in, which
/// is what (1b) closes: measured on the real tree, truncating
/// `modules/tlock/CHANGELOG.md` to ZERO BYTES gave EXIT=0, because a file that
/// exists satisfies (1), an empty file has no entries for (0) to date, no
/// `## Unreleased` for (3) to compare -- `orelse continue` -- and the index
/// link still resolves for (2). The gate enforced "a file exists", so a module
/// could hold a zero-byte placeholder and read as fully documented.
///
/// WHY (3) IS IN, GIVEN THAT IT PARSES PROSE. The index's own text promises
/// exactly this invariant ("a `BREAKING` tag means the module's own changelog
/// flags at least one breaking change in its `Unreleased` section"), and it is
/// the one field of an index line a consumer acts on -- an index that says
/// nothing broke while the module says something did is worse than a missing
/// line. The risk is a gate that cries wolf, so the rule was calibrated against
/// the whole corpus before being adopted, not after:
///
///   - The obvious rule -- "the word BREAKING appears" -- is WRONG on the real
///     tree. `montint`'s entry reads "Classified as **neither BREAKING nor
///     BEHAVIOURAL**", a deliberate negation, and the naive rule demands the
///     index tag a constant-time fix as breaking. One false failure out of 39
///     entries on day one, in the direction that makes people delete gates.
///   - The rule used instead is the literal `**BREAKING` -- the tag is a bold
///     span that STARTS with the word. Every one of the 22 occurrences across
///     the module changelogs is of that shape (`**BREAKING:**`, `**BREAKING**`,
///     `**BREAKING (wire):**`, `**BREAKING (API):**`, `**BREAKING
///     (behavioral):**`, `**BREAKING — `), and `montint`'s negation is not,
///     because its bold span starts with "neither". Measured against all 39
///     pre-existing index lines: 11 tagged, 11 expected, 0 disagreements.
///   - It fails OPEN on a spelling nobody uses (`**Breaking:**` would read as
///     "not breaking" and pass). That is the right direction for a gate whose
///     alternative is being switched off.
///
/// `BEHAVIOURAL, not breaking` -- which `cors`, `ratelimit`, `router` and
/// `throttle` carry -- is a DIFFERENT classification and deliberately does not
/// trip this. It contains no `**BREAKING`, so the rule already separates them;
/// the index states the distinction in prose so nobody re-conflates them.
///
/// WHAT IS DELIBERATELY NOT CHECKED: the module count in the index prose
/// ("the collection grew 77 → 225 modules"). `check-catalog` already pins a
/// module count against `module_list.len`, in the README, which is the one
/// place that fact is owned; a second gate on the same fact in a different
/// file is a second thing to get wrong. Worse, this sentence is release NOTES,
/// not a live count -- once a tag is cut it freezes with the rest of the
/// section, and a check keyed to `module_list.len` would then demand editing
/// released history to keep itself green. That is the shape of a gate people
/// disable.
///
/// SCOPE OF (3), stated so a green run is not over-read: it compares the
/// `## Unreleased` section of each file. After a tag is cut both sections are
/// empty and (3) checks nothing, while (1) and (2) keep working off the whole
/// file. A module that gains a NEW `Unreleased` entry after a tag is caught,
/// because (3) requires an `Unreleased` index bullet whenever the module's
/// `Unreleased` has one -- but a module whose `Unreleased` is empty is not
/// asked about at all.
fn checkChangelog(step: *std.Build.Step, options: std.Build.Step.MakeOptions) anyerror!void {
    _ = options;
    const b = step.owner;
    const io = b.graph.io;
    const root = try b.build_root.handle.readFileAlloc(io, "CHANGELOG.md", b.allocator, .limited(4 * 1024 * 1024));

    var failed = false;

    const root_unreleased = unreleasedSection(root) orelse blk: {
        std.log.err("CHANGELOG.md has no `## Unreleased` section for the changelog gate to check", .{});
        failed = true;
        break :blk "";
    };

    // (1) + (3): every module HAS a changelog, it is indexed, and the tag agrees.
    for (module_list) |m| {
        const path = b.fmt("modules/{s}/CHANGELOG.md", .{m.name});
        const text = b.build_root.handle.readFileAlloc(io, path, b.allocator, .limited(4 * 1024 * 1024)) catch |err| {
            std.log.err(
                "module '{s}' has no readable {s} ({s}) — every module in `module_list` carries " ++
                    "one (CONVENTIONS.md §8), including a module whose only history is being " ++
                    "created. Copy `modules/_template/CHANGELOG.md` to {s}, fill in its heading " ++
                    "and its dated `New module:` entry, then add the one-line pointer " ++
                    "`- [`{s}`]({s})` to the root CHANGELOG.md under \"### Modules with a " ++
                    "changelog\" — the file alone is not enough, the index is what a consumer " ++
                    "reads. (`modules/_template/` is not in `module_list` and is not asked for " ++
                    "one.)",
                .{ m.name, path, @errorName(err), path, m.name, path },
            );
            failed = true;
            continue;
        };

        // (1b) runs first: the checks below read structure out of this file, so
        // "is it a changelog at all" is the question that has to be answered
        // before any of them mean anything.
        checkChangelogShape(m.name, path, text, &failed);

        // (0) runs before the index checks, and outside their `continue`s: an
        // entry with no date is wrong whether or not the index links the file.
        checkEntryDates(m.name, path, text, &failed);

        if (std.mem.indexOf(u8, root, b.fmt("]({s})", .{path})) == null) {
            std.log.err(
                "module '{s}' has a {s} that the root CHANGELOG.md never links — add a one-line " ++
                    "pointer `- [`{s}`]({s})` under \"### Modules with a changelog\". The root file " ++
                    "is an index (CONVENTIONS.md §8); a module missing from it reads to a consumer " ++
                    "as a module that did not change.",
                .{ m.name, path, m.name, path },
            );
            failed = true;
            continue;
        }

        // Absent only in a file (1b) has already failed the build over, so this
        // `continue` no longer skips a module silently.
        const mod_unreleased = unreleasedSection(text) orelse continue;
        // "Has an entry" = has a bullet. A section with only a heading is a
        // module whose history is all under dated tags, and (3) does not ask
        // about it.
        if (std.mem.indexOf(u8, mod_unreleased, "\n- ") == null) continue;

        const bullet_head = b.fmt("- [`{s}`]({s})", .{ m.name, path });
        const bullet = indexBullet(root_unreleased, bullet_head) orelse {
            std.log.err(
                "module '{s}' has an `## Unreleased` entry in {s} but the root CHANGELOG.md's own " ++
                    "`## Unreleased` index has no `{s}` line for it",
                .{ m.name, path, bullet_head },
            );
            failed = true;
            continue;
        };

        // See the rule's calibration in this function's doc comment: the tag is
        // a bold span STARTING with the word, which is what keeps `montint`'s
        // "**neither BREAKING nor BEHAVIOURAL**" from being read as a tag.
        const mod_breaking = std.mem.indexOf(u8, mod_unreleased, "**BREAKING") != null;
        const idx_breaking = std.mem.indexOf(u8, bullet, "**BREAKING") != null;
        if (mod_breaking and !idx_breaking) {
            std.log.err(
                "module '{s}' flags **BREAKING in its `Unreleased` section but its root CHANGELOG.md " ++
                    "index line does not — the index promises the tag means exactly this. (If the " ++
                    "module's entry is `BEHAVIOURAL, not breaking`, it does not carry the tag and " ++
                    "this would not fire.)",
                .{m.name},
            );
            failed = true;
        } else if (idx_breaking and !mod_breaking) {
            std.log.err(
                "module '{s}' is tagged **BREAKING** in the root CHANGELOG.md index but its own " ++
                    "`{s}` `Unreleased` section flags no breaking change",
                .{ m.name, path },
            );
            failed = true;
        }
    }

    // (2): every index link resolves. Driven from the root file's text, which
    // is the only direction that can see an entry pointing at nothing.
    const tail = "/CHANGELOG.md)";
    const head = "](modules/";
    var i: usize = 0;
    while (std.mem.indexOfPos(u8, root, i, tail)) |end| {
        i = end + tail.len;
        const before = root[0..end];
        const p = std.mem.lastIndexOf(u8, before, head) orelse continue;
        const name = before[p + head.len ..];
        // A clean module name only. Anything else means this `/CHANGELOG.md)`
        // did not belong to the `](modules/…` we walked back to.
        if (name.len == 0 or std.mem.indexOfAny(u8, name, "/()`[] \t\n") != null) continue;
        if (!fileExists(b, io, b.fmt("modules/{s}/CHANGELOG.md", .{name}))) {
            std.log.err(
                "root CHANGELOG.md indexes `modules/{s}/CHANGELOG.md`, which does not exist",
                .{name},
            );
            failed = true;
        }
    }

    if (failed) return step.fail("changelog index drift — see errors above", .{});
}

/// Claim (1b): the file at `modules/<m>/CHANGELOG.md` is a changelog, not just
/// a file at that path.
///
/// THE HOLE THIS CLOSES, measured and not reasoned about: with (1) demanding
/// the file, truncating `modules/tlock/CHANGELOG.md` to zero bytes still gave
/// `zig build check-changelog` EXIT=0. Every other claim is written to read
/// structure OUT of this file, so an empty one answers all of them vacuously —
/// no entries to date, no `## Unreleased` to compare against the index, and the
/// index link resolves because the file is there. "Exists" and "is a changelog"
/// are different facts and only the first was checked.
///
/// THE RULE: two landmarks, both required.
///
///   1. The first line is a level-1 markdown title (`# `) that NAMES the module.
///   2. The file has an `## Unreleased` section heading.
///
/// CALIBRATED AGAINST THE WHOLE CORPUS BEFORE ADOPTION, which is the lesson the
/// `**BREAKING` rule in `checkChangelog` is written from. All 225 files in
/// `module_list` were checked, not sampled: 225/225 open with exactly
/// `# <name> — changelog`, 225/225 carry `## Unreleased`, and 225/225 have
/// exactly one `## ` heading (no tag has been cut in a module changelog yet).
/// Zero of the 225 have to change to pass.
///
/// WHY NOT PIN THE EXACT TITLE, given that 225/225 match `# <name> — changelog`
/// byte for byte. Because `modules/_template/CHANGELOG.md` — the file the error
/// messages tell you to copy — writes it as ``# `<name>` — changelog``, with
/// backticks. A rule that fails the tree's own skeleton the moment its
/// placeholder is filled in is a rule that gets deleted, so the requirement is
/// the weaker "a `# ` title mentioning the module": it passes the 225, passes a
/// filled-in template either way, and still catches a template copied WITHOUT
/// renaming, because `<name>` does not contain the module's name.
///
/// WHY `## Unreleased` IS DEMANDED BUT AN ENTRY UNDER IT IS NOT. The heading is
/// the file's contract with the root index — (3) compares that section, and
/// with no heading at all `unreleasedSection` returns null and the module falls
/// out of the loop through `orelse continue`, which is the fail-open path
/// itself. A BULLET is deliberately not required even though 225/225 have one
/// today: the moment a tag is cut those bullets move into the release section
/// and the heading legitimately stands empty, and a gate that then demanded an
/// entry would be asking modules to invent one. That is the same distinction
/// `checkChangelog` already draws at "a section with only a heading".
///
/// WHAT IS DELIBERATELY NOT CHECKED: the preamble line pointing back at the
/// root index (225/225 carry it, but it is prose that says nothing a reader
/// cannot get from the link they followed), and any minimum length — a byte
/// count is a proxy for the two facts above, and a worse one.
fn checkChangelogShape(name: []const u8, path: []const u8, text: []const u8, failed: *bool) void {
    const nl = std.mem.indexOfScalar(u8, text, '\n') orelse text.len;
    const title = text[0..nl];
    if (!std.mem.startsWith(u8, title, "# ") or std.mem.indexOf(u8, title, name) == null) {
        std.log.err(
            "{s}:1: this is not a changelog — its first line must be a `# ` title naming the " ++
                "module, as in `# {s} — changelog`, and it reads `{s}`. An empty or " ++
                "placeholder file passes `every module has a CHANGELOG.md` while telling a " ++
                "consumer nothing; copy `modules/_template/CHANGELOG.md` and fill it in. " ++
                "Module '{s}'; see CONVENTIONS.md §8.",
            .{ path, name, title[0..@min(title.len, 48)], name },
        );
        failed.* = true;
    }
    if (unreleasedSection(text) == null) {
        std.log.err(
            "{s}: no `## Unreleased` heading — every module changelog has one, and it is the " ++
                "section the root CHANGELOG.md index is checked against. Without it the module " ++
                "silently drops out of that comparison. Add the heading (it may stand empty " ++
                "once a tag is cut; what is not allowed is its absence). Module '{s}'; see " ++
                "CONVENTIONS.md §8.",
            .{ path, name },
        );
        failed.* = true;
    }
}

/// Claim (0): every entry in a module changelog says WHEN it landed.
///
/// THE PROBLEM. Entries sat under `## Unreleased` with no date at all, so
/// "what changed when" was unanswerable from the file — a reader had to run
/// `git log` against a repository they may not have. The tag a change ships in
/// (CONVENTIONS §8) answers it only AFTER a tag is cut, and the whole point is
/// to be able to answer it before.
///
/// THE FORMAT: `- **YYYY-MM-DD** — <entry>`, on the top-level bullet only.
/// Continuation paragraphs and nested bullets belong to the entry above and
/// carry nothing. The date is `20YY-MM-DD`, the same shape `scripts/tag.sh`
/// accepts for a tag name, so the repo has ONE date format rather than two.
///
/// The date is WHEN THE CHANGE LANDED ON MAIN, not when the entry was typed.
/// The two differ here by up to three weeks: 37eabe5 backfilled ~40 of these
/// entries in one commit, describing work that landed as early as 2026-07-18,
/// and dating them to the backfill would have made the whole retrofit useless
/// in exactly the direction that matters. Going forward an entry is written
/// with its change and the two coincide.
///
/// WHY A PREFIX AND NOT A SUBSECTION. `### 2026-07-29` headings grouping
/// entries by date were rejected on what happens when a tag is cut: entries
/// move into a `## 2026-08-14` release section, and a date heading nested in a
/// date heading forces the reader to tell "released on" from "landed on" by
/// heading level alone. A prefix has no such collision — the section says when
/// it shipped, the bullet says when it landed, and both stay true and
/// non-redundant (the current Unreleased spans 2026-07-18 to 2026-08-13, so
/// one release date cannot stand in for 88 landing dates). A subsection is
/// also a structural edit where a prefix is a line edit, and 38 of the 55
/// files have exactly one entry, which would each get a heading of their own.
///
/// WHY NOT A TRAILING `(2026-08-13, 61f2f9a)`. These entries are not
/// one-liners — `dtls`'s run past 30 lines each — so a trailing date lands at
/// the bottom of a wall of prose, which is where a reader scanning a file will
/// not find it. A prefix puts every date in one column down the left margin.
/// It is also ambiguous which paragraph of a multi-paragraph entry "trailing"
/// means, and prose ambiguity is what makes a gate cry wolf.
///
/// WHY NO COMMIT HASH, which was the closer call. A hash is exact and a date
/// is not (five entries here landed on 2026-07-29). It still loses on three
/// counts. It ROTS: §8 itself prescribes `git filter-repo` for a spin-off,
/// which rewrites every hash of the extracted module, and this history is not
/// yet published. It is for the WRONG READER: a module CHANGELOG is
/// consumer-facing (§5), and a consumer with no clone cannot resolve a hash,
/// while a reader with one can find the commit from the entry's own wording
/// via `git log -S` — which is exactly how these 88 dates were recovered. And
/// it would need a SECOND OWNER: nothing can keep a hand-copied hash agreeing
/// with the entry beside it, and a gate that verified it would have to shell
/// out to git — dying in a shallow clone or in the per-module tarball §8
/// contemplates shipping. Where a hash is genuinely the right tool it goes in
/// the commit message and in SPEC.md, both of which already carry them, and
/// where rot costs nothing.
///
/// SCOPE: EVERY `## ` section, not only `## Unreleased`. Restricting it to
/// Unreleased would build in a rule that stops applying the moment a tag is
/// cut — 88 entries would move into a released section and silently leave the
/// gate's sight, which is a gate switching itself off. Dating an entry is a
/// fact about the past, so a frozen release section never needs editing to
/// stay green; that is what separates this from the module-count sentence the
/// function above deliberately does not check.
///
/// WHAT IS DELIBERATELY NOT CHECKED:
///
///   - The ROOT index carries no dates. The date is owned by the module
///     changelog, and restating it on the index line would be a second place
///     to get it wrong for no reader who is not one click away from the first.
///   - That an entry's date is <= the date of the release section holding it.
///     True by construction, but no released module section exists yet, so the
///     rule would ship with zero instances behind it — an untested branch that
///     first runs on the day someone cuts a tag.
///   - There is no "cannot attribute" escape hatch, because the retrofit
///     needed none: all 88 entries resolved to a commit. An accepted sentinel
///     with zero real uses is an untested branch and a standing invitation.
///     An entry whose landing genuinely cannot be pinned takes the date of the
///     commit that records it, which always exists.
///
/// CALIBRATION, run before the rule was adopted rather than after (the lesson
/// the `**BREAKING` rule above is written from): dry-run against all 55
/// existing files after the retrofit — 88 entries, 88 accepted, 0
/// disagreements. Both failure directions were then proven by planting them: a
/// stripped date and a `2026-8-13` / `13-08-2026` malformation each turn this
/// red, naming the file and line.
fn checkEntryDates(name: []const u8, path: []const u8, text: []const u8, failed: *bool) void {
    // The body starts at the first `## ` heading; the preamble above it is the
    // file's title and the pointer back to the root index, not entries.
    var body_start: usize = 0;
    if (!std.mem.startsWith(u8, text, "## ")) {
        body_start = (std.mem.indexOf(u8, text, "\n## ") orelse return) + 1;
    }

    var line_no = std.mem.count(u8, text[0..body_start], "\n") + 1;
    var it = std.mem.splitScalar(u8, text[body_start..], '\n');
    while (it.next()) |line| : (line_no += 1) {
        // A top-level bullet, i.e. an entry. An indented `- ` is a sub-point of
        // the entry above it and a blank or indented line is its continuation;
        // none of those carry a date of their own.
        if (!std.mem.startsWith(u8, line, "- ")) continue;
        const rest = line[2..];
        if (entryDate(rest) != null) continue;

        failed.* = true;
        if (!std.mem.startsWith(u8, rest, "**")) {
            std.log.err(
                "{s}:{d}: changelog entry has no date — write it as " ++
                    "`- **YYYY-MM-DD** — {s}…`, where the date is the day the change " ++
                    "landed on main (find it with `git log -S` on a distinctive phrase " ++
                    "of the entry, not by guessing). Module '{s}'; see CONVENTIONS.md §8.",
                .{ path, line_no, rest[0..@min(rest.len, 32)], name },
            );
        } else {
            std.log.err(
                "{s}:{d}: changelog entry opens with a bold span that is not a date — " ++
                    "`{s}…`. The form is exactly `- **YYYY-MM-DD** — `, zero-padded, " ++
                    "year first, em dash after (the same shape scripts/tag.sh accepts " ++
                    "for a tag). A bold tag such as `**BREAKING:**` goes AFTER the date, " ++
                    "not instead of it. Module '{s}'; see CONVENTIONS.md §8.",
                .{ path, line_no, rest[0..@min(rest.len, 32)], name },
            );
        }
    }
}

/// The `**YYYY-MM-DD** — ` opening of an entry, or null if it is absent or
/// malformed. The date shape mirrors `scripts/tag.sh`'s own
/// `^20[0-9]{2}-[0-9]{2}-[0-9]{2}$` so a tag name and an entry date are the
/// same kind of string.
fn entryDate(rest: []const u8) ?[]const u8 {
    const close = "** — ";
    if (!std.mem.startsWith(u8, rest, "**")) return null;
    const after = rest[2..];
    if (after.len < 10 + close.len) return null;
    if (!std.mem.startsWith(u8, after[10..], close)) return null;

    const d = after[0..10];
    if (!std.mem.startsWith(u8, d, "20")) return null;
    if (d[4] != '-' or d[7] != '-') return null;
    for ([_]usize{ 2, 3, 5, 6, 8, 9 }) |i| {
        if (!std.ascii.isDigit(d[i])) return null;
    }
    // Range-checked, so `2026-13-45` is caught as well as `2026-1-5`. A
    // per-month day count is deliberately not modelled: this is a shape check,
    // and the date is only ever copied out of `git log`.
    const month = @as(u16, d[5] - '0') * 10 + (d[6] - '0');
    const day = @as(u16, d[8] - '0') * 10 + (d[9] - '0');
    if (month < 1 or month > 12) return null;
    if (day < 1 or day > 31) return null;
    return d;
}

/// The body of a markdown file's `## Unreleased` section: everything after the
/// heading up to the next `## `. Null if there is no such heading.
fn unreleasedSection(text: []const u8) ?[]const u8 {
    const heading = "## Unreleased";
    const start = std.mem.indexOf(u8, text, heading) orelse return null;
    const rest = text[start + heading.len ..];
    const end = std.mem.indexOf(u8, rest, "\n## ") orelse rest.len;
    return rest[0..end];
}

/// One `- […](…)` list item of the index, from `head` to the next item or the
/// next heading. Index entries are hard-wrapped over several lines, so a
/// per-line search would only ever see the first of them — and the `BREAKING`
/// tag is not always on it (`bfv`'s is, `hpke`'s continuation lines are not).
fn indexBullet(section: []const u8, head: []const u8) ?[]const u8 {
    const start = std.mem.indexOf(u8, section, head) orelse return null;
    const rest = section[start..];
    var end = rest.len;
    if (std.mem.indexOfPos(u8, rest, head.len, "\n- ")) |n| end = @min(end, n);
    if (std.mem.indexOfPos(u8, rest, head.len, "\n#")) |n| end = @min(end, n);
    return rest[0..end];
}

/// Provenance gate: every module says where it came from, and the repository
/// can still answer "what do I owe a third party?" from ONE file.
///
/// Three claims, each of which was false somewhere when this was written:
///
///  1. Every module has a `README.md` carrying a `Provenance:` line
///     (CONVENTIONS §6.1). 22 modules had no such line and 5 -- `ethfrag`,
///     `liveness-hyst`, `netsim`, `pping`, `spf-ect` -- had no README at all.
///     The old catalog check only ever read the ROOT README, so a module could
///     ship with no documentation of its own and stay green.
///
///  2. Every `modules/<m>/NOTICE` declares its kind on line 1: either
///     `<m> — third-party attribution` (carries a condition) or
///     `<m> — provenance note` (record only). Without a discriminator the two
///     are indistinguishable without reading all 42, and one of them is the
///     one that matters legally.
///
///  3. The root NOTICE §1 list of condition-bearing modules is EXACTLY the set
///     of `third-party attribution` files -- no missing entry (root §1 said
///     "one module does" while listing three, when four existed: `imap` had
///     been added a day earlier and root §1 was not) and no stale one.
///
///  4. Every `modules/<x>/NOTICE` §1 cites is a real module. Checks 1-3 are
///     driven FROM `module_list`, so they can only ever see a module whose
///     files disagree with §1 -- never a §1 row corresponding to nothing. A
///     planted `modules/ghost/NOTICE` row passed all three.
///
///  5. A module's provenance note either STATES an answer (clean-room /
///     original work / no entry needed) or has somewhere real to send the
///     reader. `fleetsim`'s entire note was "Provenance: see /NOTICE." and
///     NOTICE had never heard of it; five more cited entries that did not
///     exist. A pointer to nothing is worse than silence -- the reader cannot
///     tell "clean-room" from "somebody forgot".
///
/// Claim 3 is the load-bearing one. §1 is what lets a consumer conclude
/// "zig-libs is plain MIT" without opening every module; an unlisted
/// attribution file makes that conclusion wrong, which no test would ever
/// notice. Claim 5 found the one real license defect of the sweep:
/// `bitcoinscript` reproduces ~2000 rows of Bitcoin Core's `script_tests.json`
/// verbatim -- the same shape as `decimal`'s decTest corpus -- with no
/// attribution file at all.
///
/// Every claim was verified by planting the defect it describes and watching
/// this step go red. Two lessons are baked into the code above:
///
///   - Claim 4 exists BECAUSE its mutation was the one that stayed green: the
///     other checks are all driven FROM `module_list` and are structurally
///     blind to a §1 row that corresponds to nothing.
///   - Judge these mutations by the step's EXIT CODE. Grepping for `^error:`
///     silently passed a build that did not compile (`build.zig:657: error:`
///     does not start the line with `error:`), so two mutations "survived"
///     against a binary that was never built.
fn checkProvenance(b: *std.Build, io: std.Io, failed: *bool) !void {
    const notice = try b.build_root.handle.readFileAlloc(io, "NOTICE", b.allocator, .limited(4 * 1024 * 1024));
    const sec1 = sectionSlice(notice, "1. REQUIRED ATTRIBUTION", "2. DESIGN REFERENCES") orelse {
        std.log.err("NOTICE has no \"1. REQUIRED ATTRIBUTION\" section for the provenance gate to check", .{});
        failed.* = true;
        return;
    };

    for (module_list) |m| {
        const readme_path = b.fmt("modules/{s}/README.md", .{m.name});
        if (b.build_root.handle.readFileAlloc(io, readme_path, b.allocator, .limited(4 * 1024 * 1024))) |mod_readme| {
            // Two spellings are in use and both are fine: an inline
            // `Provenance: …` line (the short case) and a `## Provenance`
            // section (the crypto modules, whose provenance needs paragraphs).
            // What is NOT accepted is the word appearing incidentally, e.g.
            // "fixture provenance" or "see kat_vectors.zig for provenance" --
            // that names where provenance lives without stating it.
            if (std.mem.indexOf(u8, mod_readme, "Provenance:") == null and
                std.mem.indexOf(u8, mod_readme, "## Provenance") == null)
            {
                std.log.err(
                    "modules/{s}/README.md has no `Provenance:` line — say whether it is clean-room " ++
                        "from a spec, a studied design reference (root NOTICE), or ported source " ++
                        "(modules/{s}/NOTICE). See CONVENTIONS.md §5.",
                    .{ m.name, m.name },
                );
                failed.* = true;
            }
        } else |_| {
            std.log.err("module '{s}' has no modules/{s}/README.md (CONVENTIONS §6.1)", .{ m.name, m.name });
            failed.* = true;
        }

        // A provenance statement that sends the reader to NOTICE must have
        // something there to find. `fleetsim` said only "Provenance: see
        // /NOTICE." and NOTICE had never heard of it; five more named real
        // design references (Flatbush, BurntSushi/fst, Lucene, LibreQoS,
        // conntrack-tools) and pointed at entries that did not exist. A
        // pointer to nothing is worse than silence: the reader cannot tell
        // "clean-room" from "somebody forgot".
        if (b.build_root.handle.readFileAlloc(io, readme_path, b.allocator, .limited(4 * 1024 * 1024))) |mod_readme| {
            if (provenanceStatement(mod_readme)) |raw_claim| {
                // Match against a whitespace-collapsed copy. READMEs are hard
                // wrapped, so "no `NOTICE`\nentry is required" and "No\n`NOTICE`
                // entry required" both hide the disclaimer from a literal
                // search -- this check reported 27 false positives, `raft` and
                // half my own new lines among them, until it normalized first.
                const claim = collapseWhitespace(b.allocator, raw_claim);
                // The target is a statement that says NOTHING and merely
                // points -- `fleetsim`'s entire note was "Provenance: see
                // /NOTICE." and NOTICE had never heard of it. A note that
                // states its own answer ("clean-room", "no source ported",
                // "original work", "no entry needed") is fine whatever NOTICE
                // says: the reader already has the answer. So this fires only
                // when the note neither answers nor has anywhere real to send
                // you.
                // Case-insensitive: `x509` opens its section with "Clean-room"
                // and a lowercase-only needle flagged it.
                const answers = containsAnyIgnoreCase(claim, &.{
                    "clean-room",           "clean room",     "original work",   "original composition",
                    "no entry",             "none needed",    "none required",   "not required",
                    "entry required",       "entry needed",   "no root",         "source ported",
                    "source is ported",     "source read",    "source was read", "source consulted",
                    "source was consulted", "no third-party",
                });
                if (!answers and !hasNoticeEntry(notice, m.name) and !fileExists(b, io, b.fmt("modules/{s}/NOTICE", .{m.name}))) {
                    std.log.err(
                        "modules/{s}/README.md's Provenance note neither states an answer " ++
                            "(clean-room / original work / no entry needed) nor has anything to point " ++
                            "at: no `{s}` entry in NOTICE and no modules/{s}/NOTICE",
                        .{ m.name, m.name, m.name },
                    );
                    failed.* = true;
                }

                // A statement about SOURCE does not answer for committed DATA.
                // Every check above is satisfied by "clean-room from the public
                // spec, no third-party source ported" -- a sentence that can be
                // entirely true of a module that also ships someone else's test
                // corpus in `src/testdata/`. Reproduced third-party data owes
                // attribution exactly like ported code does, and the one real
                // licence defect the 2026-07-31 sweep found was that shape:
                // `bitcoinscript` carried ~2000 rows of Bitcoin Core's
                // `script_tests.json` verbatim with no attribution file, behind
                // a provenance line that talked only about the script language.
                //
                // So: if a module ships a committed file that is neither Zig
                // source nor documentation, its provenance statement must
                // ADDRESS data, or the module must carry its own NOTICE. This
                // does not decide whether the data is clean -- it only refuses
                // to let the question go unasked.
                //
                // LIMIT, stated so nobody mistakes this for more than it is: a
                // module that HAS a `modules/<m>/NOTICE` is exempt, because a
                // human wrote a provenance file for it. That file could still
                // cover only some of the module's data. This gate closes the
                // "nobody ever wrote anything" hole, not the "what was written
                // is incomplete" one -- the latter needs a reader, not a check.
                if (!fileExists(b, io, b.fmt("modules/{s}/NOTICE", .{m.name}))) {
                    if (firstDataFile(b, io, b.fmt("modules/{s}", .{m.name}), 0)) |witness| {
                        const covers_data = containsAnyIgnoreCase(claim, &.{
                            "test data", "testdata",    "test vector", "vectors",
                            "corpus",    "corpora",     "fixture",     "golden",
                            "capture",   "litmus",      "data only",   "no source code",
                            "no data",   "own tooling",
                        });
                        if (!covers_data) {
                            std.log.err(
                                "modules/{s} ships committed data ({s}) but its Provenance statement " ++
                                    "speaks only about source — say where the DATA came from (generated " ++
                                    "by our own tooling / captured from this machine / reproduced from " ++
                                    "<upstream>, in which case it needs modules/{s}/NOTICE). Reproduced " ++
                                    "third-party test data owes attribution exactly like ported code does.",
                                .{ m.name, witness, m.name },
                            );
                            failed.* = true;
                        }
                    }
                }
            }
        } else |_| {}

        // The module-local NOTICE, if there is one, must declare its kind, and
        // §1 must agree about whether it carries a condition.
        const notice_path = b.fmt("modules/{s}/NOTICE", .{m.name});
        const mod_notice = b.build_root.handle.readFileAlloc(io, notice_path, b.allocator, .limited(4 * 1024 * 1024)) catch {
            // No module-local NOTICE: §1 must not claim there is one.
            if (std.mem.indexOf(u8, sec1, notice_path) != null) {
                std.log.err(
                    "NOTICE §1 lists `{s}`, but that file does not exist",
                    .{notice_path},
                );
                failed.* = true;
            }
            continue;
        };

        const first_line = mod_notice[0 .. std.mem.indexOfScalar(u8, mod_notice, '\n') orelse mod_notice.len];
        const attribution = b.fmt("{s} — third-party attribution", .{m.name});
        const provenance = b.fmt("{s} — provenance note", .{m.name});
        const is_attribution = std.mem.eql(u8, std.mem.trim(u8, first_line, " \r"), attribution);
        const is_provenance = std.mem.eql(u8, std.mem.trim(u8, first_line, " \r"), provenance);

        if (!is_attribution and !is_provenance) {
            std.log.err(
                "{s} line 1 is \"{s}\" — it must be exactly \"{s}\" (carries a condition) or " ++
                    "\"{s}\" (record only). CONVENTIONS.md §5.",
                .{ notice_path, first_line, attribution, provenance },
            );
            failed.* = true;
            continue;
        }

        const listed = std.mem.indexOf(u8, sec1, notice_path) != null;
        if (is_attribution and !listed) {
            std.log.err(
                "{s} carries required attribution but NOTICE §1 does not list it — a consumer " ++
                    "reading §1 would wrongly conclude zig-libs owes nothing beyond MIT",
                .{notice_path},
            );
            failed.* = true;
        } else if (is_provenance and listed) {
            std.log.err(
                "NOTICE §1 lists {s}, but that file is a provenance note and carries no condition — " ++
                    "§1 must contain exactly the condition-bearing files",
                .{notice_path},
            );
            failed.* = true;
        }
    }

    // The other direction. Everything above is driven FROM module_list, so it
    // can only see a module whose file disagrees with §1 -- never a §1 entry
    // that corresponds to no module at all. A planted `modules/ghost/NOTICE`
    // row sailed through until this loop existed, which is the same
    // one-directional blind spot the catalog check itself had.
    var scan: usize = 0;
    while (std.mem.indexOfPos(u8, sec1, scan, "`modules/")) |open| {
        const after = open + "`modules/".len;
        const close = std.mem.indexOfScalarPos(u8, sec1, after, '`') orelse break;
        scan = close + 1;
        const cited = sec1[after..close];
        if (!std.mem.endsWith(u8, cited, "/NOTICE")) continue;
        const name = cited[0 .. cited.len - "/NOTICE".len];
        // §1's prose spells the pattern itself as `modules/<name>/NOTICE`.
        if (std.mem.indexOfScalar(u8, name, '<') != null) continue;
        const known = for (module_list) |m| {
            if (std.mem.eql(u8, m.name, name)) break true;
        } else false;
        if (!known) {
            std.log.err(
                "NOTICE §1 cites `modules/{s}` but there is no module '{s}'",
                .{ cited, name },
            );
            failed.* = true;
        }
    }
}

/// The lexicographically first committed data file under `modules/<m>/` --
/// anything that is neither Zig source nor documentation nor the module's own
/// NOTICE. Naming the file is what makes claim 6's diagnostic actionable: "say
/// where `src/testdata/xlsx_sample.xlsx` came from" is a task, "this module
/// ships data" is a mood.
///
/// Lexicographic rather than iteration order on purpose -- readdir order is not
/// stable across filesystems, and a gate whose error message changes between
/// machines is a gate people stop trusting.
fn firstDataFile(b: *std.Build, io: std.Io, dir_path: []const u8, depth: u8) ?[]const u8 {
    // `src/testdata/csv-spectrum/csvs/x.csv` is four levels below the module;
    // 6 leaves room without letting a symlink cycle run forever.
    if (depth > 6) return null;
    var dir = b.build_root.handle.openDir(io, dir_path, .{ .iterate = true }) catch return null;
    defer dir.close(io);

    var best: ?[]const u8 = null;
    var it = dir.iterate();
    while (it.next(io) catch return best) |e| {
        const path = b.fmt("{s}/{s}", .{ dir_path, e.name });
        const candidate = switch (e.kind) {
            .directory => firstDataFile(b, io, path, depth + 1) orelse continue,
            .file => blk: {
                if (std.mem.endsWith(u8, e.name, ".zig")) continue;
                if (std.mem.endsWith(u8, e.name, ".md")) continue;
                if (std.mem.eql(u8, e.name, "NOTICE")) continue;
                break :blk path;
            },
            else => continue,
        };
        if (best == null or std.mem.lessThan(u8, candidate, best.?)) best = candidate;
    }
    return best;
}

/// Oracle-provenance gate: `ANCHORS.tsv`'s CLASS/ANCHOR columns record where each
/// module's TEST ORACLE gets its authority from -- see the file's own header for
/// the A/B/C/D and EXTERNAL/REDERIVED/MIXED/SELF vocabulary. This is deliberately
/// a separate function from `checkProvenance` above, which guards where
/// implementation CODE came from (licensing / clean-room). Same word, opposite
/// question -- conflating them would mean one of the two silently stops being
/// enforced.
///
/// This bookkeeping went stale three times by hand before this gate existed
/// (backlog 1B), always the same way: closing an anchor task updates
/// `ANCHOR-TASKS.tsv` -- the one place actually owned while doing the work -- and
/// `ANCHORS.tsv`, a dated snapshot regenerated separately, is never told. Running
/// this gate against the repo as it stood found exactly that: 11 modules (`pbb`,
/// `isis`, `isis-adj`, `isis-dis`, `isis-flood`, `isis-spf`, `lnwire`, `psbt`,
/// `accesslog`, `lninvoice`, `yaml`) where `ANCHOR-TASKS.tsv` had already moved
/// past what `ANCHORS.tsv` still said, closed 2026-08-02..2026-08-05 while
/// `ANCHORS.tsv` was last regenerated 2026-08-01. Fixed by syncing those 11 rows;
/// this gate is what stops it from happening an eleventh time.
///
/// What CAN be checked mechanically, and is:
///   - every module in `module_list` has exactly one `ANCHORS.tsv` row, and every
///     `ANCHORS.tsv` row names a real module -- no ghost row for a deleted
///     module, the same one-directional blind spot `checkProvenance`'s claim 4
///     documents for NOTICE §1 (driving the check FROM `module_list` alone can
///     only ever see a module whose row disagrees, never a row with no module)
///   - CLASS is one of A/B/C/D and ANCHOR is one of
///     EXTERNAL/REDERIVED/MIXED/SELF/n/a, in both TSVs
///   - the pairing rule from `ANCHORS.tsv`'s own header: a class A/B module
///     (faces the outside world) must carry a real ANCHOR value; a class C/D
///     module (no outside exists) must be `n/a`
///   - `ANCHOR-TASKS.tsv` only ever lists class A/B modules -- a C/D module
///     cannot carry anchor debt by construction, so its presence there is a
///     misclassification somewhere
///   - `ANCHOR-TASKS.tsv`'s CLASS matches `ANCHORS.tsv`'s CLASS for the same
///     module -- CLASS records a module's relationship to the outside world,
///     which the header states does not change, so any disagreement is a bug
///   - `ANCHORS.tsv`'s ANCHOR matches `ANCHOR-TASKS.tsv`'s ANCHOR for every
///     module in both -- this is the actual fix for the staleness above: what
///     used to be a silently tolerated snapshot lag is now a build error
///
/// What CANNOT be checked, and this does not pretend to:
///   - that a module claiming EXTERNAL/REDERIVED genuinely has one. The KAT
///     file, live peer or foreign oracle a row points at could be deleted,
///     fabricated, or never have existed, and every check above stays green --
///     "the TSV cell says EXTERNAL" is not the same fact as "bytes in this repo
///     were produced by a foreign implementation", and nothing short of a human
///     re-running the foreign oracle (i.e. the anchor-task work itself) can close
///     that gap. Claiming otherwise here would manufacture false confidence.
///   - that EVIDENCE prose is accurate -- only the CLASS/ANCHOR/SOURCE columns
///     are validated; EVIDENCE is free text for a human to judge, same as the
///     README `Provenance:` note is left to a human elsewhere in this file.
///
/// Deliberately NOT built: a "module claims EXTERNAL therefore its tree must
/// contain a file named like a golden/vector" filename heuristic. It was tried
/// while designing this gate -- `sandbox` (EXTERNAL: seccomp/landlock tested
/// against the real running kernel) and `traceroute` (MIXED: real ICMP over a
/// veth pair) are both single-file modules with no `*golden*`/`*vector*`/`*kat*`
/// filename anywhere in their tree, so the heuristic would already need a
/// per-module exemption list on a clean repo, on day one. A check that starts
/// pre-broken teaches everyone to ignore it, which is worse than not having it --
/// see `checkNonGoals`'s own exemption mechanism for what that costs when it IS
/// worth paying for.
fn checkAnchors(b: *std.Build, io: std.Io, failed: *bool) !void {
    const anchors_src = try b.build_root.handle.readFileAlloc(io, "ANCHORS.tsv", b.allocator, .limited(1 * 1024 * 1024));
    const tasks_src = try b.build_root.handle.readFileAlloc(io, "ANCHOR-TASKS.tsv", b.allocator, .limited(1 * 1024 * 1024));

    const anchor_rows = parseAnchorRows(anchors_src, b);
    const task_rows = parseAnchorRows(tasks_src, b);

    // module_list <-> ANCHORS.tsv, both directions -- the same shape as the
    // module_list <-> modules/ check earlier in checkCatalog.
    for (module_list) |m| {
        if (findAnchorRow(anchor_rows, m.name) == null) {
            std.log.err("module '{s}' has no ANCHORS.tsv row (CLASS/ANCHOR oracle bookkeeping)", .{m.name});
            failed.* = true;
        }
    }
    for (anchor_rows) |row| {
        const known = for (module_list) |m| {
            if (std.mem.eql(u8, m.name, row.name)) break true;
        } else false;
        if (!known) {
            std.log.err("ANCHORS.tsv has a row for '{s}' but no such module exists in module_list", .{row.name});
            failed.* = true;
        }
    }

    // Schema + the A/B <-> non-n/a pairing rule, on ANCHORS.tsv.
    for (anchor_rows) |row| {
        if (!containsName(&.{ "A", "B", "C", "D" }, row.class)) {
            std.log.err("ANCHORS.tsv: module '{s}' has CLASS '{s}', not one of A/B/C/D", .{ row.name, row.class });
            failed.* = true;
        }
        if (!containsName(&.{ "EXTERNAL", "REDERIVED", "MIXED", "SELF", "n/a" }, row.anchor)) {
            std.log.err("ANCHORS.tsv: module '{s}' has ANCHOR '{s}', not one of EXTERNAL/REDERIVED/MIXED/SELF/n/a", .{ row.name, row.anchor });
            failed.* = true;
        }
        const faces_outside = std.mem.eql(u8, row.class, "A") or std.mem.eql(u8, row.class, "B");
        const has_anchor = !std.mem.eql(u8, row.anchor, "n/a");
        if (faces_outside and !has_anchor) {
            std.log.err(
                "ANCHORS.tsv: module '{s}' is CLASS {s} (faces the outside world) but ANCHOR is 'n/a' -- " ++
                    "an A/B module must record EXTERNAL/REDERIVED/MIXED/SELF",
                .{ row.name, row.class },
            );
            failed.* = true;
        } else if (!faces_outside and has_anchor) {
            std.log.err(
                "ANCHORS.tsv: module '{s}' is CLASS {s} (no outside truth exists for it) but ANCHOR is '{s}', not 'n/a'",
                .{ row.name, row.class, row.anchor },
            );
            failed.* = true;
        }
    }

    // ANCHOR-TASKS.tsv: schema, ghost rows, and agreement with ANCHORS.tsv.
    for (task_rows) |trow| {
        if (!containsName(&.{ "EXTERNAL", "REDERIVED", "MIXED", "SELF", "n/a" }, trow.anchor)) {
            std.log.err("ANCHOR-TASKS.tsv: module '{s}' has ANCHOR '{s}', not one of EXTERNAL/REDERIVED/MIXED/SELF/n/a", .{ trow.name, trow.anchor });
            failed.* = true;
        }
        const arow = findAnchorRow(anchor_rows, trow.name) orelse {
            std.log.err("ANCHOR-TASKS.tsv has a row for '{s}' but ANCHORS.tsv has no such module", .{trow.name});
            failed.* = true;
            continue;
        };
        if (!std.mem.eql(u8, arow.class, "A") and !std.mem.eql(u8, arow.class, "B")) {
            std.log.err(
                "ANCHOR-TASKS.tsv lists '{s}', but ANCHORS.tsv classifies it CLASS {s} -- only class A/B modules can carry anchor debt",
                .{ trow.name, arow.class },
            );
            failed.* = true;
        }
        if (!std.mem.eql(u8, arow.class, trow.class)) {
            std.log.err(
                "CLASS disagreement for '{s}': ANCHORS.tsv says {s}, ANCHOR-TASKS.tsv says {s} -- CLASS records a " ++
                    "module's relationship to the outside world and must never change between the two files",
                .{ trow.name, arow.class, trow.class },
            );
            failed.* = true;
        }
        if (!std.mem.eql(u8, arow.anchor, trow.anchor)) {
            std.log.err(
                "ANCHOR drift for '{s}': ANCHORS.tsv says {s}, ANCHOR-TASKS.tsv (the file owned while closing anchor " ++
                    "tasks) says {s} -- ANCHORS.tsv was not updated when the task closed",
                .{ trow.name, arow.anchor, trow.anchor },
            );
            failed.* = true;
        }
    }
}

const AnchorRow = struct {
    name: []const u8,
    class: []const u8,
    anchor: []const u8,
};

/// Parse the `module<TAB>CLASS<TAB>ANCHOR<TAB>...` rows both `ANCHORS.tsv` and
/// `ANCHOR-TASKS.tsv` share as their first three columns, skipping `#` comment
/// lines, blank lines, and any malformed line with fewer than three tab-separated
/// fields (a row that short is not a data row this gate can make sense of, and
/// reporting a parse error on it would obscure the real drift this gate exists to
/// find -- CONVENTIONS.md documents the fuller column set each file adds after
/// ANCHOR).
fn parseAnchorRows(content: []const u8, b: *std.Build) []const AnchorRow {
    var out: std.ArrayList(AnchorRow) = .empty;
    var lines = std.mem.splitScalar(u8, content, '\n');
    while (lines.next()) |raw_line| {
        const line = std.mem.trimEnd(u8, raw_line, "\r");
        if (line.len == 0 or line[0] == '#') continue;
        var cols = std.mem.splitScalar(u8, line, '\t');
        const name = cols.next() orelse continue;
        const class = cols.next() orelse continue;
        const anchor = cols.next() orelse continue;
        out.append(b.allocator, .{ .name = name, .class = class, .anchor = anchor }) catch @panic("OOM");
    }
    return out.toOwnedSlice(b.allocator) catch @panic("OOM");
}

fn findAnchorRow(rows: []const AnchorRow, name: []const u8) ?AnchorRow {
    for (rows) |r| {
        if (std.mem.eql(u8, r.name, name)) return r;
    }
    return null;
}

// ---------------------------------------------------------------------------
// `zig build check-fuzz` — the fuzz-coverage gate.
// ---------------------------------------------------------------------------

/// A row of `FUZZ-EXEMPT.tsv`: `module<TAB>REASON<TAB>EVIDENCE`.
const FuzzExemptRow = struct {
    name: []const u8,
    reason: []const u8,
    evidence: []const u8,
};

fn parseFuzzExemptRows(content: []const u8, b: *std.Build) []const FuzzExemptRow {
    var out: std.ArrayList(FuzzExemptRow) = .empty;
    var lines = std.mem.splitScalar(u8, content, '\n');
    while (lines.next()) |raw_line| {
        const line = std.mem.trimEnd(u8, raw_line, "\r");
        if (line.len == 0 or line[0] == '#') continue;
        var cols = std.mem.splitScalar(u8, line, '\t');
        const name = cols.next() orelse continue;
        const reason = cols.next() orelse continue;
        const evidence = std.mem.trim(u8, cols.next() orelse "", " ");
        out.append(b.allocator, .{ .name = name, .reason = reason, .evidence = evidence }) catch @panic("OOM");
    }
    return out.toOwnedSlice(b.allocator) catch @panic("OOM");
}

/// What `checkFuzz` learns about one module by reading its sources.
const FuzzScan = struct {
    /// Files under `modules/<m>/src/` that expose a `pub fn` whose PARAMETER
    /// LIST accepts caller-supplied bytes (`[]const u8`, `[]u8`, or a Reader).
    surface_files: usize,
    /// Files under `modules/<m>/src/` containing a `testing.fuzz(` call.
    harness_files: usize,
    /// `testing.fuzz(` call sites, i.e. individual harnesses.
    harnesses: usize,
};

/// THE GATE'S DEFINITION OF "SHOULD BE FUZZED", AND WHY IT IS NOT A FIG LEAF.
///
/// A module is obligated to carry a fuzz harness when BOTH of these hold:
///
///   1. `ANCHORS.tsv` classifies it CLASS **A** (wire / interop format — other
///      implementations must byte-agree with it) or **B** (published crypto or
///      algorithmic construction). That column is the repo's own, already
///      CI-enforced statement that *foreign bytes are the truth for this
///      module*.
///   2. Its sources expose a `pub fn` that ACCEPTS BYTES — a parameter list
///      mentioning `[]const u8`, `[]u8`, or a `Reader`. That is a property of
///      the code, derived here, not declared anywhere.
///
/// Neither half alone works, and this was measured rather than assumed:
///
///   - CLASS A/B alone obligates 46 harness-less modules, 20 of which have no
///     byte-accepting public function at all: `spbfib`, `bumtree`, `l2forward`,
///     `isis-spf`/`-dis`/`-flood`, `cors`, `security-headers`, `openapi`,
///     `accesslog`, … Those are FSMs and emitters over already-decoded structs.
///     Four of them (`spbfib`, `tcplan`, `workerpool`, `reconcilable`) were
///     independently *justified* as unfuzzable by wave-2 auditors, in prose,
///     before this gate existed — and the structural half reproduces that
///     judgement without being told.
///   - Condition 2 alone obligates the whole repo: `kv`, `ramcache`,
///     `hashdigest` all take `[]const u8` from callers who are us.
///
/// The conjunction is hard to escape cheaply. To make an obligated module stop
/// being obligated you must either take the byte-accepting function out of the
/// public API (a real code change that also removes the surface), or downgrade
/// its CLASS — and CLASS is load-bearing for something else: `checkAnchors`
/// forces a non-A/B module's ANCHOR to `n/a`, which deletes its recorded
/// external anchor and drops it out of `ANCHOR-TASKS.tsv`. You cannot buy fuzz
/// exemption without paying in anchor provenance, in a file whose whole purpose
/// is to be read. That is the difference between this and the earlier
/// "external anchor ⇒ vector file" proxy, which was measured and rejected: this
/// gate does not infer coverage from bookkeeping, it infers OBLIGATION from
/// bookkeeping that is already independently policed, and then checks coverage
/// against the code.
///
/// `FUZZ-EXEMPT.tsv` exists for the residue — cases where condition 2 is true
/// but the bytes are ours (`metrics` takes `[]const u8` metric NAMES, authored
/// by our own callers, and never parses the exposition format it emits). It has
/// ONE row, and five rules keep it that way; see `checkFuzzExempt`. It is not
/// the mechanism, it is the mechanism's error term.
///
/// WHAT THIS GATE DOES NOT DO. It is per MODULE, not per FILE. `lninvoice`
/// passes it today while `bolt12.zig` has no harness of its own. A file-level
/// version was implemented and measured before this one: 455 files in class A/B
/// modules contain a byte-accepting `pub fn` and 234 of them have no harness in
/// the same file. A gate that fires on half the files it looks at is a wishlist,
/// not a gate, and no sharper file predicate separated cleanly (requiring an
/// error-union return only moved it to 162 files across 75 modules). So the
/// file-granularity half of the problem is answered in `scripts/fuzz-sweep.sh`
/// instead, which now budgets and reports per HARNESS with its file path, so a
/// module whose second decoder is unfuzzed is visible in every sweep — and, more
/// importantly, adding that harness no longer steals budget from the first.
///
/// WHY A SEPARATE STEP FROM `check-catalog`. It is red on 26 modules right now
/// (`zig build check-fuzz` prints them). Folding it into the gate that every
/// commit runs would make the tree red for pre-existing debt none of which this
/// slot owns. The one-line change is `check.dependOn(check_fuzz_inner)` in
/// `build()`; it belongs to whoever burns those 26 down, not here. Weakening the
/// gate to make the tree green was the alternative and was rejected.
/// `zig build check-uapi` (campaign C-09). Shells out to
/// `scripts/check-uapi-consts.py` rather than re-implementing its C-header
/// parsing in Zig -- the script is itself the tested, documented artifact
/// (see its own module docstring), and this step is just what makes running
/// it "standing" instead of "something you have to remember to type".
///
/// Absence of `python3` on `PATH` is a SKIP, not a failure, for the same
/// reason the script itself skips a module whose kernel header is not
/// installed: a check that only builds on hosts with specific packages
/// present cannot be a hard gate every clone of this repo goes through.
fn checkUapi(step: *std.Build.Step, options: std.Build.Step.MakeOptions) anyerror!void {
    _ = options;
    const b = step.owner;
    const io = b.graph.io;

    const script_path = b.pathFromRoot("scripts/check-uapi-consts.py");
    const result = std.process.run(b.allocator, io, .{
        .argv = &.{ "python3", script_path },
    }) catch |err| switch (err) {
        error.FileNotFound => {
            std.log.warn("check-uapi: SKIP -- python3 not found on PATH", .{});
            return;
        },
        else => return err,
    };
    defer b.allocator.free(result.stdout);
    defer b.allocator.free(result.stderr);

    if (result.stdout.len > 0) std.log.info("{s}", .{result.stdout});
    if (result.stderr.len > 0) std.log.err("{s}", .{result.stderr});

    switch (result.term) {
        .exited => |code| if (code != 0)
            return step.fail("kernel-UAPI constant drift found by {s} -- see output above", .{script_path}),
        else => |t| return step.fail("check-uapi-consts.py terminated abnormally: {any}", .{t}),
    }
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
/// output, and hands it to `scripts/dark-tests.sh --summary <file>`, which
/// builds nothing. That path is the gate; this step is the standalone entry
/// point for a CI shape that does not go through the driver, and for running
/// the check by hand. `-Ddark-module=<name>` narrows it.
const DarkTestsStep = struct {
    step: std.Build.Step,
    /// From `-Ddark-module`; empty means every module. Carried on the step
    /// rather than read at make time because `b.option` is only callable while
    /// the graph is being built.
    modules: []const []const u8,

    fn make(step: *std.Build.Step, options: std.Build.Step.MakeOptions) anyerror!void {
        _ = options;
        const self: *DarkTestsStep = @fieldParentPtr("step", step);
        const b = step.owner;
        const io = b.graph.io;

        var argv: std.ArrayList([]const u8) = .empty;
        try argv.append(b.allocator, "bash");
        try argv.append(b.allocator, b.pathFromRoot("scripts/dark-tests.sh"));
        for (self.modules) |m| try argv.append(b.allocator, m);

        const result = std.process.run(b.allocator, io, .{
            .argv = argv.items,
            // The script builds and runs every module's suite, so its output is
            // a whole `--summary all` tree plus, for a red module, that
            // module's own test output. `stdout_limit` defaults to
            // `.unlimited`, which is what this needs.
            .cwd = .{ .dir = b.build_root.handle },
        }) catch |err| switch (err) {
            error.FileNotFound => {
                std.log.warn("check-dark-tests: SKIP -- bash not found on PATH", .{});
                return;
            },
            else => return err,
        };
        defer b.allocator.free(result.stdout);
        defer b.allocator.free(result.stderr);

        if (result.stdout.len > 0) std.log.info("{s}", .{result.stdout});
        if (result.stderr.len > 0) std.log.err("{s}", .{result.stderr});

        switch (result.term) {
            .exited => |code| if (code != 0)
                return step.fail("dark tests found -- a module declares tests the test binary never ran; see output above", .{}),
            else => |t| return step.fail("dark-tests.sh terminated abnormally: {any}", .{t}),
        }
    }
};

fn checkFuzz(step: *std.Build.Step, options: std.Build.Step.MakeOptions) anyerror!void {
    _ = options;
    const b = step.owner;
    const io = b.graph.io;

    const anchors_src = try b.build_root.handle.readFileAlloc(io, "ANCHORS.tsv", b.allocator, .limited(1 * 1024 * 1024));
    const anchor_rows = parseAnchorRows(anchors_src, b);
    const exempt_src = try b.build_root.handle.readFileAlloc(io, "FUZZ-EXEMPT.tsv", b.allocator, .limited(1 * 1024 * 1024));
    const exempt_rows = parseFuzzExemptRows(exempt_src, b);

    var failed = false;
    var n_obligated: usize = 0;
    var n_covered: usize = 0;
    var n_exempt: usize = 0;
    var n_failing: usize = 0;
    var n_harnesses: usize = 0;

    for (module_list) |m| {
        const scan = try scanModuleForFuzz(b, io, m.name);
        n_harnesses += scan.harnesses;

        const row = findAnchorRow(anchor_rows, m.name) orelse {
            // checkAnchors reports the missing row itself; repeat it here so a
            // module cannot dodge THIS gate by simply having no CLASS.
            std.log.err(
                "module '{s}' has no ANCHORS.tsv row, so check-fuzz cannot tell whether foreign bytes are its truth",
                .{m.name},
            );
            failed = true;
            continue;
        };
        const faces_outside = std.mem.eql(u8, row.class, "A") or std.mem.eql(u8, row.class, "B");
        if (!faces_outside or scan.surface_files == 0) continue;

        n_obligated += 1;
        if (scan.harnesses > 0) {
            n_covered += 1;
            continue;
        }
        if (findFuzzExemptRow(exempt_rows, m.name) != null) {
            n_exempt += 1;
            continue;
        }
        n_failing += 1;
        std.log.err(
            "module '{s}' is CLASS {s} and exposes a byte-accepting public API in {d} source file(s), " ++
                "but modules/{s}/src/ contains no `testing.fuzz(` harness — so every repo-wide sweep " ++
                "skips it and it looks covered from outside. Add a harness on the decode entry point, " ++
                "or add a justified row to FUZZ-EXEMPT.tsv",
            .{ m.name, row.class, scan.surface_files, m.name },
        );
        failed = true;
    }

    try checkFuzzExempt(b, io, exempt_rows, anchor_rows, &failed);

    std.log.info(
        "check-fuzz: {d} modules obligated, {d} covered, {d} exempt, {d} FAILING ({d} harnesses total)",
        .{ n_obligated, n_covered, n_exempt, n_failing, n_harnesses },
    );

    if (failed) return step.fail("fuzz-coverage gap — see errors above", .{});
}

/// The five rules that keep `FUZZ-EXEMPT.tsv` from becoming the thing that
/// makes this gate meaningless. Every one of them is a claim the gate can
/// refute from the tree, which is the whole point: a row survives only while
/// the code still agrees with it.
///
///  1. REASON comes from a closed vocabulary — `EMIT-ONLY` or `PRE-PARSED`.
///     Free prose in the reason column is how an exemption list stops being
///     readable, and how "we'll fuzz it later" gets in.
///  2. The module exists in `module_list`. (Ghost rows outlive their module —
///     the same blindness `checkProvenance` claim 4 was added for.)
///  3. The row must be DOING WORK: the module must be one this gate would
///     otherwise flag (CLASS A/B *and* a byte-accepting public API). You cannot
///     pre-emptively exempt a module, and an exemption written for a module that
///     later stops facing the wire becomes an error rather than dead weight.
///  4. The module must NOT have a harness. The moment someone fuzzes it anyway,
///     the row is a lie and the gate says so, so stale rows cannot accumulate.
///  5. `PRE-PARSED` must name, in EVIDENCE, a sibling that is a declared `deps`
///     entry of the exempt module AND is itself fuzzed. "Somebody else validates
///     it first" is only an argument if that somebody exists, is actually wired
///     in, and is itself covered. `EMIT-ONLY` must still write down why in
///     EVIDENCE — it is the one claim only a human can make, so it is the one
///     that has to be stated in full.
fn checkFuzzExempt(
    b: *std.Build,
    io: std.Io,
    exempt_rows: []const FuzzExemptRow,
    anchor_rows: []const AnchorRow,
    failed: *bool,
) !void {
    for (exempt_rows) |row| {
        if (!containsName(&.{ "EMIT-ONLY", "PRE-PARSED" }, row.reason)) {
            std.log.err(
                "FUZZ-EXEMPT.tsv: '{s}' has REASON '{s}', not one of EMIT-ONLY/PRE-PARSED",
                .{ row.name, row.reason },
            );
            failed.* = true;
            continue;
        }
        if (row.evidence.len == 0) {
            std.log.err("FUZZ-EXEMPT.tsv: '{s}' has an empty EVIDENCE column", .{row.name});
            failed.* = true;
        }

        const mod = for (module_list) |m| {
            if (std.mem.eql(u8, m.name, row.name)) break m;
        } else {
            std.log.err("FUZZ-EXEMPT.tsv has a row for '{s}' but no such module exists in module_list", .{row.name});
            failed.* = true;
            continue;
        };

        const scan = try scanModuleForFuzz(b, io, row.name);
        const class = if (findAnchorRow(anchor_rows, row.name)) |r| r.class else "?";
        const faces_outside = std.mem.eql(u8, class, "A") or std.mem.eql(u8, class, "B");
        if (!faces_outside or scan.surface_files == 0) {
            std.log.err(
                "FUZZ-EXEMPT.tsv exempts '{s}', but check-fuzz would not have flagged it (CLASS {s}, " ++
                    "{d} byte-accepting source file(s)) — an exemption that excuses nothing is dead weight; delete the row",
                .{ row.name, class, scan.surface_files },
            );
            failed.* = true;
        }
        if (scan.harnesses > 0) {
            std.log.err(
                "FUZZ-EXEMPT.tsv exempts '{s}' as {s}, but modules/{s}/src/ now contains {d} fuzz harness(es) — " ++
                    "the code contradicts the exemption; delete the row",
                .{ row.name, row.reason, row.name, scan.harnesses },
            );
            failed.* = true;
        }

        if (std.mem.eql(u8, row.reason, "PRE-PARSED")) {
            if (!containsName(mod.deps, row.evidence)) {
                std.log.err(
                    "FUZZ-EXEMPT.tsv: '{s}' claims PRE-PARSED by '{s}', but '{s}' is not one of its declared deps " ++
                        "in build.zig's module_list — the bytes cannot be arriving pre-decoded from a module it does not import",
                    .{ row.name, row.evidence, row.evidence },
                );
                failed.* = true;
            } else {
                const upstream = try scanModuleForFuzz(b, io, row.evidence);
                if (upstream.harnesses == 0) {
                    std.log.err(
                        "FUZZ-EXEMPT.tsv: '{s}' claims PRE-PARSED by '{s}', but '{s}' has no fuzz harness of its own — " ++
                            "the exemption hands the untrusted surface to a module nobody fuzzes",
                        .{ row.name, row.evidence, row.evidence },
                    );
                    failed.* = true;
                }
            }
        }
    }
}

fn findFuzzExemptRow(rows: []const FuzzExemptRow, name: []const u8) ?FuzzExemptRow {
    for (rows) |r| {
        if (std.mem.eql(u8, r.name, name)) return r;
    }
    return null;
}

/// Read `modules/<name>/src/*.zig` and count the two things the gate compares:
/// files exposing a byte-accepting public function, and fuzz harnesses.
///
/// Only the flat `src/*.zig` layer is scanned, which is exactly the set
/// `scripts/fuzz-sweep.sh` derives its targets from; the only nested `.zig`
/// files in the repo live under `src/testdata/`.
fn scanModuleForFuzz(b: *std.Build, io: std.Io, name: []const u8) !FuzzScan {
    var out: FuzzScan = .{ .surface_files = 0, .harness_files = 0, .harnesses = 0 };
    const dir_path = b.fmt("modules/{s}/src", .{name});
    var dir = b.build_root.handle.openDir(io, dir_path, .{ .iterate = true }) catch return out;
    defer dir.close(io);
    var it = dir.iterate();
    while (try it.next(io)) |e| {
        if (e.kind != .file or !std.mem.endsWith(u8, e.name, ".zig")) continue;
        const path = b.fmt("{s}/{s}", .{ dir_path, e.name });
        const src = try b.build_root.handle.readFileAlloc(io, path, b.allocator, .limited(8 * 1024 * 1024));

        const n = countFuzzCalls(src);
        out.harnesses += n;
        if (n > 0) out.harness_files += 1;
        if (fileHasByteAcceptingPubFn(src)) out.surface_files += 1;
    }
    return out;
}

fn countFuzzCalls(src: []const u8) usize {
    var n: usize = 0;
    var i: usize = 0;
    while (std.mem.indexOfPos(u8, src, i, "testing.fuzz(")) |at| {
        n += 1;
        i = at + 1;
    }
    return n;
}

/// Does this file expose a `pub fn` whose PARAMETER LIST accepts bytes the
/// caller supplies — `[]const u8` or a `Reader`?
///
/// Three deliberate narrowings, each of which removed a measured false positive:
///
///  - PARAMETER LIST, not the whole signature. A function RETURNING `[]const u8`
///    hands bytes out; it does not take them in.
///  - `[]const u8` but NOT `[]u8`. A mutable byte slice parameter is a buffer
///    the callee WRITES — `isis-flood`'s `buildPsnp(scratch: []u8, …)` and
///    `accesslog`'s `addr_buf: []u8` are output space, and counting them
///    obligated two modules that consume only already-decoded structs.
///  - Parentheses are MATCHED from the one after the function name, so the ~378
///    multi-line signatures in the repo are read correctly. A line-oriented
///    regex missed `adaptor` and `musig2`, which wrap their parameters, and
///    would have let both crypto modules out of the gate.
///
/// Line comments are skipped so a `pub fn` inside a doc-comment example does not
/// obligate a module.
fn fileHasByteAcceptingPubFn(src: []const u8) bool {
    var i: usize = 0;
    while (std.mem.indexOfPos(u8, src, i, "pub fn ")) |at| {
        i = at + 7;
        if (isInsideLineComment(src, at)) continue;
        const open = std.mem.indexOfScalarPos(u8, src, i, '(') orelse break;
        // Anything but an identifier between `pub fn ` and `(` means this is
        // not a plain function header.
        var depth: usize = 1;
        var j = open + 1;
        while (j < src.len and depth > 0) : (j += 1) {
            switch (src[j]) {
                '(' => depth += 1,
                ')' => depth -= 1,
                else => {},
            }
        }
        const params = src[open + 1 .. if (j > 0) j - 1 else 0];
        if (std.mem.indexOf(u8, params, "[]const u8") != null or
            std.mem.indexOf(u8, params, "Reader") != null) return true;
        i = j;
    }
    return false;
}

/// Is byte `at` preceded on its own line by a `//` that is not inside a string
/// literal? Cheap, and only ever consulted for a `pub fn ` occurrence.
fn isInsideLineComment(src: []const u8, at: usize) bool {
    const line_start = if (std.mem.lastIndexOfScalar(u8, src[0..at], '\n')) |nl| nl + 1 else 0;
    var in_str = false;
    var k = line_start;
    while (k + 1 < at) : (k += 1) {
        switch (src[k]) {
            '"' => in_str = !in_str,
            '/' => if (!in_str and src[k + 1] == '/') return true,
            else => {},
        }
    }
    return false;
}

/// The module README's provenance statement: from the first `Provenance:` or
/// `## Provenance` marker to the end of that paragraph (a blank line following
/// at least one line of text), or to the next `## ` heading. Null if the README
/// has no marker at all -- that case is already reported separately.
fn provenanceStatement(readme: []const u8) ?[]const u8 {
    const start = std.mem.indexOf(u8, readme, "Provenance:") orelse
        std.mem.indexOf(u8, readme, "## Provenance") orelse return null;
    const rest = readme[start..];
    // A `## Provenance` SECTION runs to the next heading; an inline
    // `Provenance:` line runs to the end of its paragraph.
    if (std.mem.startsWith(u8, rest, "## ")) {
        const next = std.mem.indexOfPos(u8, rest, 3, "\n## ") orelse return rest;
        return rest[0..next];
    }
    const para_end = std.mem.indexOf(u8, rest, "\n\n") orelse return rest;
    return rest[0..para_end];
}

/// Every run of whitespace becomes one space, so a hard-wrapped sentence
/// matches the same needle a single-line one does.
fn collapseWhitespace(gpa: std.mem.Allocator, s: []const u8) []const u8 {
    const out = gpa.alloc(u8, s.len) catch @panic("OOM");
    var n: usize = 0;
    var in_ws = false;
    for (s) |c| {
        if (std.ascii.isWhitespace(c)) {
            in_ws = true;
            continue;
        }
        if (in_ws and n > 0) {
            out[n] = ' ';
            n += 1;
        }
        in_ws = false;
        out[n] = c;
        n += 1;
    }
    return out[0..n];
}

fn containsAnyIgnoreCase(haystack: []const u8, needles: []const []const u8) bool {
    for (needles) |n| {
        if (std.ascii.indexOfIgnoreCase(haystack, n) != null) return true;
    }
    return false;
}

fn fileExists(b: *std.Build, io: std.Io, path: []const u8) bool {
    b.build_root.handle.access(io, path, .{}) catch return false;
    return true;
}

/// Whether the root NOTICE has an entry for `name`. Two layouts are in use --
/// `  name  — …` and `` `name`  — … `` -- and both must count, or the check
/// reports a missing entry that is right there (this bit me: a first pass
/// matched only the unquoted form and called `jinja` and `reconcilable`
/// undocumented).
fn hasNoticeEntry(notice: []const u8, name: []const u8) bool {
    var it = std.mem.splitScalar(u8, notice, '\n');
    while (it.next()) |line| {
        const t = std.mem.trimStart(u8, line, " ");
        const body = if (std.mem.startsWith(u8, t, "`")) t[1..] else t;
        if (!std.mem.startsWith(u8, body, name)) continue;
        const after = body[name.len..];
        const tail = if (std.mem.startsWith(u8, after, "`")) after[1..] else after;
        const trimmed = std.mem.trimStart(u8, tail, " ");
        if (std.mem.startsWith(u8, trimmed, "—") or std.mem.startsWith(u8, trimmed, "-")) return true;
    }
    return false;
}

/// The slice of `haystack` between the first occurrence of `from` and the next
/// occurrence of `to` after it. Null if either marker is missing or `to`
/// precedes `from`.
fn sectionSlice(haystack: []const u8, from: []const u8, to: []const u8) ?[]const u8 {
    const start = std.mem.indexOf(u8, haystack, from) orelse return null;
    const rest = haystack[start..];
    const end = std.mem.indexOf(u8, rest, to) orelse return null;
    return rest[0..end];
}

/// Non-goals gate: the "Non-goals — deliberately not built here" section must
/// not name a capability that IS a module.
///
/// The catalog check above only ever reads the section that lists what we HAVE,
/// so the section listing what we deliberately DON'T have was unguarded and
/// rotted in one direction: five rows outlived the decision they recorded
/// (`websocket`, `smtp` and `jinja` were still being sent to third-party libs,
/// IMAP was "stays unbuilt" after becoming a planned port, HTTP/3 was "not
/// researched" after being researched). `1c408e6` had fixed two neighbouring
/// rows by hand a day earlier and missed a third one table up -- which is the
/// argument for a gate rather than another sweep.
///
/// A module name counts as "named" when it occurs with non-alphanumeric
/// characters on both sides, case-insensitively. That is deliberately narrow:
/// it fires on `karlseguin/websocket.zig`, `smtp_client.zig` and `vibe-jinja`
/// (the three real defects) while a name buried inside a longer word never
/// fires, so `kv` does not match "kvtree" and `http` does not match "https".
///
/// What it CANNOT see is a row whose staleness has no lexical trace -- "HTTP/3
/// (QUIC) — not researched" said nothing about `quic-crypto`, and "Templates"
/// said nothing about `jinja` except by way of an adopt-candidate that happened
/// to carry the name. Do not read a green gate as "the section is true"; read
/// it as "the section names nothing we have built".
///
/// A legitimate cross-reference (a non-goal explaining itself in terms of a
/// module that DOES exist, e.g. `taskqueue` folded into `jobqueue`) is exempted
/// per name, not per line, with a trailing `<!-- non-goal-ok: name, name -->`.
/// An exemption naming something the line does not mention is itself an error,
/// so the exemptions cannot quietly outlive their reason either.
fn checkNonGoals(readme: []const u8, b: *std.Build, failed: *bool) void {
    const heading = "## Non-goals";
    const start = std.mem.indexOf(u8, readme, heading) orelse {
        std.log.err("README has no \"{s}\" section for the non-goals gate to check", .{heading});
        failed.* = true;
        return;
    };
    const body_start = start + heading.len;
    const end = if (std.mem.indexOf(u8, readme[body_start..], "\n## ")) |i|
        body_start + i
    else
        readme.len;

    var line_no = 1 + std.mem.count(u8, readme[0..start], "\n");
    var lines = std.mem.splitScalar(u8, readme[start..end], '\n');
    while (lines.next()) |line| : (line_no += 1) {
        // Search the line with its own marker cut out. The marker names
        // modules, so leaving it in makes every exemption look justified by
        // its own text -- and in particular makes the stale-exemption check
        // below unable to fire at all, which is how it was first written.
        const body = lineWithoutMarker(line, b);
        var exempted: std.ArrayList([]const u8) = .empty;
        for (module_list) |m| {
            if (!mentionsName(body, m.name)) continue;
            if (nonGoalExempt(line, m.name)) {
                exempted.append(b.allocator, m.name) catch @panic("OOM");
                continue;
            }
            std.log.err(
                "README:{d}: the non-goals section names '{s}', but modules/{s}/ exists — " ++
                    "either the row is stale (delete it) or the mention is a deliberate " ++
                    "cross-reference (append `<!-- non-goal-ok: {s} -->` to the line)",
                .{ line_no, m.name, m.name, m.name },
            );
            failed.* = true;
        }
        for (nonGoalExemptions(line, b)) |claimed| {
            if (!containsName(exempted.items, claimed)) {
                std.log.err(
                    "README:{d}: `non-goal-ok: {s}` exempts a name this line does not " ++
                        "mention as an existing module — drop it",
                    .{ line_no, claimed },
                );
                failed.* = true;
            }
        }
    }
}

/// True when `name` occurs in `haystack` bounded by non-alphanumeric characters
/// on both sides, case-insensitively. The boundary rule treats `-`, `_`, `/`
/// and `.` as separators, which is what lets `smtp` match `smtp_client.zig` and
/// `jinja` match `vibe-jinja`, while keeping a name that is merely a prefix or
/// an infix of a longer word (`kv` in "kvtree", `tar` in "Structured") silent.
fn mentionsName(haystack: []const u8, name: []const u8) bool {
    if (name.len == 0 or name.len > haystack.len) return false;
    var i: usize = 0;
    while (i + name.len <= haystack.len) : (i += 1) {
        if (!std.ascii.eqlIgnoreCase(haystack[i .. i + name.len], name)) continue;
        if (i > 0 and std.ascii.isAlphanumeric(haystack[i - 1])) continue;
        const after = i + name.len;
        if (after < haystack.len and std.ascii.isAlphanumeric(haystack[after])) continue;
        return true;
    }
    return false;
}

/// The line with its `<!-- non-goal-ok: … -->` marker removed, so a mention
/// inside the marker cannot stand in for a mention in the prose.
fn lineWithoutMarker(line: []const u8, b: *std.Build) []const u8 {
    const marker = "<!-- non-goal-ok:";
    const idx = std.mem.indexOf(u8, line, marker) orelse return line;
    const tail = line[idx..];
    const close = std.mem.indexOf(u8, tail, "-->") orelse return line[0..idx];
    return std.mem.concat(b.allocator, u8, &.{ line[0..idx], tail[close + 3 ..] }) catch @panic("OOM");
}

/// The names listed in a line's `<!-- non-goal-ok: a, b -->` marker, or empty.
fn nonGoalExemptions(line: []const u8, b: *std.Build) []const []const u8 {
    const marker = "<!-- non-goal-ok:";
    const idx = std.mem.indexOf(u8, line, marker) orelse return &.{};
    const after = line[idx + marker.len ..];
    const close = std.mem.indexOf(u8, after, "-->") orelse after.len;

    var out: std.ArrayList([]const u8) = .empty;
    var toks = std.mem.splitScalar(u8, after[0..close], ',');
    while (toks.next()) |tok| {
        const trimmed = std.mem.trim(u8, tok, " \t");
        if (trimmed.len > 0) out.append(b.allocator, trimmed) catch @panic("OOM");
    }
    return out.toOwnedSlice(b.allocator) catch @panic("OOM");
}

fn nonGoalExempt(line: []const u8, name: []const u8) bool {
    const marker = "<!-- non-goal-ok:";
    const idx = std.mem.indexOf(u8, line, marker) orelse return false;
    const after = line[idx + marker.len ..];
    const close = std.mem.indexOf(u8, after, "-->") orelse after.len;
    var toks = std.mem.splitScalar(u8, after[0..close], ',');
    while (toks.next()) |tok| {
        if (std.mem.eql(u8, std.mem.trim(u8, tok, " \t"), name)) return true;
    }
    return false;
}

/// Extract the module names in a README catalog row's Deps column (the
/// last `|`-delimited cell) for `name` -- e.g. a cell reading
/// `ocsp, http, x509` becomes three names, an empty/`—` cell becomes zero.
/// Row *existence* is checked by the caller before this runs, so `null`
/// here only means the located row's line was too malformed to have a
/// trailing cell (should not happen for a well-formed table row).
fn readmeDepsCell(readme: []const u8, name: []const u8, b: *std.Build) ?[]const []const u8 {
    const needle = b.fmt("| `{s}` |", .{name});
    const start = std.mem.indexOf(u8, readme, needle) orelse return null;
    const line_end = std.mem.indexOfScalarPos(u8, readme, start, '\n') orelse readme.len;
    const line = std.mem.trimEnd(u8, readme[start..line_end], " \t\r");
    if (!std.mem.endsWith(u8, line, "|")) return null;
    const body = line[0 .. line.len - 1];
    const last_pipe = std.mem.lastIndexOfScalar(u8, body, '|') orelse return null;
    const cell = std.mem.trim(u8, body[last_pipe + 1 ..], " \t");
    if (cell.len == 0 or std.mem.eql(u8, cell, "—") or std.mem.eql(u8, cell, "-")) {
        return &.{};
    }

    var out: std.ArrayList([]const u8) = .empty;
    var toks = std.mem.splitScalar(u8, cell, ',');
    while (toks.next()) |tok| {
        const trimmed = std.mem.trim(u8, tok, " \t");
        if (trimmed.len > 0) out.append(b.allocator, trimmed) catch @panic("OOM");
    }
    return out.toOwnedSlice(b.allocator) catch @panic("OOM");
}

/// Extract the sibling-module names inside a root.zig's `pub const meta`
/// block's `.deps = .{...}` tuple, e.g. `.deps = .{"p256"}` -> `{"p256"}`.
/// Returns `null` when the module has no `meta` block at all, or the block
/// has no `.deps` field -- the caller treats both as "nothing stated".  An
/// explicit empty tuple `.deps = .{}` returns a non-null empty slice, which
/// IS compared against module_list (so a module that silently grew a real
/// dep without updating a `.deps = .{}` stub still gets caught).
///
/// Only the repo's dominant shape is recognised: a tuple of quoted
/// sibling-module-name strings, with any `std.*` usage noted in a trailing
/// `//` comment rather than inside the tuple itself (see CONVENTIONS.md and
/// most modules for the pattern) -- a narrow, well-known shape to locate
/// with `mem.indexOf` + quote-scanning, unlike a general `@import` scan
/// (see the authoritative-source note above `check-catalog`'s definition
/// in `build()`, and CONVENTIONS.md, for why that stays out of the gate).
fn metaDepsFromRoot(src: []const u8, b: *std.Build) ?[]const []const u8 {
    const meta_idx = std.mem.indexOf(u8, src, "pub const meta") orelse return null;
    const meta_end = std.mem.indexOfPos(u8, src, meta_idx, "\n};") orelse src.len;
    const block = src[meta_idx..meta_end];

    // Match the compound literal ".deps = .{", not bare ".deps" -- a
    // module's doc comment can talk *about* `meta.deps` in prose (e.g.
    // `` `meta.deps = .{}` `` as a design-rationale aside) ahead of the
    // real field, and a bare-".deps" search would land on that prose
    // instead. The compound literal only ever matches the real field.
    const deps_idx = std.mem.indexOf(u8, block, ".deps = .{") orelse return null;
    const open = std.mem.indexOfScalarPos(u8, block, deps_idx, '{') orelse return null;
    const close = std.mem.indexOfScalarPos(u8, block, open, '}') orelse return null;
    const inner = block[open + 1 .. close];

    var out: std.ArrayList([]const u8) = .empty;
    var i: usize = 0;
    while (std.mem.indexOfScalarPos(u8, inner, i, '"')) |q1| {
        const q2 = std.mem.indexOfScalarPos(u8, inner, q1 + 1, '"') orelse break;
        out.append(b.allocator, inner[q1 + 1 .. q2]) catch @panic("OOM");
        i = q2 + 1;
    }
    return out.toOwnedSlice(b.allocator) catch @panic("OOM");
}

fn containsName(list: []const []const u8, name: []const u8) bool {
    for (list) |n| {
        if (std.mem.eql(u8, n, name)) return true;
    }
    return false;
}

/// Compare `want` (build.zig's module_list `.deps` -- the ground truth,
/// since `mod.addImport` in pass 2 of `build()` is what actually lets a
/// module `@import` a sibling) against `have` (what a doc surface --
/// the README table or root.zig's `meta.deps` -- claims). Logs one
/// precise error per direction that disagrees and flips `failed.*`; never
/// stops at the first module or the first surface.
fn checkDepsMatch(
    name: []const u8,
    surface: []const u8,
    want: []const []const u8,
    have: []const []const u8,
    b: *std.Build,
    failed: *bool,
) void {
    var missing: std.ArrayList([]const u8) = .empty;
    for (want) |w| {
        if (!containsName(have, w)) missing.append(b.allocator, w) catch @panic("OOM");
    }
    var extra: std.ArrayList([]const u8) = .empty;
    for (have) |h| {
        if (!containsName(want, h)) extra.append(b.allocator, h) catch @panic("OOM");
    }
    if (missing.items.len == 0 and extra.items.len == 0) return;

    if (missing.items.len > 0) {
        const joined = std.mem.join(b.allocator, ", ", missing.items) catch @panic("OOM");
        std.log.err(
            "module '{s}': {s} is missing dep(s) [{s}] that build.zig's module_list declares",
            .{ name, surface, joined },
        );
    }
    if (extra.items.len > 0) {
        const joined = std.mem.join(b.allocator, ", ", extra.items) catch @panic("OOM");
        std.log.err(
            "module '{s}': {s} lists dep(s) [{s}] that build.zig's module_list does not declare",
            .{ name, surface, joined },
        );
    }
    failed.* = true;
}
