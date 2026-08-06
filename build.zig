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
    .{ .name = "http", .deps = &.{"netaddr"}, .test_deps = &.{"testkit"} },
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
    .{ .name = "acme", .deps = &.{ "http", "router" } },
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
    .{ .name = "timelock_envelope", .deps = &.{ "tlock", "hqc", "chachapoly" } },
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
    .{ .name = "wireguard", .deps = &.{ "netlink", "genetlink" } },
    .{ .name = "tc", .deps = &.{"netlink"}, .test_deps = &.{"testkit"} },
    .{ .name = "traceroute", .deps = &.{ "icmp", "netaddr", "latency-stats" } },
    .{ .name = "probe", .deps = &.{ "netaddr", "latency-stats" } },
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
    .{ .name = "webauthn", .deps = &.{ "cbor", "rsa", "p256" } },
    .{ .name = "zipstream" },
    .{ .name = "tz", .deps = &.{"datefmt"} },
    .{ .name = "pollworker" },
    .{ .name = "ipcbus", .deps = &.{"framing"} },
    .{ .name = "csvstream" },
    .{ .name = "csvsafe" },
    .{ .name = "numparse", .deps = &.{"decimal"} },
    .{ .name = "argsafe" },
    .{ .name = "sessions", .deps = &.{ "router", "http", "cookies", "ramcache" } },
    .{ .name = "jobqueue", .deps = &.{"kv"} },
    .{ .name = "reconcilable", .deps = &.{"resilience"} },
    .{ .name = "llmclient", .deps = &.{"http"} },
    .{ .name = "rawsock", .deps = &.{"netaddr"} },
    .{ .name = "encoding" },
    .{ .name = "syslog" },
    .{ .name = "sntp" },
    .{ .name = "stun", .deps = &.{"netaddr"} },
    .{ .name = "opcua", .deps = &.{ "rsa", "x509" }, .test_deps = &.{"testkit"}, .heavy = true },
    .{ .name = "noise" },
    .{ .name = "x509", .deps = &.{"rsa"} },
    .{ .name = "ocsp", .deps = &.{ "x509", "rsa", "p256" }, .heavy = true },
    .{ .name = "ocspcache", .deps = &.{ "ocsp", "http", "x509" } },
    .{ .name = "dnssec", .deps = &.{ "dns", "rsa" } },
    .{ .name = "dnp3", .deps = &.{"aeskw"} },
    .{ .name = "slhdsa", .heavy = true },
    .{ .name = "falcon" },
    .{ .name = "hqc", .heavy = true },
    .{ .name = "dtls", .deps = &.{ "rsa", "x509" }, .test_deps = &.{"testkit"} },
    .{ .name = "tlsresume" },
    .{ .name = "quic-crypto" },
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
    .{ .name = "hpke", .deps = &.{"p256"} },
    .{ .name = "adaptor", .deps = &.{ "bip340", "k256" } },
    .{ .name = "frost", .deps = &.{ "bip340", "k256" } },
    .{ .name = "oscore" },
    .{ .name = "spake2plus", .deps = &.{"p256"} },
    .{ .name = "voprf" },
    .{ .name = "opaque", .deps = &.{"voprf"} },
    .{ .name = "bulletproofs" },
    .{ .name = "xmss", .heavy = true },
    .{ .name = "minisign", .heavy = true },
    .{ .name = "otp" },
    .{ .name = "ctap2pin", .deps = &.{"p256"} },
    .{ .name = "bls12_381", .heavy = true },
    .{ .name = "bbs", .deps = &.{"bls12_381"} },
    .{ .name = "coconut", .deps = &.{"bls12_381"}, .heavy = true },
    .{ .name = "tlock", .deps = &.{"bls12_381"} },
    .{ .name = "ibe", .deps = &.{"bls12_381"}, .heavy = true },
    .{ .name = "bn254", .heavy = true },
    .{ .name = "ed448" },
    .{ .name = "decaf448", .deps = &.{"ed448"} },
    .{ .name = "paillier", .deps = &.{"montint"}, .heavy = true },
    .{ .name = "threshold_ecdsa", .deps = &.{ "paillier", "montint" }, .heavy = true },
    .{ .name = "dkg", .deps = &.{ "threshold_ecdsa", "paillier" }, .heavy = true },
    .{ .name = "vdf", .deps = &.{"montint"} },
    .{ .name = "signal" },
    .{ .name = "mls", .deps = &.{"hpke"} },
    .{ .name = "megolm", .deps = &.{"aescbc"} },
    .{ .name = "ebpf", .deps = &.{"netlink"}, .test_deps = &.{"testkit"} },
    .{ .name = "xdp-classifier", .deps = &.{"ebpf"} },
    .{ .name = "ecvrf" },
    .{ .name = "fss" },
    .{ .name = "pir", .deps = &.{"fss"} },
    .{ .name = "bfv" },
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
    .{ .name = "tfhe", .heavy = true },
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

        const unit_tests = b.addTest(.{ .root_module = test_root });
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
}

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
