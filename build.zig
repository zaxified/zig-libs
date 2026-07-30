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
    .{ .name = "netaddr" },
    .{ .name = "http", .deps = &.{"netaddr"} },
    .{ .name = "websocket", .deps = &.{"http"} },
    .{ .name = "accesslog", .deps = &.{"http"} },
    .{ .name = "staticfiles", .deps = &.{"http"} },
    .{ .name = "brotli" },
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
    .{ .name = "netlink" },
    .{ .name = "genetlink", .deps = &.{"netlink"} },
    .{ .name = "nl80211", .deps = &.{ "genetlink", "netlink" } },
    .{ .name = "ethtool", .deps = &.{ "genetlink", "netlink" } },
    .{ .name = "devlink", .deps = &.{ "genetlink", "netlink" } },
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
    .{ .name = "netconf", .deps = &.{ "ssh", "xml" } },
    .{ .name = "nftables", .deps = &.{"netlink"} },
    .{ .name = "trie" },
    .{ .name = "fuzzysearch", .deps = &.{"trie"} },
    .{ .name = "geoindex" },
    .{ .name = "readthrough", .deps = &.{"ramcache"} },
    .{ .name = "timelock_envelope", .deps = &.{ "tlock", "hqc", "chachapoly" } },
    .{ .name = "drand", .deps = &.{ "bls12_381", "tlock" } },
    .{ .name = "tcplan", .deps = &.{"tc"} },
    .{ .name = "modbus" },
    .{ .name = "iec104" },
    .{ .name = "fleetsim", .deps = &.{ "modbus", "dnp3", "iec104", "s7comm", "bacnet", "enip", "opcua", "netsim" } },
    .{ .name = "smtp", .deps = &.{"netaddr"} },
    .{ .name = "iec61850", .deps = &.{"xml"} },
    .{ .name = "iec62351", .deps = &.{ "x509", "rsa" } },
    .{ .name = "s7comm" },
    .{ .name = "enip", .deps = &.{"netaddr"} },
    .{ .name = "bacnet", .deps = &.{ "netaddr", "websocket" } },
    .{ .name = "whois", .deps = &.{"netaddr"} },
    .{ .name = "uci" },
    .{ .name = "mqtt" },
    .{ .name = "snmp" },
    .{ .name = "wireguard", .deps = &.{ "netlink", "genetlink" } },
    .{ .name = "tc", .deps = &.{"netlink"} },
    .{ .name = "traceroute", .deps = &.{ "icmp", "netaddr", "latency-stats" } },
    .{ .name = "probe", .deps = &.{ "netaddr", "latency-stats" } },
    .{ .name = "l2disco", .deps = &.{"netaddr"} },
    .{ .name = "upstream", .deps = &.{ "resilience", "probe" } },
    .{ .name = "jwt", .deps = &.{ "http", "router", "p256" } },
    .{ .name = "rbac" },
    .{ .name = "xml" },
    .{ .name = "xmldsig", .deps = &.{ "xml", "rsa", "p256" } },
    .{ .name = "saml", .deps = &.{ "xmldsig", "xml", "xmlenc", "rsa", "x509" }, .heavy = true },
    .{ .name = "xmlenc", .deps = &.{ "xml", "rsa", "aescbc", "aeskw" }, .heavy = true },
    .{ .name = "aescbc" },
    .{ .name = "aeskw" },
    .{ .name = "jwe", .deps = &.{ "rsa", "p256", "aescbc", "aeskw" } },
    .{ .name = "rdap", .deps = &.{ "http", "netaddr" } },
    .{ .name = "blobstore", .deps = &.{"hashdigest"} },
    .{ .name = "procnet", .deps = &.{"netaddr"} },
    .{ .name = "conntrack", .deps = &.{ "netlink", "netaddr" } },
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
    .{ .name = "cbor" },
    .{ .name = "protobuf" },
    .{ .name = "grpc", .deps = &.{ "http", "protobuf" } },
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
    .{ .name = "llmclient", .deps = &.{"http"} },
    .{ .name = "rawsock", .deps = &.{"netaddr"} },
    .{ .name = "encoding" },
    .{ .name = "syslog" },
    .{ .name = "sntp" },
    .{ .name = "stun", .deps = &.{"netaddr"} },
    .{ .name = "opcua", .deps = &.{ "rsa", "x509" }, .heavy = true },
    .{ .name = "noise" },
    .{ .name = "x509", .deps = &.{"rsa"} },
    .{ .name = "ocsp", .deps = &.{ "x509", "rsa", "p256" }, .heavy = true },
    .{ .name = "ocspcache", .deps = &.{ "ocsp", "http", "x509" } },
    .{ .name = "dnssec", .deps = &.{ "dns", "rsa" } },
    .{ .name = "dnp3", .deps = &.{"aeskw"} },
    .{ .name = "slhdsa", .heavy = true },
    .{ .name = "falcon" },
    .{ .name = "hqc", .heavy = true },
    .{ .name = "dtls", .deps = &.{ "rsa", "x509" } },
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
    .{ .name = "ebpf", .deps = &.{"netlink"} },
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
    .{ .name = "poseidon", .deps = &.{ "bn254", "bls12_381" } },
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

        const unit_tests = b.addTest(.{ .root_module = mod });
        const run = b.addRunArtifact(unit_tests);
        test_step.dependOn(&run.step);

        // Per-module test step: `zig build test-<name>`.
        const one = b.step(b.fmt("test-{s}", .{m.name}), b.fmt("Test the {s} module", .{m.name}));
        one.dependOn(&run.step);
    }

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
        for (m.deps, 0..) |dep, i| {
            if (i != 0) try w.writeAll(",");
            try w.writeAll(dep);
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

    if (failed) return step.fail("catalog drift — see errors above", .{});
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
