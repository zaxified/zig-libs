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
    example: bool = false,
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
    .{ .name = "validate", .deps = &.{ "router", "http", "netaddr" }, .example = true },
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
    .{ .name = "acme", .deps = &.{ "http", "router", "entropy" }, .example = true },
    .{ .name = "netlink", .test_deps = &.{"testkit"} },
    .{ .name = "genetlink", .deps = &.{"netlink"} },
    .{ .name = "nl80211", .deps = &.{ "genetlink", "netlink" }, .test_deps = &.{"testkit"}, .example = true },
    .{ .name = "ethtool", .deps = &.{ "genetlink", "netlink" }, .test_deps = &.{"testkit"}, .example = true },
    .{ .name = "devlink", .deps = &.{ "genetlink", "netlink" }, .test_deps = &.{"testkit"}, .example = true },
    .{ .name = "decimal" },
    .{ .name = "seqmap" },
    .{ .name = "icmp", .deps = &.{ "seqmap", "netaddr" } },
    .{ .name = "mcp" },
    .{ .name = "mcp-http", .deps = &.{ "router", "http", "mcp" } },
    .{ .name = "coap", .example = true },
    .{ .name = "kv" },
    .{ .name = "kvtree", .deps = &.{"kv"} },
    .{ .name = "blobmsg", .example = true },
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
    .{ .name = "netconf", .deps = &.{ "ssh", "xml" }, .test_deps = &.{"testkit"}, .example = true },
    .{ .name = "nftables", .deps = &.{"netlink"}, .test_deps = &.{"testkit"}, .example = true },
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
    .{ .name = "smtp", .deps = &.{"netaddr"}, .test_deps = &.{"testkit"}, .example = true },
    .{ .name = "imap", .test_deps = &.{"testkit"}, .example = true },
    .{ .name = "iec61850", .deps = &.{"xml"}, .test_deps = &.{"testkit"}, .example = true },
    .{ .name = "iec62351", .deps = &.{ "x509", "rsa" } },
    .{ .name = "s7comm", .test_deps = &.{"testkit"} },
    .{ .name = "enip", .deps = &.{"netaddr"}, .test_deps = &.{"testkit"} },
    .{ .name = "bacnet", .deps = &.{ "netaddr", "websocket" }, .test_deps = &.{"testkit"} },
    .{ .name = "whois", .deps = &.{"netaddr"} },
    .{ .name = "uci" },
    .{ .name = "mqtt", .example = true },
    .{ .name = "snmp", .test_deps = &.{"testkit"}, .example = true },
    .{ .name = "wireguard", .deps = &.{ "netlink", "genetlink", "chachapoly", "entropy", "netaddr" }, .example = true },
    .{ .name = "tc", .deps = &.{"netlink"}, .test_deps = &.{"testkit"} },
    .{ .name = "traceroute", .deps = &.{ "icmp", "netaddr", "latency-stats" } },
    .{ .name = "probe", .deps = &.{ "netaddr", "latency-stats" }, .test_deps = &.{"testkit"} },
    .{ .name = "pathmtu", .deps = &.{ "icmp", "netaddr" } },
    .{ .name = "l2disco", .deps = &.{"netaddr"}, .example = true },
    .{ .name = "upstream", .deps = &.{ "resilience", "probe" } },
    .{ .name = "jwt", .deps = &.{ "http", "router", "p256" }, .example = true },
    .{ .name = "rbac", .example = true },
    .{ .name = "xml" },
    .{ .name = "xmldsig", .deps = &.{ "xml", "rsa", "p256" } },
    .{ .name = "saml", .deps = &.{ "xmldsig", "xml", "xmlenc", "rsa", "x509", "datefmt" }, .heavy = true, .example = true },
    .{ .name = "xmlenc", .deps = &.{ "xml", "rsa", "aescbc", "aeskw" }, .heavy = true },
    .{ .name = "aescbc" },
    .{ .name = "aeskw" },
    .{ .name = "jwe", .deps = &.{ "rsa", "p256", "aescbc", "aeskw" }, .example = true },
    .{ .name = "rdap", .deps = &.{ "http", "netaddr" } },
    .{ .name = "blobstore", .deps = &.{"hashdigest"} },
    .{ .name = "procnet", .deps = &.{"netaddr"} },
    .{ .name = "diskusage" },
    .{ .name = "conntrack", .deps = &.{ "netlink", "netaddr" }, .test_deps = &.{"testkit"}, .example = true },
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
    .{ .name = "jinja", .test_deps = &.{"testkit"}, .example = true },
    .{ .name = "cbor" },
    .{ .name = "protobuf", .test_deps = &.{"testkit"} },
    .{ .name = "grpc", .deps = &.{ "http", "protobuf" }, .test_deps = &.{"testkit"}, .example = true },
    .{ .name = "webauthn", .deps = &.{ "cbor", "rsa", "p256", "x509" } },
    .{ .name = "zipstream" },
    .{ .name = "qr" },
    .{ .name = "qrscan", .deps = &.{"qr"} },
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
    .{ .name = "falcon", .example = true },
    .{ .name = "hqc", .heavy = true },
    .{ .name = "dtls", .deps = &.{ "rsa", "x509", "chachapoly" }, .test_deps = &.{"testkit"}, .example = true },
    .{ .name = "tlsresume", .example = true },
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
    .{ .name = "frost", .deps = &.{ "bip340", "k256" }, .example = true },
    .{ .name = "oscore" },
    .{ .name = "spake2plus", .deps = &.{"p256"} },
    .{ .name = "ct25519" },
    .{ .name = "voprf", .deps = &.{"ct25519"} },
    .{ .name = "opaque", .deps = &.{ "voprf", "ct25519" } },
    .{ .name = "bulletproofs", .deps = &.{"ct25519"} },
    .{ .name = "xmss", .heavy = true, .example = true },
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
    .{ .name = "mls", .deps = &.{"hpke"}, .example = true },
    .{ .name = "megolm", .deps = &.{ "aescbc", "entropy" } },
    .{ .name = "ebpf", .deps = &.{"netlink"}, .test_deps = &.{"testkit"} },
    .{ .name = "xdp-classifier", .deps = &.{"ebpf"} },
    .{ .name = "ecvrf", .deps = &.{"ct25519"} },
    .{ .name = "fss" },
    .{ .name = "pir", .deps = &.{"fss"} },
    .{ .name = "bfv", .deps = &.{"entropy"}, .example = true },
    .{ .name = "groth16", .deps = &.{"bn254"}, .example = true },
    // Not heavy: the parameter derivation + all 30 tests run in 5s under
    // -Dstrict-debug, well under the >15s threshold (and a Debug compile of
    // this module is ~1s against ~27s at ReleaseSafe, so marking it heavy
    // would cost more than it saves).
    .{ .name = "poseidon", .deps = &.{ "bn254", "bls12_381" }, .test_deps = &.{"testkit"}, .example = true },
    // Not heavy, despite the inverse S-box (72 multiplies per element per
    // half-round). Measured serially on this host: strict-Debug compile ~8.5s
    // + run ~1.0s = 9.5s, under the >15s threshold — and a ReleaseSafe compile
    // of this module is ~46s (comptime SHAKE256 derivation + heavily unrolled
    // field code), so marking it heavy would cost 5x what it saves.
    .{ .name = "rescue" },
    .{ .name = "tfhe", .deps = &.{"entropy"}, .heavy = true, .example = true },
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

    // Gate for the "a body nothing references is never analysed" class — see
    // the `force_mod` block in pass 2 for what it compiles and why.
    const check_pubfn_reach = b.step("check-pubfn-reach", "Analyse every non-generic public declaration, including the ones no test reaches");

    // `check-examples` — build `modules/<name>/example/main.zig` as a real
    // consumer binary. See the `example` block in pass 2 for the one class it
    // covers that no test in this repository can.
    const check_examples = b.step("check-examples", "Build each module's example as an outside consumer would");

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

        // ⭐ `.name` defaults to "test", which made all 225 compilations
        // indistinguishable in every place zig names a step: the progress tree
        // said `compile test` whichever module was building, and so did
        // `--summary`. Naming them after the module is what makes a build or a
        // hang self-identifying — without it no amount of log plumbing can say
        // WHICH module is the slow one.
        const unit_tests = b.addTest(.{
            .name = m.name,
            .root_module = test_root,
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
        b.getInstallStep().dependOn(&unit_tests.step);

        // Per-module test step: `zig build test-<name>`.
        const one = b.step(b.fmt("test-{s}", .{m.name}), b.fmt("Test the {s} module", .{m.name}));
        one.dependOn(&run.step);

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
            .root_source_file = b.path("scripts/force-pubfn-reach.zig"),
            .target = target,
            .optimize = if (m.heavy) heavy_optimize else optimize,
        });
        force_mod.addImport("m", test_root);
        const force_tests = b.addTest(.{
            .name = b.fmt("force-{s}", .{m.name}),
            .root_module = force_mod,
        });
        check_pubfn_reach.dependOn(&force_tests.step);

        // ⭐ The one class nothing else here can cover: **is the published API
        // sufficient to do the job?**
        //
        // Every test in this collection lives in the same file as the code it
        // tests, so it reads private declarations freely and its build carries
        // `test_deps` the published module never gets. It can therefore pass
        // while a function is unreachable from outside, a type needed to call
        // it is not exported, or an error is not nameable. That is not a
        // hypothetical either — it is exactly how `diskusage` shipped two
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
        // Compile-only, like every other check step here: nothing installs or
        // runs the artifact, so the build passes `-fno-emit-bin` and this does
        // NOT cover consumer-BINARY facts — link-time reach (a MIPS `PC16`
        // fixup overflows at ±128 KB) or what a module drags in (`http`'s
        // TLS-vs-plaintext split was 334 KB). That class needs a linked,
        // measured binary; `scripts/check-http-sizeprobe.sh` is the one place
        // this repository does it today.
        //
        // Scoped, not universal (survey 2026-08-21): 78 of 229 modules already
        // have an in-repo consumer, so their boundary is exercised by real
        // code; 93 more have a public surface under 25 functions, a third of
        // them anchored to published test vectors, where an internal vector
        // test is strictly stronger than an example. The 57 that are left have
        // no consumer AND a wide surface — those get examples, largest first.
        if (m.example) {
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
            for (m.deps) |dep| example_mod.addImport(dep, mods.get(dep).?);
            const example = b.addExecutable(.{
                .name = b.fmt("example-{s}", .{m.name}),
                .root_module = example_mod,
            });
            check_examples.dependOn(&example.step);
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
        "Compile every module's tests for each target in its meta.targets, checked against scripts/portable-known-failures.tsv",
    );

    // Pass 1: parse every module's declared set once, in module_list order,
    // at graph-build time -- step CREATION below (pass 3) needs it to decide
    // which `portable-<name>-<target>` steps to make. A module whose
    // declaration cannot be read (no `meta` block, no `.targets` field, an
    // unknown/duplicate token, or a set missing the mandatory `.linux64`)
    // contributes no entry to `module_targets` and instead a message to
    // `portable_decl_errors`, surfaced by `PortableBaselineStep.make` below --
    // this is what makes "a module missing its declaration" a gate failure
    // (bolt3, before this commit, had a `meta` block with no platform claim
    // at all and nothing noticed).
    var module_targets = std.StringHashMap([]const PortableTarget).init(b.allocator);
    var portable_decl_errors: std.ArrayList([]const u8) = .empty;
    for (module_list) |m| {
        const parsed = parseMetaTargets(b, b.graph.io, m.name);
        if (parsed.err) |e| {
            portable_decl_errors.append(b.allocator, b.fmt("{s}: {s}", .{ m.name, e })) catch @panic("OOM");
            continue;
        }
        module_targets.put(m.name, parsed.targets) catch @panic("OOM");
    }

    // Snapshot of `module_targets` as a plain, deterministically-sorted slice
    // -- `check-portable-table` (below) renders a README table from this, and
    // a hash map's iteration order is not something a checked-in file's row
    // order should depend on. Same data as `module_targets`, just ordered.
    var portable_decls: std.ArrayList(PortableDecl) = .empty;
    {
        var it = module_targets.iterator();
        while (it.next()) |e| portable_decls.append(b.allocator, .{ .module = e.key_ptr.*, .targets = e.value_ptr.* }) catch @panic("OOM");
    }
    std.mem.sort(PortableDecl, portable_decls.items, {}, struct {
        fn lessThan(_: void, x: PortableDecl, y: PortableDecl) bool {
            return std.mem.lessThan(u8, x.module, y.module);
        }
    }.lessThan);

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
                .optimize = .ReleaseSmall,
            })) catch @panic("OOM");
        }
        cross_mods[ti] = map;
    }
    for (cross_compile_targets, 0..) |_, ti| {
        for (module_list) |m| {
            const mod = cross_mods[ti].get(m.name).?;
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
    var portable_pairs: std.ArrayList(PortablePair) = .empty;
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
                    .optimize = .ReleaseSmall,
                });
                for (m.deps) |dep| t.addImport(dep, cross_mods[ti].get(dep).?);
                for (m.test_deps) |dep| t.addImport(dep, cross_mods[ti].get(dep).?);
                break :blk t;
            };
            const cross_test = b.addTest(.{ .name = step_name, .root_module = test_root });
            const one = b.step(
                step_name,
                b.fmt("Compile {s}'s tests for {s} (true status, not baseline-checked)", .{ m.name, ct.label() }),
            );
            one.dependOn(&cross_test.step);

            if (is_declared) portable_pairs.append(b.allocator, .{ .module = m.name, .target = ct }) catch @panic("OOM");
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
    // `scripts/portable-known-failures.tsv` itself.
    const portable_baseline = b.allocator.create(PortableBaselineStep) catch @panic("OOM");
    portable_baseline.* = .{
        .step = std.Build.Step.init(.{
            .id = .custom,
            .name = "check-portable",
            .owner = b,
            .makeFn = PortableBaselineStep.make,
        }),
        .pairs = portable_pairs.items,
        .decl_errors = portable_decl_errors.items,
    };
    portable.dependOn(&portable_baseline.step);

    // `zig build check-portable-table` / `zig build gen-portable-table` — the
    // consumer-facing half of the schema above. `check-portable` proves a
    // claim; nothing until now let a consumer SEE it without reading 228
    // `root.zig` files and a TSV. This renders the README's "Portability"
    // table from exactly the two sources `check-portable` itself reads --
    // `module_targets`' declared sets (snapshotted into `portable_decls`
    // above) and `scripts/portable-known-failures.tsv` -- so the table can
    // never assert a status the gate did not itself check, and a stale table
    // (edited by hand, or left behind after a module's `.targets` changed)
    // fails the build exactly as a stale baseline row does. Two named steps
    // sharing one `make`: `check-portable-table` (the gate; `.write = false`)
    // and `gen-portable-table` (the fix; `.write = true`), so "verify" and
    // "regenerate" can never drift into two different rendering paths.
    const portable_table_check = b.allocator.create(PortableTableStep) catch @panic("OOM");
    portable_table_check.* = .{
        .step = std.Build.Step.init(.{
            .id = .custom,
            .name = "check-portable-table",
            .owner = b,
            .makeFn = PortableTableStep.make,
        }),
        .decls = portable_decls.items,
        .decl_errors = portable_decl_errors.items,
        .write = false,
    };
    b.step(
        "check-portable-table",
        "Verify README.md's generated Portability table matches meta.targets + the known-failures baseline",
    ).dependOn(&portable_table_check.step);

    const portable_table_gen = b.allocator.create(PortableTableStep) catch @panic("OOM");
    portable_table_gen.* = .{
        .step = std.Build.Step.init(.{
            .id = .custom,
            .name = "gen-portable-table",
            .owner = b,
            .makeFn = PortableTableStep.make,
        }),
        .decls = portable_decls.items,
        .decl_errors = portable_decl_errors.items,
        .write = true,
    };
    b.step(
        "gen-portable-table",
        "Regenerate README.md's Portability table from meta.targets + the known-failures baseline",
    ).dependOn(&portable_table_gen.step);

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
    const check_global_alloc_inner = b.allocator.create(std.Build.Step) catch @panic("OOM");
    check_global_alloc_inner.* = std.Build.Step.init(.{
        .id = .custom,
        .name = "check-global-alloc",
        .owner = b,
        .makeFn = checkGlobalAlloc,
    });
    check_global_alloc.dependOn(check_global_alloc_inner);

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
    const check_uapi = b.step("check-uapi", "Diff hardcoded kernel UAPI constants against installed kernel headers");
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

        if (std.mem.indexOf(u8, readme, catalogRowNeedle(b, m.name)) == null) {
            std.log.err(
                "module '{s}' has no README catalog row — the first cell must be" ++
                    " exactly `[`{s}`](modules/{s}/README.md)`, so the table's own" ++
                    " link is checked rather than trusted",
                .{ m.name, m.name, m.name },
            );
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

/// `zig build check-changelog` — every module documents itself, in a file that
/// is really a changelog, with every entry dated.
///
/// CONVENTIONS §8 splits the changelog: detail lives in
/// `modules/<m>/CHANGELOG.md` and the root file does not restate it, so a
/// consumer of three modules reads three files.
///
/// HISTORY, because it is what every rule below was bought with. The root file
/// used to carry a per-module INDEX -- one pointer bullet per module, 225 of
/// them, 437 of the file's 503 lines -- and this gate spent three of its five
/// claims enforcing that index against the tree. Nothing had checked it when it
/// was written, and 16 of 55 module changelogs (`acme`, `bbs`, `bls12_381`,
/// `cookies`, `cors`, `ed448`, `entropy`, `ibe`, `ratelimit`, `router`,
/// `sessions`, `signal`, `throttle`, `timelock_envelope`, `tlock`, `wireguard`)
/// had no index line at all -- the failure mode an index has, being silently
/// incomplete, so a consumer reads it and concludes their module did not
/// change. The index was removed on 2026-08-14 and the two claims that existed
/// only to police it went with it; see "WHY THE INDEX CHECKS ARE GONE" below.
/// The three claims that survived are about the module files themselves, and
/// each of them caught a real hole on the real tree.
///
/// Four claims:
///
///  0. Every entry in a `modules/<m>/CHANGELOG.md` carries its landing date.
///     See `checkEntryDates` for the format and its calibration.
///  1. Every module in `module_list` HAS a `modules/<m>/CHANGELOG.md`. Driven
///     from `module_list`; a `modules/<x>/` that is not in `module_list` is
///     `check-catalog`'s error, not this one, and `modules/_template/` -- which
///     is not in `module_list` -- is outside the requirement by construction.
///  1b. That file is a CHANGELOG and not merely a file at that path. See
///     `checkChangelogShape` for the two landmarks and their calibration.
///  2. Every `modules/<m>/CHANGELOG.md` link IN the root file resolves to a
///     file that exists. This is link integrity, not index membership: it does
///     not ask that any particular module be linked, only that a link the root
///     file does carry points at something. See its own note below for what it
///     covers TODAY, which is nothing, and why it is kept anyway.
///
/// WHY (1) DEMANDS THE FILE. The first version of this loop read each module
/// changelog with `catch continue`, so a module with NO `CHANGELOG.md` was
/// skipped entirely and every claim below it was skipped with it. That is
/// fail-open in exactly the shape a new module arrives in. Measured on the real
/// tree, not reasoned about: with the index still in place, deleting
/// `modules/tlock/CHANGELOG.md` ALONE was caught -- as a dangling index link,
/// EXIT=1 -- but deleting the file AND its one index bullet, which is the state
/// of a module added today, gave EXIT=0. So the claim "every module carries a
/// `CHANGELOG.md`" held over 225 of 225 modules as a fact about that morning
/// and not as an invariant, and the one case where a gate is worth having -- a
/// module being added -- was the one case it did not cover. Note that this is
/// now the ONLY thing standing behind that invariant: the index is gone, so
/// there is no dangling-link path that would catch a deleted changelog by
/// accident. A read failure that is not `FileNotFound` fails too: the gate
/// cannot verify what it cannot read, and "skip whatever you could not read" is
/// the exact reflex that produced the hole in the first place. That fix left
/// the same reflex one layer in, which is what (1b) closes: measured on the
/// real tree, truncating `modules/tlock/CHANGELOG.md` to ZERO BYTES gave
/// EXIT=0, because a file that exists satisfied (1), an empty file has no
/// entries for (0) to date, and the index link still resolved. The gate
/// enforced "a file exists", so a module could hold a zero-byte placeholder and
/// read as fully documented.
///
/// WHY THE INDEX CHECKS ARE GONE. Two claims were dropped with the index: that
/// every module changelog is linked from it, and that a `**BREAKING` tag in a
/// module's `Unreleased` section is mirrored in the module's index bullet.
/// Both were real, both were green, and neither had a subject once the index
/// did not exist -- their entire subject was the copy the index made of facts
/// the module files already state. The `BREAKING` mirror is the one worth
/// spelling out, because it is the only thing the index carried that a reader
/// could not get without opening 225 files:
///
///   - `## Unreleased` is by definition not released, so the consumer the index
///     was justified by does not read it. The mirror served a MAINTAINER during
///     the pending window, and for that maintainer it is dominated by asking
///     the tree directly -- `rg -l '\*\*BREAKING' modules/*/CHANGELOG.md`,
///     which returned exactly the 12 modules the index tagged (`bfv`,
///     `coconut`, `cookies`, `dtls`, `fss`, `hpke`, `http`, `saml`,
///     `security-headers`, `snmp`, `tfhe`, `threshold_ecdsa`) at the moment of
///     removal, with no second place to keep in sync.
///   - A check whose only subject is a copy is a closed loop: 12 duplicated
///     lines kept so that one check can notice those same 12 lines went stale.
///     Deleting the copy deletes the drift, and the check with it. That is the
///     opposite of fail-open -- there is no longer a claim that can be silently
///     wrong -- which is why the remnant was not kept half-enforced.
///   - Before deleting, all 225 bullets were checked against the file each
///     pointed at, on the premise that a summary which is not derivable from
///     its target is content and not an index. All 225 were derivable,
///     including every one of the 128 finding-counts they asserted (125 stated
///     verbatim in the target, 3 -- `threshold_ecdsa`, `validate`, `zipstream`
///     -- countable from its entries) and every specific figure they carried
///     (`isis-flood`'s 256, `netconf`'s 159s→0.015s, `bacnet`'s ~15 sites).
///     Zero contradictions. Nothing was lost by deleting it.
///
/// The `**BREAKING` matching rule and its calibration are not reproduced here
/// because nothing matches on it any more; CONVENTIONS §8 keeps the one part
/// that is still live, which is that `BEHAVIOURAL, not breaking` is a third
/// classification and not a synonym for either.
///
/// WHAT (2) COVERS TODAY: nothing. With the index gone the root file carries no
/// `](modules/…/CHANGELOG.md)` link at all, so this loop matches zero times,
/// and that is stated rather than left for someone to discover. It is kept
/// because its subject is not the index but the root file's links, and §8 keeps
/// the root file in the business of naming modules -- a dated tag section says
/// which modules that tag touched. The first such section reintroduces links,
/// and a typo'd module name in one is exactly what this catches. A check that
/// currently matches nothing is not fail-open; it makes no claim that could be
/// silently false, unlike the index checks it outlived.
///
/// WHAT IS DELIBERATELY NOT CHECKED: the module count in the root prose ("the
/// collection grew 77 → 225 modules"). `check-catalog` already pins a module
/// count against `module_list.len`, in the README, which is the one place that
/// fact is owned; a second gate on the same fact in a different file is a
/// second thing to get wrong. Worse, this sentence is release NOTES, not a live
/// count -- once a tag is cut it freezes with the rest of the section, and a
/// check keyed to `module_list.len` would then demand editing released history
/// to keep itself green. That is the shape of a gate people disable.
fn checkChangelog(step: *std.Build.Step, options: std.Build.Step.MakeOptions) anyerror!void {
    _ = options;
    const b = step.owner;
    const io = b.graph.io;
    const root = try b.build_root.handle.readFileAlloc(io, "CHANGELOG.md", b.allocator, .limited(4 * 1024 * 1024));

    var failed = false;

    // (1): every module HAS a changelog, (1b) it is one, (0) its entries are dated.
    for (module_list) |m| {
        const path = b.fmt("modules/{s}/CHANGELOG.md", .{m.name});
        const text = b.build_root.handle.readFileAlloc(io, path, b.allocator, .limited(4 * 1024 * 1024)) catch |err| {
            std.log.err(
                "module '{s}' has no readable {s} ({s}) — every module in `module_list` carries " ++
                    "one (CONVENTIONS.md §8), including a module whose only history is being " ++
                    "created. Copy `modules/_template/CHANGELOG.md` to {s} and fill in its " ++
                    "heading and its dated `New module:` entry. (`modules/_template/` is not in " ++
                    "`module_list` and is not asked for one.)",
                .{ m.name, path, @errorName(err), path },
            );
            failed = true;
            continue;
        };

        // (1b) runs first: (0) reads structure out of this file, so "is it a
        // changelog at all" is the question that has to be answered before it
        // means anything.
        checkChangelogShape(m.name, path, text, &failed);
        checkEntryDates(m.name, path, text, &failed);
    }

    // (2): every module-changelog link in the root file resolves. Driven from
    // the root file's text, which is the only direction that can see a link
    // pointing at nothing. Matches nothing today -- see the doc comment.
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
                "root CHANGELOG.md links `modules/{s}/CHANGELOG.md`, which does not exist",
                .{name},
            );
            failed = true;
        }
    }

    if (failed) return step.fail("changelog gate failed — see errors above", .{});
}

/// Claim (1b): the file at `modules/<m>/CHANGELOG.md` is a changelog, not just
/// a file at that path.
///
/// THE HOLE THIS CLOSES, measured and not reasoned about: with (1) demanding
/// the file, truncating `modules/tlock/CHANGELOG.md` to zero bytes still gave
/// `zig build check-changelog` EXIT=0. Every other claim is written to read
/// structure OUT of this file, so an empty one answers all of them vacuously —
/// no entries to date, and (when the root index still existed) no
/// `## Unreleased` to compare against it while its index link resolved because
/// the file was there. "Exists" and "is a changelog" are different facts and
/// only the first was checked.
///
/// THE RULE: two landmarks, both required.
///
///   1. The first line is a level-1 markdown title (`# `) that NAMES the module.
///   2. The file has an `## Unreleased` section heading.
///
/// CALIBRATED AGAINST THE WHOLE CORPUS BEFORE ADOPTION, which is the lesson the
/// since-removed `**BREAKING` index rule was written from. All 225 files in
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
/// WHY `## Unreleased` IS STILL DEMANDED, AND WHY AN ENTRY UNDER IT IS NOT.
/// This landmark was originally justified by the root index: (3) compared that
/// section, and a file with no heading fell out of the comparison through
/// `orelse continue`, which was the fail-open path itself. That justification
/// died with the index, so the landmark is re-argued rather than inherited. It
/// is kept because it is the second half of "this is a changelog": the heading
/// is where the next entry goes, §8 requires it, and 225/225 carry it — a file
/// with a title and no `## Unreleased` gives an author nowhere to write and is
/// the shape a hand-made stub takes. It is NOT load-bearing for the zero-byte
/// case any more; the title landmark alone catches that, and the two are kept
/// as independent facts rather than one rule doing double duty. A BULLET is
/// deliberately not required even though 225/225 have one today: the moment a
/// tag is cut those bullets move into the release section and the heading
/// legitimately stands empty, and a gate that then demanded an entry would be
/// asking modules to invent one.
///
/// WHAT IS DELIBERATELY NOT CHECKED: the preamble line pointing back at the
/// root `CHANGELOG.md` (226/226 files carry it; it is prose, and it survived
/// the index's removal intact because it points at the root file for "which
/// release tag each entry shipped in" — the release index — and never at the
/// per-module index that was deleted), and any minimum length — a byte count
/// is a proxy for the two facts above, and a worse one.
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
            "{s}: no `## Unreleased` heading — every module changelog has one, and it is where " ++
                "the next entry goes; a file with a title and nowhere to write is the shape a " ++
                "hand-made stub takes. Add the heading (it may stand empty once a tag is cut; " ++
                "what is not allowed is its absence). Module '{s}'; see CONVENTIONS.md §8.",
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
///   - The ROOT file carries no per-entry dates. The date is owned by the
///     module changelog; the root file dates TAGS, not the entries beneath
///     them, and restating an entry date there would be a second place to get
///     it wrong.
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
/// the since-removed `**BREAKING` index rule was written from): all 55
/// existing files after the retrofit — 88 entries, 88 accepted, 0
/// disagreements. Both failure directions were then proven by planting them: a
/// stripped date and a `2026-8-13` / `13-08-2026` malformation each turn this
/// red, naming the file and line.
fn checkEntryDates(name: []const u8, path: []const u8, text: []const u8, failed: *bool) void {
    // The body starts at the first `## ` heading; the preamble above it is the
    // file's title and its pointer back to the root CHANGELOG.md, not entries.
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

/// A module's anchor grade, read from the one line that states it. Both the gate
/// that validates the grade and the fuzz gate that acts on it come through here,
/// so neither can end up reading a different answer than the other.
const AnchorGrade = struct {
    class: u8,
    oracle: []const u8,
    /// The file it was read from, for error messages that name where to fix it.
    path: []const u8,
};

/// Read `**Anchor grade:** class <X> · oracle <Y>` from `modules/<name>/SPEC.md`,
/// or `README.md` for the six modules that have no SPEC.md. Returns null and logs
/// the reason when the line is missing, doubled or malformed -- callers must treat
/// null as a failure, never as "no grade, so nothing applies": a module dropping
/// silently out of an obligation because its grade would not parse is exactly the
/// fail-open shape this gate exists to prevent.
fn moduleAnchorGrade(b: *std.Build, io: std.Io, name: []const u8) ?AnchorGrade {
    const needle = "**Anchor grade:** class ";
    var path = b.fmt("modules/{s}/SPEC.md", .{name});
    b.build_root.handle.access(io, path, .{}) catch {
        path = b.fmt("modules/{s}/README.md", .{name});
    };
    const src = b.build_root.handle.readFileAlloc(io, path, b.allocator, .limited(4 * 1024 * 1024)) catch {
        std.log.err("module '{s}': cannot read {s} for its anchor grade", .{ name, path });
        return null;
    };

    const first = std.mem.indexOf(u8, src, needle) orelse {
        std.log.err(
            "module '{s}': {s} states no anchor grade -- add a line `{s}<A|B|C|D> · oracle " ++
                "<EXTERNAL|REDERIVED|MIXED|SELF|n/a>` saying where its expected values get their " ++
                "authority (see modules/_template/SPEC.md)",
            .{ name, path, needle },
        );
        return null;
    };
    if (std.mem.indexOfPos(u8, src, first + needle.len, needle) != null) {
        std.log.err(
            "module '{s}': {s} states an anchor grade twice -- two copies of one fact is how the " ++
                "repository-level tables this replaced went stale",
            .{ name, path },
        );
        return null;
    }

    const rest = src[first + needle.len ..];
    const line_end = std.mem.indexOfScalar(u8, rest, '\n') orelse rest.len;
    const line = std.mem.trim(u8, rest[0..line_end], " \t\r");
    const sep = " · oracle ";
    const sep_at = std.mem.indexOf(u8, line, sep) orelse {
        std.log.err(
            "module '{s}': anchor grade line in {s} is malformed -- expected `class <X> · oracle <Y>`, got `{s}`",
            .{ name, path, line },
        );
        return null;
    };
    const class = std.mem.trim(u8, line[0..sep_at], " \t");
    if (class.len != 1) {
        std.log.err("module '{s}': anchor class '{s}' is not a single letter ({s})", .{ name, class, path });
        return null;
    }
    return .{
        .class = class[0],
        .oracle = std.mem.trim(u8, line[sep_at + sep.len ..], " \t"),
        .path = path,
    };
}

/// Oracle-provenance gate: every module states, beside its own tests, where the
/// authority of its expected values comes from.
///
/// WHAT IT READS: the one line `moduleAnchorGrade` above parses. CLASS answers
/// "does an external truth exist for this module at all?" and ORACLE answers
/// "where does the test oracle's authority come from?". The vocabulary, and the
/// five things that look like an anchor and are not (a sibling's anchor; reading
/// a foreign source rather than running it; a live test that skips on this host;
/// anchored primitives under unanchored framing; a prose claim of parity), are
/// in `modules/_template/SPEC.md`.
///
/// WHERE THIS LIVED BEFORE, and why it moved on 2026-08-14: two repository-level
/// files, `ANCHORS.tsv` (a grade per module) and `ANCHOR-TASKS.tsv` (the same
/// grade again, plus the work). Everything that went wrong with them went wrong
/// because the fact lived away from the thing it described:
///
///   - Eleven rows where the tasks file had moved past what the grades file
///     still said, closed 2026-08-02..05 against a snapshot regenerated 08-01.
///   - Thirty rows graded SELF in BOTH files while their own NOTE cited the
///     commit that had anchored them -- a check comparing a column against its
///     duplicate is green whenever both copies are wrong the same way.
///   - Nineteen rows whose NOTE said the task had closed while SOURCE still
///     named the tool, so the file's own header claimed twenty open tasks for a
///     week while nineteen of them were finished.
///
/// None of those three can recur: there is one copy now, beside the tests, and a
/// module cannot drift from itself.
///
/// WHAT IT CHECKS: that every module in `module_list` carries exactly one
/// well-formed grade, that CLASS and ORACLE are from the vocabulary, and the
/// pairing rule -- a class A/B module (an outside truth exists) may not grade its
/// oracle `n/a`, and a class C/D module (none exists) must.
///
/// WHAT IT CANNOT CHECK, stated because a green run here is weaker than it looks:
/// whether the grade is TRUE. `EXTERNAL` is a claim about what a test file
/// contains, and only reading the tests settles it. This keeps the claim present,
/// well-formed and self-consistent; it does not audit it.
fn checkAnchors(b: *std.Build, io: std.Io, failed: *bool) !void {
    for (module_list) |m| {
        const grade = moduleAnchorGrade(b, io, m.name) orelse {
            failed.* = true;
            continue;
        };
        if (std.mem.indexOfScalar(u8, "ABCD", grade.class) == null) {
            std.log.err(
                "module '{s}': anchor class '{c}' is not one of A/B/C/D ({s})",
                .{ m.name, grade.class, grade.path },
            );
            failed.* = true;
            continue;
        }
        if (!containsName(&.{ "EXTERNAL", "REDERIVED", "MIXED", "SELF", "n/a" }, grade.oracle)) {
            std.log.err(
                "module '{s}': anchor oracle '{s}' is not one of EXTERNAL/REDERIVED/MIXED/SELF/n/a ({s})",
                .{ m.name, grade.oracle, grade.path },
            );
            failed.* = true;
            continue;
        }

        const faces_out = grade.class == 'A' or grade.class == 'B';
        const na = std.mem.eql(u8, grade.oracle, "n/a");
        if (faces_out and na) {
            std.log.err(
                "module '{s}': class {c} means another implementation can disagree with it, so 'n/a' is not " ++
                    "an answer -- grade the oracle from what the tests contain",
                .{ m.name, grade.class },
            );
            failed.* = true;
        }
        if (!faces_out and !na) {
            std.log.err(
                "module '{s}': class {c} means no outside truth exists for it, so the oracle must be 'n/a', " ++
                    "not '{s}' -- grading a C/D module invents anchor debt that cannot be paid",
                .{ m.name, grade.class, grade.oracle },
            );
            failed.* = true;
        }
    }
}

// ---------------------------------------------------------------------------
// `zig build check-fuzz` — the fuzz-coverage gate.
// ---------------------------------------------------------------------------

/// A module's fuzz exemption, read from the one line that states it:
///
///     **Fuzz exemption:** EMIT-ONLY
///     **Fuzz exemption:** PRE-PARSED via <sibling>
///
/// followed by the argument in prose. It lived in a root-level `FUZZ-EXEMPT.tsv`
/// until 2026-08-14, where it was one row: a repository-level table holding a
/// single fact about a single module, which is the shape the anchor tables had
/// just been retired for. The file's own header had predicted the opposite
/// failure -- "if this file grows past a handful of rows, the derivation is
/// wrong" -- and it never grew.
const FuzzExemption = struct {
    /// `EMIT-ONLY` or `PRE-PARSED`. Validated by the caller, not here, so a
    /// malformed reason is reported against the module rather than swallowed.
    reason: []const u8,
    /// The sibling named after `via`, for `PRE-PARSED`. Empty for `EMIT-ONLY`.
    sibling: []const u8,
    /// Everything after the line up to the next `## ` heading -- the argument
    /// the exemption rests on, which rule 5 requires to be present.
    evidence: []const u8,
    path: []const u8,
};

/// Read a module's fuzz exemption, or null when it claims none.
///
/// A module with NO exemption is the normal case and null is the right answer
/// for it: the caller then holds it to the obligation, which is the safe
/// direction. A module with a PRESENT but malformed line is a different thing
/// entirely and must not read as "no exemption" -- that would be a silent pass
/// for whoever typoed it, so it is reported and treated as a failure.
fn moduleFuzzExemption(b: *std.Build, io: std.Io, name: []const u8, failed: *bool) ?FuzzExemption {
    const needle = "**Fuzz exemption:** ";
    var path = b.fmt("modules/{s}/SPEC.md", .{name});
    b.build_root.handle.access(io, path, .{}) catch {
        path = b.fmt("modules/{s}/README.md", .{name});
    };
    const src = b.build_root.handle.readFileAlloc(io, path, b.allocator, .limited(4 * 1024 * 1024)) catch return null;

    const at = std.mem.indexOf(u8, src, needle) orelse return null;
    if (std.mem.indexOfPos(u8, src, at + needle.len, needle) != null) {
        std.log.err("module '{s}': {s} states a fuzz exemption twice", .{ name, path });
        failed.* = true;
        return null;
    }

    const rest = src[at + needle.len ..];
    const line_end = std.mem.indexOfScalar(u8, rest, '\n') orelse rest.len;
    const line = std.mem.trim(u8, rest[0..line_end], " \t\r");

    var reason = line;
    var sibling: []const u8 = "";
    const via = " via ";
    if (std.mem.indexOf(u8, line, via)) |v| {
        reason = std.mem.trim(u8, line[0..v], " \t");
        sibling = std.mem.trim(u8, line[v + via.len ..], " \t`");
    }

    const after = rest[line_end..];
    const stop = std.mem.indexOf(u8, after, "\n## ") orelse after.len;
    return .{
        .reason = reason,
        .sibling = sibling,
        .evidence = std.mem.trim(u8, after[0..stop], " \t\r\n"),
        .path = path,
    };
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
///   1. its own SPEC.md grades it anchor class **A** (wire / interop format — other
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
/// forces a non-A/B module's oracle grade to `n/a`, which deletes the module's
/// own recorded external anchor. You cannot buy fuzz exemption without paying in
/// anchor provenance, in the file a reader of that module actually opens. That is the difference between this and the earlier
/// "external anchor ⇒ vector file" proxy, which was measured and rejected: this
/// gate does not infer coverage from bookkeeping, it infers OBLIGATION from
/// bookkeeping that is already independently policed, and then checks coverage
/// against the code.
///
/// A module's own `**Fuzz exemption:**` line exists for the residue — cases where condition 2 is true
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
/// The declared-target vocabulary for `meta.targets` (CONVENTIONS.md §4).
/// Each tag is a real, checkable claim.
const PortableTarget = enum {
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

    fn label(self: PortableTarget) []const u8 {
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
const cross_compile_targets = [_]PortableTarget{ .wasm32, .windows, .linux32 };

/// One (module, target) pair `check-portable` is responsible for -- either
/// because the module declares that target in `meta.targets`, or (with
/// `-Dportable-measure-all`) because every pair is being probed regardless of
/// declaration.
const PortablePair = struct { module: []const u8, target: PortableTarget };

/// A module's full declared set, as read from `meta.targets` -- the raw
/// material `check-portable-table`'s generator groups into rows. Distinct
/// from `PortablePair` (one declared (module, target) pair each): this is
/// one entry per MODULE, carrying its whole declared set including the
/// mandatory `.linux64`.
const PortableDecl = struct { module: []const u8, targets: []const PortableTarget };

/// A module's `meta.targets` declaration, or the reason it could not be read.
/// `err == null` iff `targets` is a valid, non-empty, duplicate-free set that
/// includes `.linux64` (CONVENTIONS.md §4). Read from the module's own source
/// because that block is the canonical declaration; a duplicate list in this
/// file would be a second thing to keep in step (this replaces the old
/// `declaresAnyPlatform`, which only ever answered "is it `.any`").
const ParsedTargets = struct {
    targets: []const PortableTarget = &.{},
    err: ?[]const u8 = null,
};

fn parseMetaTargets(b: *std.Build, io: std.Io, name: []const u8) ParsedTargets {
    const path = b.fmt("modules/{s}/src/root.zig", .{name});
    const src = b.build_root.handle.readFileAlloc(io, path, b.allocator, .limited(4 * 1024 * 1024)) catch |err| {
        return .{ .err = b.fmt("cannot read {s}: {t}", .{ path, err }) };
    };
    const meta_idx = std.mem.indexOf(u8, src, "pub const meta") orelse
        return .{ .err = "has no `pub const meta` block" };
    const meta_end = std.mem.indexOfPos(u8, src, meta_idx, "\n};") orelse src.len;
    const block = src[meta_idx..meta_end];

    // Match the compound literal, not bare `.targets` -- a doc comment can
    // say `` `meta.targets = .{.wasm32}` `` in prose ahead of the real field
    // (`metaDepsFromRoot` has the identical guard for `.deps`, for the same
    // reason: a bare-word search would land on the prose instead).
    const targets_idx = std.mem.indexOf(u8, block, ".targets = .{") orelse
        return .{ .err = "`meta` block has no `.targets = .{...}` field" };
    const open = std.mem.indexOfScalarPos(u8, block, targets_idx, '{').?;
    const close = std.mem.indexOfScalarPos(u8, block, open, '}') orelse
        return .{ .err = "`.targets` list has no closing `}`" };
    const inner = block[open + 1 .. close];

    var out: std.ArrayList(PortableTarget) = .empty;
    var i: usize = 0;
    while (std.mem.indexOfScalarPos(u8, inner, i, '.')) |dot| {
        var j = dot + 1;
        while (j < inner.len and (std.ascii.isAlphanumeric(inner[j]) or inner[j] == '_')) j += 1;
        const tok = inner[dot + 1 .. j];
        i = j;
        if (tok.len == 0) continue;
        const t = std.meta.stringToEnum(PortableTarget, tok) orelse
            return .{ .err = b.fmt("meta.targets names unknown target `.{s}`", .{tok}) };
        for (out.items) |seen| if (seen == t)
            return .{ .err = b.fmt("meta.targets lists `.{s}` twice", .{tok}) };
        out.append(b.allocator, t) catch @panic("OOM");
    }
    if (out.items.len == 0) return .{ .err = "meta.targets is empty" };
    for (out.items) |t| {
        if (t == .linux64) return .{ .targets = out.toOwnedSlice(b.allocator) catch @panic("OOM") };
    }
    return .{ .err = "meta.targets does not include `.linux64` -- every module claims the collection's baseline target (CONVENTIONS.md §4)" };
}

/// Data file listing `check-portable`'s known-failure baseline: one
/// `<module> TAB <target> TAB <reason>` row per (module, target) pair that
/// the module DECLARES in `meta.targets` but whose test compile is currently
/// red, with the reason taken from the actual compiler error (never
/// invented). See `scripts/portable-known-failures.tsv`'s own header for the
/// full contract. Keyed by (module, target), not by module alone (as of this
/// schema) -- a module can declare several targets and fail only some of
/// them.
const portable_baseline_path = "scripts/portable-known-failures.tsv";

/// A parsed `scripts/portable-known-failures.tsv` row.
const PortableBaselineEntry = struct { module: []const u8, target: PortableTarget, reason: []const u8 };

/// Composite key for the (module, target) hash maps below -- a plain string
/// join is enough since neither half of the pair can itself contain a NUL.
fn portablePairKey(b: *std.Build, module: []const u8, target: PortableTarget) []const u8 {
    return b.fmt("{s}\x00{s}", .{ module, target.label() });
}

/// Parse `scripts/portable-known-failures.tsv`: blank lines and `#`-comment
/// lines are skipped, every other line is `<module>\t<target>\t<reason>` with
/// a non-empty reason and a `target` naming one of `cross_compile_targets`.
/// Malformed rows are reported through `failed` rather than silently skipped
/// -- a row this gate cannot parse is a row it cannot enforce, which is
/// exactly the kind of silent hole `check-changelog`'s "exists != is a
/// changelog" lesson says not to leave.
fn parsePortableBaseline(
    b: *std.Build,
    io: std.Io,
    failed: *bool,
) []const PortableBaselineEntry {
    const src = b.build_root.handle.readFileAlloc(io, portable_baseline_path, b.allocator, .limited(1024 * 1024)) catch |err| {
        std.log.err("check-portable: cannot read {s}: {t}", .{ portable_baseline_path, err });
        failed.* = true;
        return &.{};
    };
    var entries: std.ArrayList(PortableBaselineEntry) = .empty;
    var seen = std.StringHashMap(void).init(b.allocator);
    var line_no: usize = 0;
    var lines = std.mem.splitScalar(u8, src, '\n');
    while (lines.next()) |raw_line| {
        line_no += 1;
        const line = std.mem.trim(u8, raw_line, " \t\r");
        if (line.len == 0 or line[0] == '#') continue;
        const tab1 = std.mem.indexOfScalar(u8, line, '\t') orelse {
            std.log.err("{s}:{d}: expected `<module>\\t<target>\\t<reason>`, no tab found: {s}", .{ portable_baseline_path, line_no, line });
            failed.* = true;
            continue;
        };
        const after1 = line[tab1 + 1 ..];
        const tab2 = std.mem.indexOfScalar(u8, after1, '\t') orelse {
            std.log.err(
                "{s}:{d}: expected `<module>\\t<target>\\t<reason>`, only one tab found: {s}",
                .{ portable_baseline_path, line_no, line },
            );
            failed.* = true;
            continue;
        };
        const module = std.mem.trim(u8, line[0..tab1], " \t");
        const target_str = std.mem.trim(u8, after1[0..tab2], " \t");
        const reason = std.mem.trim(u8, after1[tab2 + 1 ..], " \t");
        if (module.len == 0) {
            std.log.err("{s}:{d}: empty module name", .{ portable_baseline_path, line_no });
            failed.* = true;
            continue;
        }
        const target = std.meta.stringToEnum(PortableTarget, target_str) orelse {
            std.log.err("{s}:{d}: unknown target '{s}'", .{ portable_baseline_path, line_no, target_str });
            failed.* = true;
            continue;
        };
        if (target == .linux64) {
            std.log.err(
                "{s}:{d}: '.linux64' is never cross-compiled by this gate and cannot appear in the baseline",
                .{ portable_baseline_path, line_no },
            );
            failed.* = true;
            continue;
        }
        if (reason.len == 0) {
            std.log.err(
                "{s}:{d}: module '{s}' target '{s}' has no reason -- an entry nobody can argue with is one nobody will revisit " ++
                    "(see CONVENTIONS.md's `global-alloc-ok:` rule for why a reason is required)",
                .{ portable_baseline_path, line_no, module, target_str },
            );
            failed.* = true;
            continue;
        }
        const key = portablePairKey(b, module, target);
        if (seen.contains(key)) {
            std.log.err("{s}:{d}: (module, target) pair '{s}'/'{s}' is listed twice", .{ portable_baseline_path, line_no, module, target_str });
            failed.* = true;
            continue;
        }
        seen.put(key, {}) catch @panic("OOM");
        entries.append(b.allocator, .{ .module = module, .target = target, .reason = reason }) catch @panic("OOM");
    }
    return entries.items;
}

/// `zig build check-portable`'s baseline verdict. See the long comment at its
/// call site (in `build()`) for why this is a subprocess re-invocation rather
/// than a plain `dependOn` of the `portable-<name>-<target>` compile steps:
/// the whole point of a baseline is that a KNOWN failure must not turn the
/// gate red, and the build-step graph has no way to swallow a dependency's
/// failure short of not depending on it.
///
/// Verdict per (module, target) pair, compared against
/// `scripts/portable-known-failures.tsv`:
///
///   pass, not listed   — fine, the common case.
///   fail, listed        — fine, an accounted-for baseline entry.
///   fail, NOT listed    — gate fails: a new/unlisted regression.
///   pass, listed        — gate fails: a STALE entry. Without this half the
///                         list can only ever grow, which is exactly how a
///                         baseline rots into a lie nobody re-reads.
/// Best-effort slice of `text` (the sweep subprocess's combined stdout+stderr)
/// covering (module, target) pair's own compile: from just after the previous
/// `failed command:` line to the end of the `failed command:` line that names
/// `--name portable-<name>-<target>`. `zig build`'s own diagnostics for a
/// failed `Compile` step are printed immediately before the `failed command:`
/// line that names it, which is what makes this work without parsing the tree
/// output. NOT exact under concurrent compilation (`zig build` interleaves
/// output from parallel jobs by line, so a neighbour's diagnostic can land in
/// the slice) -- it exists to save a round trip to
/// `zig build portable-<name>-<target>` by hand, not to be machine-parsed
/// itself.
fn findModuleErrorBlock(b: *std.Build, text: []const u8, module: []const u8, target: PortableTarget) ?[]const u8 {
    const marker = b.fmt("--name portable-{s}-{s} ", .{ module, target.label() });
    const marker_idx = std.mem.indexOf(u8, text, marker) orelse return null;
    const start: usize = if (std.mem.lastIndexOf(u8, text[0..marker_idx], "failed command:")) |prev|
        (std.mem.indexOfScalarPos(u8, text, prev, '\n') orelse prev) + 1
    else
        0;
    const end = std.mem.indexOfScalarPos(u8, text, marker_idx, '\n') orelse text.len;
    if (start >= end) return null;
    return text[start..end];
}

/// Splits a `portable-<name>-<target>` step name's tail (everything after the
/// `portable-` prefix has already been stripped by the caller) back into
/// `(module, target)` by matching one of the fixed, hyphen-free target
/// labels as a suffix -- the module half may itself contain hyphens
/// (`aaa-gate`, `security-headers`), so the split has to anchor on the KNOWN
/// side.
fn parsePortableStepTail(rest: []const u8) ?PortablePair {
    inline for (@typeInfo(PortableTarget).@"enum".fields) |f| {
        const t: PortableTarget = @enumFromInt(f.value);
        if (t == .linux64) continue; // never a suffix; no compile step exists for it
        const suffix = "-" ++ f.name;
        if (std.mem.endsWith(u8, rest, suffix)) {
            return .{ .module = rest[0 .. rest.len - suffix.len], .target = t };
        }
    }
    return null;
}

const PortableBaselineStep = struct {
    step: std.Build.Step,
    /// Every (module, target) pair this gate is responsible for -- computed
    /// once in `build()` so this can't drift from which pairs actually got a
    /// `portable-<name>-<target>` step.
    pairs: []const PortablePair,
    /// Human-readable messages for modules whose `meta.targets` could not be
    /// read at all (missing block/field, malformed, or missing the mandatory
    /// `.linux64`) -- these modules contribute NO entries to `pairs` (nothing
    /// to sweep), so without this list a broken declaration would silently
    /// vanish from the gate instead of failing it.
    decl_errors: []const []const u8,

    fn make(step: *std.Build.Step, options: std.Build.Step.MakeOptions) anyerror!void {
        _ = options;
        const self: *PortableBaselineStep = @fieldParentPtr("step", step);
        const b = step.owner;
        const io = b.graph.io;

        var failed = false;
        for (self.decl_errors) |e| {
            std.log.err("check-portable: {s}", .{e});
            failed = true;
        }

        const baseline = parsePortableBaseline(b, io, &failed);

        if (self.pairs.len == 0) {
            // Nothing declared a cross-compiled target, or every declaration
            // errored above -- still worth its own line so a green run
            // because there was nothing to sweep is distinguishable from one
            // that actually swept something.
            std.log.info("check-portable: 0 (module, target) pairs declared -- nothing to sweep", .{});
            if (failed) return step.fail("check-portable: declaration errors -- see errors above", .{});
            return;
        }

        var argv: std.ArrayList([]const u8) = .empty;
        try argv.append(b.allocator, b.graph.zig_exe);
        try argv.append(b.allocator, "build");
        for (self.pairs) |p| {
            try argv.append(b.allocator, b.fmt("portable-{s}-{s}", .{ p.module, p.target.label() }));
        }
        // Reuse exactly the cache this build is already using, so the
        // subprocess sees a warm cache instead of recompiling std for each
        // cross-compiled target from scratch. Omitted when the outer build
        // used the ambient default (a null `.path` means "relative to cwd",
        // which the subprocess's own `cwd` below already reproduces).
        if (b.cache_root.path) |p| {
            try argv.append(b.allocator, "--cache-dir");
            try argv.append(b.allocator, p);
        }
        if (b.graph.global_cache_root.path) |p| {
            try argv.append(b.allocator, "--global-cache-dir");
            try argv.append(b.allocator, p);
        }
        // Cap the subprocess's OWN internal concurrency. Left at the default
        // (all cores), ~195 concurrent wasm32 LLVM-backend compiles under
        // memory pressure produce zig build-runner failures with NO
        // `file:line: error:` diagnostic at all -- indistinguishable, from
        // this step's own summary parsing, from a real compile failure.
        // Measured 2026-08-18 on this host (8 cores, ~2 GiB free RAM, swap
        // full): 71 modules that compile cleanly in isolation came back
        // "failure" this way under unbounded `-j`; `-j4` reproduced the
        // isolated (correct) result. `scripts/test.sh` uses `-j1` elsewhere in
        // this repo, but for a different reason (serializing live-peer RUN
        // steps, not compile memory pressure) -- `-j4` here is this step's
        // own bound, not a reuse of that one.
        try argv.append(b.allocator, "-j4");
        try argv.append(b.allocator, "--summary");
        try argv.append(b.allocator, "all");

        const result = std.process.run(b.allocator, io, .{
            .argv = argv.items,
            .cwd = .{ .dir = b.build_root.handle },
            .stdout_limit = .unlimited,
            .stderr_limit = .unlimited,
        }) catch |err| {
            std.log.err("check-portable: could not run the cross-compile sweep: {t}", .{err});
            return step.fail("check-portable: subprocess spawn failed", .{});
        };
        defer b.allocator.free(result.stdout);
        defer b.allocator.free(result.stderr);

        // Both streams, concatenated: `--summary all`'s step-status lines are
        // stdout, and a module's own compile errors are stderr, but only the
        // former is parsed below -- this is just so a human reading the
        // logged text after a failure sees both.
        var combined: std.ArrayList(u8) = .empty;
        try combined.appendSlice(b.allocator, result.stdout);
        try combined.appendSlice(b.allocator, result.stderr);

        // Top-level step-status lines sit at column 0: `portable-http-wasm32
        // success` / `... cached` / `... failure` / `... transitive failure`
        // / `... skipped` / `... skipped (not enough memory)`. Source of
        // truth for that exact vocabulary: zig 0.16's
        // `lib/compiler/build_runner.zig`, the `StepNames.write`-shaped
        // switch on `Step.State` -- `.success` prints `cached` when
        // `result_cached` (a step the runner determined, from a PRIOR run,
        // needed no rebuild -- still a pass, not "not run") or `success`
        // otherwise; `.dependency_failure` prints `transitive failure`;
        // `.skipped`/`.skipped_oom` print `skipped`/`skipped (not enough
        // memory)`.
        //
        // ⭐ MEASURED 2026-08-18: an earlier version of this parser accepted
        // only a bare `success` suffix as a pass. Rerun against an ALREADY-WARM
        // cache (the normal case once `check-portable` has run once), every
        // module printed `cached` instead, and the gate reported "0 pass, 115
        // NEW failure" -- 115 modules that compile cleanly in isolation,
        // reported as regressions purely because the cache had already done
        // the work. This is a distinct failure mode from the cache-corruption
        // trap (no missing `file:line: error:` diagnostic; the subprocess
        // genuinely succeeded) but shares the same symptom -- a "failure" this
        // step itself manufactured, not one the compiler reported.
        //
        // `skipped`/`skipped (not enough memory)` are neither a pass nor a
        // compiler-reported failure -- the runner chose not to attempt the
        // step at all (`skipped_oom` specifically means the runner's own
        // memory-pressure heuristic declined to run it). Recording those as
        // `.inconclusive` rather than folding them into "fail" keeps a
        // memory-constrained host from manufacturing baseline-drift errors
        // the same way the `cached`-as-failure bug did.
        const Verdict = enum { passed, failed, inconclusive };
        var status = std.StringHashMap(Verdict).init(b.allocator);
        var it = std.mem.splitScalar(u8, combined.items, '\n');
        while (it.next()) |raw_line| {
            if (raw_line.len == 0 or raw_line[0] == ' ' or raw_line[0] == '+' or raw_line[0] == '|') continue;
            const prefix = "portable-";
            if (!std.mem.startsWith(u8, raw_line, prefix)) continue;
            const rest = raw_line[prefix.len..];
            const sp = std.mem.indexOfScalar(u8, rest, ' ') orelse continue;
            const tail = rest[0..sp];
            const pair = parsePortableStepTail(tail) orelse continue;
            const suffix = std.mem.trim(u8, rest[sp + 1 ..], " \r");
            const verdict: Verdict = if (std.mem.eql(u8, suffix, "success") or std.mem.eql(u8, suffix, "cached"))
                .passed
            else if (std.mem.startsWith(u8, suffix, "skipped"))
                .inconclusive
            else
                .failed; // "failure", "transitive failure", or anything not yet invented
            status.put(portablePairKey(b, pair.module, pair.target), verdict) catch @panic("OOM");
        }

        var baseline_by_pair = std.StringHashMap([]const u8).init(b.allocator);
        for (baseline) |e| baseline_by_pair.put(portablePairKey(b, e.module, e.target), e.reason) catch @panic("OOM");

        var n_ok: usize = 0;
        var n_known_fail: usize = 0;
        var n_new_fail: usize = 0;
        var n_stale: usize = 0;
        var n_inconclusive: usize = 0;
        for (self.pairs) |p| {
            const key = portablePairKey(b, p.module, p.target);
            const verdict = status.get(key) orelse {
                std.log.err(
                    "check-portable: no `portable-{s}-{s}` line in the sweep output -- was it built?",
                    .{ p.module, p.target.label() },
                );
                failed = true;
                continue;
            };
            const listed_reason = baseline_by_pair.get(key);
            switch (verdict) {
                .inconclusive => {
                    // The runner skipped this step (commonly `skipped (not
                    // enough memory)` under host memory pressure) rather than
                    // actually attempting the compile. This is NOT evidence of
                    // either a pass or a failure -- counting it as either would
                    // make the gate's verdict depend on host load rather than
                    // on the code, which is exactly the trap this whole step
                    // exists to avoid falling into (see the `cached`-as-failure
                    // note above). Fails the gate so it gets re-run rather than
                    // silently accepted or silently blamed on the module.
                    n_inconclusive += 1;
                    std.log.err(
                        "check-portable: '{s}'/'{s}' was SKIPPED by the build runner (not attempted -- commonly a host " ++
                            "memory-pressure decision, not a compiler verdict) -- re-run rather than trusting this result",
                        .{ p.module, p.target.label() },
                    );
                    failed = true;
                },
                .passed => if (listed_reason == null) {
                    n_ok += 1;
                } else {
                    n_stale += 1;
                    std.log.err(
                        "check-portable: '{s}'/'{s}' is listed in {s} (\"{s}\") but now PASSES -- stale baseline " ++
                            "entry, remove the row",
                        .{ p.module, p.target.label(), portable_baseline_path, listed_reason.? },
                    );
                    failed = true;
                },
                .failed => if (listed_reason != null) {
                    n_known_fail += 1;
                } else {
                    n_new_fail += 1;
                    std.log.err(
                        "check-portable: '{s}'/'{s}' fails to compile and is not in {s} -- either fix it or add a " ++
                            "baseline entry naming the real compiler error",
                        .{ p.module, p.target.label(), portable_baseline_path },
                    );
                    // Surface the actual diagnostic, not just the pair --
                    // otherwise a red gate tells a developer WHICH pair
                    // without WHY, and they are back to running
                    // `zig build portable-<name>-<target>` by hand to find
                    // out. `result.stderr` (folded into `combined` above) is
                    // where the compiler's own `file:line: error:` text
                    // lives; print the pair's own slice of it rather than the
                    // whole multi-hundred-line sweep.
                    if (findModuleErrorBlock(b, combined.items, p.module, p.target)) |block| {
                        std.log.err("check-portable: '{s}'/'{s}' compiler output:\n{s}", .{ p.module, p.target.label(), block });
                    }
                    failed = true;
                },
            }
        }

        // Silent on success, like every sibling gate here: `scripts/test.sh`
        // treats ANY stderr from a check step as a failure, precisely so a
        // step cannot exit 0 while its own output says otherwise. A summary
        // printed unconditionally turns that protection into a false alarm.
        if (failed) {
            std.log.warn(
                "check-portable: {d} (module, target) pair(s) swept -- {d} pass, {d} known-failure (baseline), {d} NEW failure, {d} STALE baseline entr(y/ies), {d} SKIPPED (inconclusive)",
                .{ self.pairs.len, n_ok, n_known_fail, n_new_fail, n_stale, n_inconclusive },
            );
            return step.fail("check-portable: baseline drift -- see errors above", .{});
        }
    }
};

/// README.md markers `PortableTableStep` locates the generated table
/// between. Everything from just after the begin marker to just before the
/// end marker is fully owned by the generator -- both are regenerated
/// verbatim on every run, so no hand-added blank line or trailing space in
/// that span can ever survive a `gen-portable-table` run to cause a diff
/// `check-portable-table` cannot explain.
const portable_table_begin_marker = "<!-- BEGIN GENERATED: check-portable-table (source: build.zig; regenerate with `zig build gen-portable-table`; do not hand-edit) -->";
const portable_table_end_marker = "<!-- END GENERATED: check-portable-table -->";

/// `zig build check-portable-table` (verify) / `zig build gen-portable-table`
/// (write) — renders the README.md "Portability" table from the same two
/// sources `check-portable` itself reads (see the long comment at both
/// steps' call site in `build()`), then either diffs it against what is
/// checked in (`write = false`, fails on any difference) or writes it
/// (`write = true`).
///
/// SHAPE OF THE TABLE, AND WHY NOT ALL 228 MODULES. Every module claims
/// `.linux64` -- repeating "linux64: claimed, tested" on 228 rows would
/// assert nothing a reader does not already know from the collection's own
/// bar (CONVENTIONS.md §6/§7). The table instead lists only the modules that
/// declare a target BEYOND `.linux64` -- the ~40 (module, target) pairs
/// `check-portable` actually sweeps -- because that is where the claimed/
/// verified distinction this whole schema exists for actually lives. A
/// blank cell (never claimed) and a `known-failing` cell (claimed, declared,
/// currently broken, tracked in the baseline) are deliberately different
/// strings: collapsing them back into one signal is the exact bug this
/// campaign spent the day removing (CONVENTIONS.md §4's `meta.targets`
/// intro).
const PortableTableStep = struct {
    step: std.Build.Step,
    /// Every module's full declared set (`portable_decls` in `build()`),
    /// sorted by module name so row order does not depend on hash-map
    /// iteration.
    decls: []const PortableDecl,
    /// Same list `check-portable` itself fails on -- a module whose
    /// `meta.targets` could not be read makes the table's data untrustworthy,
    /// not just incomplete, so this step fails on it too rather than quietly
    /// omitting the module.
    decl_errors: []const []const u8,
    /// `false` = verify (fails the build if README.md disagrees with the
    /// freshly rendered table); `true` = write the rendered table into
    /// README.md.
    write: bool,

    fn make(step: *std.Build.Step, options: std.Build.Step.MakeOptions) anyerror!void {
        _ = options;
        const self: *PortableTableStep = @fieldParentPtr("step", step);
        const b = step.owner;
        const io = b.graph.io;
        const verb = if (self.write) "gen-portable-table" else "check-portable-table";

        var failed = false;
        for (self.decl_errors) |e| {
            std.log.err("{s}: {s}", .{ verb, e });
            failed = true;
        }
        const baseline = parsePortableBaseline(b, io, &failed);
        if (failed) {
            return step.fail(
                "{s}: cannot generate the table -- fix the meta.targets/baseline errors above (see `zig build check-portable`)",
                .{verb},
            );
        }

        var baseline_by_pair = std.StringHashMap([]const u8).init(b.allocator);
        for (baseline) |e| baseline_by_pair.put(portablePairKey(b, e.module, e.target), e.reason) catch @panic("OOM");

        const body = renderPortableTable(b, self.decls, baseline_by_pair) catch @panic("OOM");

        const readme_path = "README.md";
        const readme = b.build_root.handle.readFileAlloc(io, readme_path, b.allocator, .limited(4 * 1024 * 1024)) catch |err| {
            std.log.err("{s}: cannot read {s}: {t}", .{ verb, readme_path, err });
            return step.fail("{s}: cannot read {s}", .{ verb, readme_path });
        };

        const content_start = (std.mem.indexOf(u8, readme, portable_table_begin_marker) orelse {
            std.log.err("{s}: {s} has no `{s}` marker", .{ verb, readme_path, portable_table_begin_marker });
            return step.fail("{s}: begin marker missing from {s}", .{ verb, readme_path });
        }) + portable_table_begin_marker.len;
        const end_idx = std.mem.indexOfPos(u8, readme, content_start, portable_table_end_marker) orelse {
            std.log.err("{s}: {s} has a begin marker but no matching `{s}` after it", .{ verb, readme_path, portable_table_end_marker });
            return step.fail("{s}: end marker missing from {s}", .{ verb, readme_path });
        };

        const new_readme = std.mem.concat(b.allocator, u8, &.{ readme[0..content_start], "\n", body, "\n", readme[end_idx..] }) catch @panic("OOM");

        if (self.write) {
            if (std.mem.eql(u8, new_readme, readme)) {
                std.log.info("gen-portable-table: {s} already up to date", .{readme_path});
                return;
            }
            b.build_root.handle.writeFile(io, .{ .sub_path = readme_path, .data = new_readme }) catch |err| {
                std.log.err("gen-portable-table: cannot write {s}: {t}", .{ readme_path, err });
                return step.fail("gen-portable-table: write failed", .{});
            };
            std.log.info("gen-portable-table: {s} updated", .{readme_path});
            return;
        }

        if (!std.mem.eql(u8, new_readme, readme)) {
            std.log.err(
                "check-portable-table: {s}'s generated Portability table is STALE against meta.targets / {s} -- " ++
                    "run `zig build gen-portable-table` and commit the result",
                .{ readme_path, portable_baseline_path },
            );
            return step.fail("check-portable-table: stale table in {s}", .{readme_path});
        }
    }
};

/// Renders the body that goes between the two `portable_table_*_marker`
/// lines: prose (with every number computed here, never typed) followed by
/// one row per module that declares a target beyond `.linux64`.
fn renderPortableTable(
    b: *std.Build,
    decls: []const PortableDecl,
    baseline_by_pair: std.StringHashMap([]const u8),
) ![]const u8 {
    var out: std.Io.Writer.Allocating = .init(b.allocator);
    const w = &out.writer;

    var rows: std.ArrayList(PortableDecl) = .empty;
    var n_pairs: usize = 0;
    var n_pass: usize = 0;
    var n_fail: usize = 0;
    for (decls) |d| {
        if (d.targets.len <= 1) continue; // `.linux64` only -- nothing to show
        try rows.append(b.allocator, d);
        for (d.targets) |t| {
            if (t == .linux64) continue;
            n_pairs += 1;
            if (baseline_by_pair.contains(portablePairKey(b, d.module, t))) n_fail += 1 else n_pass += 1;
        }
    }

    try w.print(
        "### Portability — claimed vs. verified\n\n" ++
            "Every one of the {d} modules above claims `.linux64` (Linux, amd64 or arm64) — the " ++
            "collection's mandatory baseline (CONVENTIONS.md §4), and the one target actually " ++
            "**run**, not merely compiled: the CI matrix executes every module's tests in " ++
            "`ReleaseSafe`, `ReleaseFast` and `-Dstrict-debug`, plus a separate arm64 lane. That " ++
            "claim is not repeated below for all {d} modules — a linux64-only module has nothing " ++
            "further to show here.\n\n" ++
            "{d} of them additionally claim a cross-compile target in `meta.targets` " ++
            "(CONVENTIONS.md §4). `zig build check-portable` *compiles* (never runs — none of " ++
            "these targets has a host to run on here) each declared pair's test binary and " ++
            "checks the result against " ++
            "[`scripts/portable-known-failures.tsv`](scripts/portable-known-failures.tsv): of " ++
            "{d} declared pairs, {d} currently compile clean and {d} are known-failing, tracked " ++
            "there with the real compiler error rather than silently dropped.\n\n" ++
            "**A blank cell means the module never claimed that target.** That is a different " ++
            "fact from a `known-failing` cell next to it — one is an absent claim, the other is " ++
            "a claim currently broken and tracked — and this table exists so the two are never " ++
            "shown as the same thing.\n\n" ++
            "**A row states that the module compiles for that target. It does not state that a " ++
            "binary containing the module links for it.** Link-time reach limits are a property " ++
            "of the consuming binary's total text size, not of any single module: on 32-bit MIPS " ++
            "a branch's `PC16` fixup reaches ±128 KB, and a large enough consumer overruns it no " ++
            "matter which modules it picked. What that looks like, and what to do about it, is " ++
            "under *Consumer gotchas* below.\n\n",
        .{ module_list.len, module_list.len, rows.items.len, n_pairs, n_pass, n_fail },
    );

    try w.writeAll("| Module | linux32 | windows | wasm32 |\n|---|---|---|---|\n");
    for (rows.items) |d| {
        // Deliberately NOT `[`name`](modules/name/README.md)` -- that is the
        // exact needle `catalogRowNeedle` (in `checkCatalog`) searches the
        // whole README for to locate a module's REAL catalog row further
        // down the file; reusing it here would make `indexOf` find this
        // table's row first and feed `readmeDepsCell` the wrong line. Plain
        // backticks name the module without colliding with that needle.
        try w.print("| `{s}` |", .{d.module});
        inline for (.{ PortableTarget.linux32, PortableTarget.windows, PortableTarget.wasm32 }) |t| {
            var declared = false;
            for (d.targets) |dt| {
                if (dt == t) {
                    declared = true;
                    break;
                }
            }
            if (!declared) {
                try w.writeAll(" — |");
            } else if (baseline_by_pair.contains(portablePairKey(b, d.module, t))) {
                try w.writeAll(" known-failing |");
            } else {
                try w.writeAll(" compiles |");
            }
        }
        try w.writeAll("\n");
    }

    return out.toOwnedSlice();
}

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

    var failed = false;
    var n_obligated: usize = 0;
    var n_covered: usize = 0;
    var n_exempt: usize = 0;
    var n_failing: usize = 0;
    var n_harnesses: usize = 0;

    for (module_list) |m| {
        const scan = try scanModuleForFuzz(b, io, m.name);
        n_harnesses += scan.harnesses;

        // `moduleAnchorGrade` logs why it could not read a grade. Repeated as a
        // failure here rather than skipped, so a module cannot dodge THIS gate by
        // having an unreadable class.
        const grade = moduleAnchorGrade(b, io, m.name) orelse {
            std.log.err(
                "module '{s}': check-fuzz cannot tell whether foreign bytes are its truth without an anchor class",
                .{m.name},
            );
            failed = true;
            continue;
        };
        const faces_outside = grade.class == 'A' or grade.class == 'B';
        if (!faces_outside or scan.surface_files == 0) continue;

        n_obligated += 1;
        if (scan.harnesses > 0) {
            n_covered += 1;
            continue;
        }
        if (moduleFuzzExemption(b, io, m.name, &failed) != null) {
            n_exempt += 1;
            continue;
        }
        n_failing += 1;
        std.log.err(
            "module '{s}' is CLASS {c} and exposes a byte-accepting public API in {d} source file(s), " ++
                "but modules/{s}/src/ contains no `testing.fuzz(` harness — so every repo-wide sweep " ++
                "skips it and it looks covered from outside. Add a harness on the decode entry point, " ++
                "or state a justified `**Fuzz exemption:**` in its SPEC.md",
            .{ m.name, grade.class, scan.surface_files, m.name },
        );
        failed = true;
    }

    try checkFuzzExempt(b, io, &failed);

    // Printed only when something is wrong, and printed as a WARNING beside the
    // errors it summarises. Two reasons, both learned on 2026-08-14 when this
    // step was first wired into `scripts/test.sh`:
    //
    //   - `std.log` writes to stderr, and the driver treats a step that exits 0
    //     while writing to stderr as a failure -- the rule that catches tools
    //     which fail quietly. A gate chatting on success breaks it. The other
    //     four gates say nothing when they pass, and now so does this one.
    //   - `n_failing` counts only the missing-harness case, so on a run that
    //     failed on a BAD EXEMPTION the line said "0 FAILING" directly under
    //     the error that failed the build. A summary that contradicts the
    //     verdict beside it is worse than no summary.
    if (failed) {
        std.log.warn(
            "check-fuzz: {d} modules obligated, {d} covered, {d} exempt, {d} missing a harness ({d} harnesses total)",
            .{ n_obligated, n_covered, n_exempt, n_failing, n_harnesses },
        );
        return step.fail("fuzz-coverage gap — see errors above", .{});
    }
}

/// The identifiers this gate treats as a process-global allocator -- the
/// class CONVENTIONS.md §1.2 calls a "hidden global", as opposed to one a
/// caller passed in. `std.testing.allocator` is deliberately absent; see the
/// long comment above `check_global_alloc`'s `b.step` call for why.
const global_alloc_needles = [_][]const u8{
    "std.heap.page_allocator",
    "std.heap.smp_allocator",
    "std.heap.c_allocator",
    "std.heap.GeneralPurposeAllocator(",
    "std.heap.DebugAllocator(",
};

const global_alloc_marker = "global-alloc-ok:";

/// True when `line` starts, at column 0, a top-level declaration -- the unit
/// this gate tracks "am I inside a `test` block" against. Zig fmt never
/// indents a top-level declaration, so column 0 is a reliable boundary; it is
/// deliberately NOT full brace-depth tracking, which `.{}` struct literals and
/// `"{d}"`-style format strings would corrupt (the same "text, not semantics"
/// tradeoff `check-fuzz`'s `fileHasByteAcceptingPubFn` documents).
fn isTopLevelDecl(line: []const u8) bool {
    if (line.len == 0 or line[0] == ' ' or line[0] == '\t') return false;
    const starts = [_][]const u8{
        "test ",      "test\"",     "test{",
        "pub fn ",    "fn ",        "pub inline fn ",
        "inline fn ", "pub const ", "const ",
        "pub var ",   "var ",
    };
    for (starts) |s| if (std.mem.startsWith(u8, line, s)) return true;
    return false;
}

fn isTopLevelTestDecl(line: []const u8) bool {
    if (line.len == 0 or line[0] == ' ' or line[0] == '\t') return false;
    return std.mem.startsWith(u8, line, "test ") or
        std.mem.startsWith(u8, line, "test\"") or
        std.mem.startsWith(u8, line, "test{");
}

/// The text after `global-alloc-ok:` on a line, trimmed. Empty when the
/// marker is not present.
fn globalAllocMarkerReason(line: []const u8) []const u8 {
    const at = std.mem.indexOf(u8, line, global_alloc_marker) orelse return "";
    return std.mem.trim(u8, line[at + global_alloc_marker.len ..], " \t\r");
}

/// `zig build check-global-alloc` -- see the long comment above the `b.step`
/// call for what this enforces and the measured ground truth behind it.
///
/// Per module, per `.zig` file directly under `modules/<name>/src/` (one
/// level, matching `scanModuleForFuzz`; `bench.zig` files are skipped
/// entirely -- a benchmark is never the published module, and always wants
/// its own allocator, not a caller's). For each line NOT inside a literal
/// `test { ... }` block (tracked via `isTopLevelDecl`/`isTopLevelTestDecl`)
/// and not a full-line comment, a `global_alloc_needles` match must carry a
/// same-line `// global-alloc-ok: <reason>` marker, or the gate fails. A
/// marker with no reason, or a marker on a line that matches no needle
/// (a stale exemption -- CONVENTIONS' "exemptions cannot quietly outlive
/// their reason", same rule `checkNonGoals` enforces for `non-goal-ok`), is
/// itself an error.
fn checkGlobalAlloc(step: *std.Build.Step, options: std.Build.Step.MakeOptions) anyerror!void {
    _ = options;
    const b = step.owner;
    const io = b.graph.io;

    var failed = false;
    var n_checked: usize = 0;
    var n_in_test: usize = 0;
    var n_exempt: usize = 0;

    for (module_list) |m| {
        const dir_path = b.fmt("modules/{s}/src", .{m.name});
        var dir = b.build_root.handle.openDir(io, dir_path, .{ .iterate = true }) catch continue;
        defer dir.close(io);
        var it = dir.iterate();
        while (try it.next(io)) |e| {
            if (e.kind != .file or !std.mem.endsWith(u8, e.name, ".zig")) continue;
            if (std.mem.endsWith(u8, e.name, "bench.zig")) continue;
            const path = b.fmt("{s}/{s}", .{ dir_path, e.name });
            const src = try b.build_root.handle.readFileAlloc(io, path, b.allocator, .limited(8 * 1024 * 1024));

            var in_test = false;
            var lines = std.mem.splitScalar(u8, src, '\n');
            var line_no: usize = 0;
            while (lines.next()) |line| {
                line_no += 1;
                if (isTopLevelDecl(line)) in_test = isTopLevelTestDecl(line);

                const trimmed = std.mem.trim(u8, line, " \t\r");
                if (std.mem.startsWith(u8, trimmed, "//")) continue; // prose mention, not a use

                var matched: ?[]const u8 = null;
                for (global_alloc_needles) |needle| {
                    if (std.mem.indexOf(u8, line, needle) != null) {
                        matched = needle;
                        break;
                    }
                }
                const reason = globalAllocMarkerReason(line);

                if (matched) |needle| {
                    n_checked += 1;
                    if (in_test) {
                        n_in_test += 1;
                        continue;
                    }
                    if (reason.len == 0) {
                        std.log.err(
                            "{s}:{d}: {s} reaches for a process-global allocator outside a `test` block, " ++
                                "with no `// global-alloc-ok: <reason>` marker -- CONVENTIONS.md §1.2 wants " ++
                                "caller-supplied allocators; take one as a parameter, or justify the exception " ++
                                "inline",
                            .{ path, line_no, needle },
                        );
                        failed = true;
                        continue;
                    }
                    if (reason.len < 4) {
                        std.log.err(
                            "{s}:{d}: `global-alloc-ok:` states no real reason -- an exemption nobody can " ++
                                "argue with is one nobody will revisit",
                            .{ path, line_no },
                        );
                        failed = true;
                        continue;
                    }
                    n_exempt += 1;
                } else if (reason.len != 0) {
                    std.log.err(
                        "{s}:{d}: `global-alloc-ok:` marker present but this line uses no global allocator " ++
                            "it could exempt -- stale exemption, delete it",
                        .{ path, line_no },
                    );
                    failed = true;
                }
            }
        }
    }

    if (failed) {
        std.log.warn(
            "check-global-alloc: {d} uses checked, {d} inside test blocks, {d} exempted",
            .{ n_checked, n_in_test, n_exempt },
        );
        return step.fail("global-allocator gate failed -- see errors above", .{});
    }
}

/// The five rules that keep a fuzz exemption from becoming the thing that
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
fn checkFuzzExempt(b: *std.Build, io: std.Io, failed: *bool) !void {
    for (module_list) |mod| {
        const row = moduleFuzzExemption(b, io, mod.name, failed) orelse continue;
        if (!containsName(&.{ "EMIT-ONLY", "PRE-PARSED" }, row.reason)) {
            std.log.err(
                "module '{s}': fuzz exemption reason '{s}' is not EMIT-ONLY or PRE-PARSED ({s})",
                .{ mod.name, row.reason, row.path },
            );
            failed.* = true;
            continue;
        }
        if (row.evidence.len == 0) {
            std.log.err(
                "module '{s}': its fuzz exemption states no argument -- the prose after the line is what a " ++
                    "reader has to overturn, and an exemption nobody can argue with is one nobody will revisit ({s})",
                .{ mod.name, row.path },
            );
            failed.* = true;
        }

        const scan = try scanModuleForFuzz(b, io, mod.name);
        const class: u8 = if (moduleAnchorGrade(b, io, mod.name)) |g| g.class else '?';
        const faces_outside = class == 'A' or class == 'B';
        if (!faces_outside or scan.surface_files == 0) {
            std.log.err(
                "module '{s}' claims a fuzz exemption, but check-fuzz would not have flagged it (CLASS {c}, " ++
                    "{d} byte-accepting source file(s)) — an exemption that excuses nothing is dead weight; delete it",
                .{ mod.name, class, scan.surface_files },
            );
            failed.* = true;
        }
        if (scan.harnesses > 0) {
            std.log.err(
                "module '{s}' claims a {s} fuzz exemption, but modules/{s}/src/ now contains {d} fuzz " ++
                    "harness(es) — the code contradicts the exemption; delete it",
                .{ mod.name, row.reason, mod.name, scan.harnesses },
            );
            failed.* = true;
        }

        if (std.mem.eql(u8, row.reason, "PRE-PARSED")) {
            if (row.sibling.len == 0) {
                std.log.err(
                    "module '{s}' claims PRE-PARSED but names no sibling — write `**Fuzz exemption:** " ++
                        "PRE-PARSED via <module>`, since the whole claim is that someone else took the bytes first",
                    .{mod.name},
                );
                failed.* = true;
            } else if (!containsName(mod.deps, row.sibling)) {
                std.log.err(
                    "module '{s}' claims PRE-PARSED via '{s}', but '{s}' is not one of its declared deps in " ++
                        "build.zig's module_list — the bytes cannot arrive pre-decoded from a module it does not import",
                    .{ mod.name, row.sibling, row.sibling },
                );
                failed.* = true;
            } else {
                const upstream = try scanModuleForFuzz(b, io, row.sibling);
                if (upstream.harnesses == 0) {
                    std.log.err(
                        "module '{s}' claims PRE-PARSED via '{s}', but '{s}' has no fuzz harness of its own — " ++
                            "the exemption hands the untrusted surface to a module nobody fuzzes",
                        .{ mod.name, row.sibling, row.sibling },
                    );
                    failed.* = true;
                }
            }
        }
    }
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

/// Count fuzz harnesses in one file.
///
/// Matches `.fuzz(` preceded by an identifier character, which catches
/// `std.testing.fuzz(`, `testing.fuzz(` and an aliased `t.fuzz(` alike. It used
/// to require the literal `testing.fuzz(`, and that missed real harnesses: on
/// 2026-08-14 `csvstream` and `pping` each had genuine, running harnesses on
/// their decode entry points written through a `const t = std.testing;` alias,
/// and the gate reported both modules as having none. It was demanding a
/// spelling rather than a call -- the same defect class as a test that asserts
/// the wording of a claim instead of the claim.
///
/// Still text, not semantics, so a differently-shaped call can still hide. The
/// direction of that failure is the safe one: an unseen harness makes the gate
/// demand another, never excuse a missing one.
fn countFuzzCalls(src: []const u8) usize {
    const needle = ".fuzz(";
    var n: usize = 0;
    var i: usize = 0;
    while (std.mem.indexOfPos(u8, src, i, needle)) |at| {
        i = at + 1;
        if (at == 0) continue;
        const before = src[at - 1];
        // An identifier character before the dot: `testing`, `std.testing`, an
        // alias. Anything else (whitespace, `(`, an operator) is not a call.
        if (!std.ascii.isAlphanumeric(before) and before != '_') continue;
        n += 1;
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
/// The catalog row's opening cell, which is also its link to the module. Kept in
/// one place because both the existence check and the Deps-column reader locate a
/// row by it: if they ever disagree, a module drops out of one check silently.
///
/// The link target is part of the needle deliberately. A row could otherwise
/// carry a link to the wrong module -- the failure a reader is least likely to
/// notice, since the text they see is right and only the destination is not.
fn catalogRowNeedle(b: *std.Build, name: []const u8) []const u8 {
    return b.fmt("| [`{s}`](modules/{s}/README.md) |", .{ name, name });
}

fn readmeDepsCell(readme: []const u8, name: []const u8, b: *std.Build) ?[]const []const u8 {
    const start = std.mem.indexOf(u8, readme, catalogRowNeedle(b, name)) orelse return null;
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
