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
};

const module_list = [_]Module{
    .{ .name = "netaddr" },
    .{ .name = "http", .deps = &.{"netaddr"} },
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
    .{ .name = "netsim" },
    .{ .name = "loopfree-reconv", .deps = &.{ "netsim", "spf-ect" } },
    .{ .name = "df-elect", .deps = &.{"netsim"} },
    .{ .name = "raft", .deps = &.{"netsim"} },
    .{ .name = "liveness-hyst", .deps = &.{ "netsim", "latency-stats" } },
    .{ .name = "loopix", .deps = &.{ "netsim", "sphinx" } },
    .{ .name = "lockfree" },
    .{ .name = "hashdigest" },
    .{ .name = "sealedbox" },
    .{ .name = "rsa", .deps = &.{"montint"} },
    .{ .name = "blindrsa", .deps = &.{"rsa"} },
    .{ .name = "ssh", .deps = &.{"rsa"} },
    .{ .name = "nftables" },
    .{ .name = "modbus" },
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
    .{ .name = "jwe", .deps = &.{ "rsa", "p256" } },
    .{ .name = "rdap", .deps = &.{ "http", "netaddr" } },
    .{ .name = "blobstore", .deps = &.{"hashdigest"} },
    .{ .name = "procnet", .deps = &.{"netaddr"} },
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
    .{ .name = "opcua", .deps = &.{"rsa"} },
    .{ .name = "noise" },
    .{ .name = "x509", .deps = &.{"rsa"} },
    .{ .name = "dnssec", .deps = &.{ "dns", "rsa" } },
    .{ .name = "dnp3" },
    .{ .name = "slhdsa" },
    .{ .name = "falcon" },
    .{ .name = "hqc" },
    .{ .name = "dtls", .deps = &.{"rsa"} },
    .{ .name = "tlsresume" },
    .{ .name = "quic-crypto" },
    .{ .name = "sandbox" },
    .{ .name = "bip340", .deps = &.{"k256"} },
    .{ .name = "taproot", .deps = &.{ "bip340", "k256" } },
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
    .{ .name = "xmss" },
    .{ .name = "otp" },
    .{ .name = "ctap2pin", .deps = &.{"p256"} },
    .{ .name = "bls12_381" },
    .{ .name = "bbs", .deps = &.{"bls12_381"} },
    .{ .name = "coconut", .deps = &.{"bls12_381"} },
    .{ .name = "tlock", .deps = &.{"bls12_381"} },
    .{ .name = "ibe", .deps = &.{"bls12_381"} },
    .{ .name = "bn254" },
    .{ .name = "ed448" },
    .{ .name = "decaf448", .deps = &.{"ed448"} },
    .{ .name = "paillier", .deps = &.{"montint"} },
    .{ .name = "threshold_ecdsa", .deps = &.{ "paillier", "montint" } },
    .{ .name = "dkg", .deps = &.{ "threshold_ecdsa", "paillier" } },
    .{ .name = "vdf", .deps = &.{"montint"} },
    .{ .name = "signal" },
    .{ .name = "mls", .deps = &.{"hpke"} },
    .{ .name = "ebpf", .deps = &.{"netlink"} },
    .{ .name = "xdp-classifier", .deps = &.{"ebpf"} },
    .{ .name = "ecvrf" },
    .{ .name = "fss" },
    .{ .name = "bfv" },
    .{ .name = "groth16", .deps = &.{"bn254"} },
    .{ .name = "tfhe" },
    .{ .name = "montint" },
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

    // Pass 1: create each module so inter-module deps can be wired in pass 2.
    var mods = std.StringHashMap(*std.Build.Module).init(b.allocator);
    for (module_list) |m| {
        const mod = b.addModule(m.name, .{
            .root_source_file = b.path(b.fmt("modules/{s}/src/root.zig", .{m.name})),
            .target = target,
            .optimize = optimize,
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

    // Catalog consistency gate: `zig build check-catalog` (CI runs it).
    // Verifies module_list ↔ modules/ ↔ the README catalog table agree, so a
    // module can't ship without a catalog row (6 rows had drifted before this
    // existed) and the README's module count can't go stale.
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

fn checkCatalog(step: *std.Build.Step, options: std.Build.Step.MakeOptions) anyerror!void {
    _ = options;
    const b = step.owner;
    const io = b.graph.io;
    const readme = try b.build_root.handle.readFileAlloc(io, "README.md", b.allocator, .limited(4 * 1024 * 1024));

    var failed = false;
    for (module_list) |m| {
        b.build_root.handle.access(io, b.fmt("modules/{s}/src/root.zig", .{m.name}), .{}) catch {
            std.log.err("module_list entry '{s}' has no modules/{s}/src/root.zig", .{ m.name, m.name });
            failed = true;
        };
        if (std.mem.indexOf(u8, readme, b.fmt("| `{s}` |", .{m.name})) == null) {
            std.log.err("module '{s}' has no README catalog row (`| \\`{s}\\` |`)", .{ m.name, m.name });
            failed = true;
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
