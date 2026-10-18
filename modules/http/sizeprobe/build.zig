// SPDX-License-Identifier: MIT
const std = @import("std");

/// Mirror of the root build.zig's `Profile` (a separate build script cannot import it).
const Profile = enum { default, small };

// Standalone build for the plaintext-only http.Client size probe (see
// ./README.md). Deliberately its own tiny project rather than a step bolted
// onto the repo-root build.zig: this task's brief is scoped to modules/http/
// only, and a size/reachability probe is a one-off verification tool, not
// part of the published module graph. `netaddr` is http's only dependency
// (see the root build.zig's module_list) — wired here the same way, by path.
pub fn build(b: *std.Build) void {
    // LLVM unless -Dselfhosted: the self-hosted backend is for the edit loop only.
    const selfhosted = b.option(bool, "selfhosted", "Use Zig's self-hosted backend in Debug (edit loop only)") orelse false;
    const use_llvm: ?bool = if (selfhosted) null else true;
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const netaddr_mod = b.createModule(.{
        .root_source_file = b.path("../../netaddr/src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    const http_mod = b.createModule(.{
        .root_source_file = b.path("../src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    http_mod.addImport("netaddr", netaddr_mod);
    // `tlsclient` and its closure: `Conn.tls_client`'s TYPE names it, so the
    // module must resolve even here -- none of its code may be linked into
    // probe_after, which is exactly what the nm check asserts.
    const dep = struct {
        fn mod(bb: *std.Build, t: std.Build.ResolvedTarget, o: std.builtin.OptimizeMode, name: []const u8) *std.Build.Module {
            return bb.createModule(.{
                .root_source_file = bb.path(bb.fmt("../../{s}/src/root.zig", .{name})),
                .target = t,
                .optimize = o,
            });
        }
    };
    // ⚠ Mirror the root build.zig's `.deps` by hand: a dep added there and
    // not here only shows when `test.sh checks` runs this probe.
    const entropy_mod = dep.mod(b, target, optimize, "entropy");
    const montint_mod = dep.mod(b, target, optimize, "montint");
    const rsa_mod = dep.mod(b, target, optimize, "rsa");
    rsa_mod.addImport("montint", montint_mod);
    // The root build.zig's consumer options (`zl_options`), at their defaults
    // unless `-Dprofile` / `-Drsa-max-modulus-bits` say otherwise.
    const zl_options = b.addOptions();
    zl_options.addOption(Profile, "profile", b.option(Profile, "profile", "default | small") orelse .default);
    zl_options.addOption(?u32, "rsa_max_modulus_bits", b.option(u32, "rsa-max-modulus-bits", "rsa cap (4096..8192)"));
    rsa_mod.addImport("zl_options", zl_options.createModule());
    rsa_mod.addImport("aescbc", dep.mod(b, target, optimize, "aescbc"));
    rsa_mod.addImport("aes192", dep.mod(b, target, optimize, "aes192"));
    const b64ct_mod = dep.mod(b, target, optimize, "b64ct");
    rsa_mod.addImport("b64ct", b64ct_mod);
    http_mod.addImport("b64ct", b64ct_mod);
    const slhdsa_mod = dep.mod(b, target, optimize, "slhdsa");
    const x509_mod = dep.mod(b, target, optimize, "x509");
    x509_mod.addImport("rsa", rsa_mod);
    x509_mod.addImport("slhdsa", slhdsa_mod);
    x509_mod.addImport("netaddr", netaddr_mod);
    const p521_mod = dep.mod(b, target, optimize, "p521");
    p521_mod.addImport("entropy", entropy_mod);
    x509_mod.addImport("p521", p521_mod);
    const p256_mod = dep.mod(b, target, optimize, "p256");
    x509_mod.addImport("p256", p256_mod);
    const p384_mod = dep.mod(b, target, optimize, "p384");
    p384_mod.addImport("entropy", entropy_mod);
    const tlsclient_mod = dep.mod(b, target, optimize, "tlsclient");
    tlsclient_mod.addImport("x509", x509_mod);
    tlsclient_mod.addImport("p256", p256_mod);
    tlsclient_mod.addImport("p384", p384_mod);
    tlsclient_mod.addImport("p521", p521_mod);
    tlsclient_mod.addImport("rsa", rsa_mod);
    tlsclient_mod.addImport("tlsresume", dep.mod(b, target, optimize, "tlsresume"));
    http_mod.addImport("tlsclient", tlsclient_mod);
    http_mod.addImport("datefmt", dep.mod(b, target, optimize, "datefmt"));
    http_mod.addImport("crc32", dep.mod(b, target, optimize, "crc32"));

    const names = [_][]const u8{ "before", "after" };
    inline for (names) |which| {
        // The size-comparison binary: whatever `-Doptimize` says (default
        // ReleaseSmall auto-strips — see std.Build.Step.Compile, "strip ==
        // null and optimize == .ReleaseSmall"), matching how a real
        // deployment ships. `zig build -Dtarget=x86_64-linux-musl
        // -Doptimize=ReleaseSmall install` builds these two; compare their
        // sizes for the measured saving.
        const root_mod = b.createModule(.{
            .root_source_file = b.path("probe_" ++ which ++ ".zig"),
            .target = target,
            .optimize = optimize,
        });
        root_mod.addImport("http", http_mod);
        const exe = b.addExecutable(.{
            .use_llvm = use_llvm,
            .name = "probe_" ++ which,
            .root_module = root_mod,
            .linkage = .static,
        });
        b.installArtifact(exe);

        // The reachability-check binary: identical target/optimize (so the
        // same dead-code elimination runs), but symbols kept — a stripped
        // binary has no symbol table at all, so `nm` on it is vacuous either
        // way, not evidence of anything. Build these with `-Dsyms=true` and
        // `nm` `probe_after_syms`; it must show zero tls.Client/
        // Certificate/curve/hash symbols. `probe_before_syms` is kept for
        // contrast — the same grep against it must be NON-empty, proving
        // the grep pattern itself would actually catch a real reference.
        const syms_mod = b.createModule(.{
            .root_source_file = b.path("probe_" ++ which ++ ".zig"),
            .target = target,
            .optimize = optimize,
        });
        syms_mod.addImport("http", http_mod);
        syms_mod.strip = false;
        const syms_exe = b.addExecutable(.{
            .use_llvm = use_llvm,
            .name = "probe_" ++ which ++ "_syms",
            .root_module = syms_mod,
            .linkage = .static,
        });
        b.installArtifact(syms_exe);
    }
}
