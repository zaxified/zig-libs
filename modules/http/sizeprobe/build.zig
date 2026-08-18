const std = @import("std");

// Standalone build for the plaintext-only http.Client size probe (see
// ./README.md). Deliberately its own tiny project rather than a step bolted
// onto the repo-root build.zig: this task's brief is scoped to modules/http/
// only, and a size/reachability probe is a one-off verification tool, not
// part of the published module graph. `netaddr` is http's only dependency
// (see the root build.zig's module_list) — wired here the same way, by path.
pub fn build(b: *std.Build) void {
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
            .name = "probe_" ++ which ++ "_syms",
            .root_module = syms_mod,
            .linkage = .static,
        });
        b.installArtifact(syms_exe);
    }
}
