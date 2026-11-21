// SPDX-License-Identifier: MIT
//
// The two entry points `scripts/checks/check-fastmem-nolibcall.sh` compiles
// to an object and disassembles: `fastmem.set` / `fastmem.copy` with everything they reach
// (`setSmall`, `copySmall`, `setLarge`, `copyLarge`). The module implements
// `memset` / `memcpy`, so none of that code may call them.

const fastmem = @import("fastmem");

export fn probe_set(dest: [*]u8, c: u8, len: usize) void {
    fastmem.set(dest, c, len);
}

export fn probe_copy(noalias dest: [*]u8, noalias src: [*]const u8, len: usize) void {
    fastmem.copy(dest, src, len);
}
