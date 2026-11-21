// SPDX-License-Identifier: MIT
//
// The control of `scripts/checks/check-fastmem-nolibcall.sh`: a plain runtime-length
// `@memset` / `@memcpy`, which LLVM lowers to a call to `memset` / `memcpy`.
// The check must see them here, or it is blind and says so.

export fn control_set(dest: [*]u8, c: u8, len: usize) void {
    @memset(dest[0..len], c);
}

export fn control_copy(noalias dest: [*]u8, noalias src: [*]const u8, len: usize) void {
    @memcpy(dest[0..len], src[0..len]);
}
