// SPDX-License-Identifier: MIT
//
// The fastest-candidate side of `tools/slip.sh`: does libFuzzer's
// `-minimize_crash=1` keep the crash it started from? The property (the
// same in all three tools, `twoBugsCheck` in `src/shrink.zig`): an input
// crashes "deep" (abort, SIGABRT) when it is at least 16 bytes long and sums
// to 1500 or more, and "shallow" (trap, SIGILL) when it starts with a zero.
// Two different crash sites, as two different bugs are.
//
// Built by `tools/slip.sh` with `clang -fsanitize=fuzzer` (libFuzzer's own
// main), once plain and once with AddressSanitizer: libFuzzer compares the
// `DEDUP_TOKEN:` of the first and the minimized crash, and only a sanitizer
// prints one.

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size >= 2 && data[0] == 0) __builtin_trap();
    if (size < 16) return 0;
    uint32_t sum = 0;
    for (size_t i = 0; i < size; i++) sum += data[i];
    if (sum >= 1500) abort();
    return 0;
}
