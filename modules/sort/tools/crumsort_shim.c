/* SPDX-License-Identifier: MIT
 * C entry points of crumsort (Unlicense, scandum/crumsort) for the C++ side of
 * `bench-sort` when it is built with -DALT_CRUMSORT: `crumsort_prim` sorts
 * unsigned 64- and 32-bit integers (size codes 9 and 5). */
#include <stddef.h>
#include "crumsort.h"

void crumsort_u64(void *a, size_t n) { crumsort_prim(a, n, 9); }
void crumsort_u32(void *a, size_t n) { crumsort_prim(a, n, 5); }
