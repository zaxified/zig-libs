/* SPDX-License-Identifier: MIT */
/* Shim for compiling libsodium's src/libsodium/sodium/codecs.c alone (the
 * interop oracle and the bench, tools/README.md). Not libsodium's header. */
#ifndef B64CT_SHIM_CORE_H
#define B64CT_SHIM_CORE_H
#include <stdlib.h>
#define sodium_misuse() abort()
#endif
