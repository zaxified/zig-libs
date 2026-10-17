/* SPDX-License-Identifier: MIT */
/* Shim (see ../core.h). codecs.c needs only ACQUIRE_FENCE from libsodium's
 * private/common.h: a load fence against speculation, a no-op for a
 * functional oracle. */
#ifndef B64CT_SHIM_COMMON_H
#define B64CT_SHIM_COMMON_H
#define ACQUIRE_FENCE ((void) 0)
#endif
