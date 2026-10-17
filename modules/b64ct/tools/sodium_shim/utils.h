/* SPDX-License-Identifier: MIT */
/* Shim (see core.h): the base64 part of libsodium's public sodium/utils.h,
 * written from its documented API — the variant constants, the length macro
 * (encoded length plus the NUL) and the prototypes codecs.c defines. */
#ifndef B64CT_SHIM_UTILS_H
#define B64CT_SHIM_UTILS_H
#include <stddef.h>

#define sodium_base64_VARIANT_ORIGINAL 1
#define sodium_base64_VARIANT_ORIGINAL_NO_PADDING 3
#define sodium_base64_VARIANT_URLSAFE 5
#define sodium_base64_VARIANT_URLSAFE_NO_PADDING 7

#define sodium_base64_ENCODED_LEN(BIN_LEN, VARIANT)                         \
    ((((VARIANT) & 2U) == 0U) ? (((BIN_LEN) + 2U) / 3U * 4U + 1U)           \
                              : ((BIN_LEN) / 3U * 4U +                      \
                                 ((BIN_LEN) % 3U ? (BIN_LEN) % 3U + 1U : 0U) + 1U))

char *sodium_bin2hex(char *const hex, const size_t hex_maxlen,
                     const unsigned char *const bin, const size_t bin_len);
int sodium_hex2bin(unsigned char *const bin, const size_t bin_maxlen,
                   const char *const hex, const size_t hex_len,
                   const char *const ignore, size_t *const bin_len,
                   const char **const hex_end);
size_t sodium_base64_encoded_len(const size_t bin_len, const int variant);
char *sodium_bin2base64(char *const b64, const size_t b64_maxlen,
                        const unsigned char *const bin, const size_t bin_len,
                        const int variant);
int sodium_base642bin(unsigned char *const bin, const size_t bin_maxlen,
                      const char *const b64, const size_t b64_len,
                      const char *const ignore, size_t *const bin_len,
                      const char **const b64_end, const int variant);
int sodium_ip2bin(unsigned char bin[16], const char *ip, size_t ip_len_);
char *sodium_bin2ip(char *ip, size_t ip_maxlen, const unsigned char bin[16]);
#endif
