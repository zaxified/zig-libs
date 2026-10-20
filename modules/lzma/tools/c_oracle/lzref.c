/* SPDX-License-Identifier: MIT
 *
 * Black-box driver around liblzma 5.8.1 (compiled from the pinned XZ Utils
 * clone, see ../build-oracle.sh), for the differential tests.
 *
 *   lzref enc FORMAT SPEC CHECK in out   compress; FORMAT is xz | alone | raw1 | raw2
 *       SPEC   "6", "9e", or "6,dict=65536,lc=0,lp=2,pb=1,mode=fast,nice=32,mf=hc4,depth=5"
 *       CHECK  none | crc32 | crc64 | sha256   (xz only)
 *   lzref dec FORMAT in out              decompress (xz | alone | auto), prints "OK <bytes>"
 *                                        or "ERR <status>"; FORMAT xz is concatenated
 *   lzref raw1 PROPS5HEX SIZE EOPM in out   decompress raw LZMA1 (SIZE or -1, EOPM 0|1)
 *
 * The encoder is lzma_stream_encoder / lzma_alone_encoder / lzma_raw_encoder
 * fed the whole input then LZMA_FINISH, the way xz and Python's lzma do.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "lzma.h"

static uint8_t *slurp(const char *path, size_t *n) {
    FILE *f = fopen(path, "rb");
    if (!f) { perror(path); exit(3); }
    fseek(f, 0, SEEK_END);
    *n = (size_t)ftell(f);
    fseek(f, 0, SEEK_SET);
    uint8_t *b = malloc(*n + 1);
    if (fread(b, 1, *n, f) != *n) { fprintf(stderr, "short read\n"); exit(3); }
    fclose(f);
    return b;
}

static void spit(const char *path, const uint8_t *p, size_t n) {
    FILE *f = fopen(path, "wb");
    if (!f || fwrite(p, 1, n, f) != n) { perror(path); exit(3); }
    fclose(f);
}

static const char *status(lzma_ret r) {
    switch (r) {
    case LZMA_OK: return "OK";
    case LZMA_STREAM_END: return "STREAM_END";
    case LZMA_NO_CHECK: return "NO_CHECK";
    case LZMA_UNSUPPORTED_CHECK: return "UNSUPPORTED_CHECK";
    case LZMA_GET_CHECK: return "GET_CHECK";
    case LZMA_MEM_ERROR: return "MEM_ERROR";
    case LZMA_MEMLIMIT_ERROR: return "MEMLIMIT_ERROR";
    case LZMA_FORMAT_ERROR: return "FORMAT_ERROR";
    case LZMA_OPTIONS_ERROR: return "OPTIONS_ERROR";
    case LZMA_DATA_ERROR: return "DATA_ERROR";
    case LZMA_BUF_ERROR: return "BUF_ERROR";
    case LZMA_PROG_ERROR: return "PROG_ERROR";
    default: return "OTHER";
    }
}

static int parse_spec(const char *spec, lzma_options_lzma *o) {
    char *s = strdup(spec), *save = NULL;
    char *tok = strtok_r(s, ",", &save);
    char *endp;
    uint32_t preset = (uint32_t)strtoul(tok, &endp, 10);
    if (*endp == 'e') preset |= LZMA_PRESET_EXTREME;
    if (lzma_lzma_preset(o, preset)) return 1;
    while ((tok = strtok_r(NULL, ",", &save))) {
        char *eq = strchr(tok, '=');
        if (!eq) return 1;
        *eq++ = 0;
        if (!strcmp(tok, "dict")) o->dict_size = (uint32_t)strtoul(eq, NULL, 10);
        else if (!strcmp(tok, "lc")) o->lc = (uint32_t)strtoul(eq, NULL, 10);
        else if (!strcmp(tok, "lp")) o->lp = (uint32_t)strtoul(eq, NULL, 10);
        else if (!strcmp(tok, "pb")) o->pb = (uint32_t)strtoul(eq, NULL, 10);
        else if (!strcmp(tok, "nice")) o->nice_len = (uint32_t)strtoul(eq, NULL, 10);
        else if (!strcmp(tok, "depth")) o->depth = (uint32_t)strtoul(eq, NULL, 10);
        else if (!strcmp(tok, "mode")) o->mode = !strcmp(eq, "fast") ? LZMA_MODE_FAST : LZMA_MODE_NORMAL;
        else if (!strcmp(tok, "mf")) {
            o->mf = !strcmp(eq, "hc3") ? LZMA_MF_HC3 : !strcmp(eq, "hc4") ? LZMA_MF_HC4
                  : !strcmp(eq, "bt2") ? LZMA_MF_BT2 : !strcmp(eq, "bt3") ? LZMA_MF_BT3 : LZMA_MF_BT4;
        } else return 1;
    }
    free(s);
    return 0;
}

static lzma_check parse_check(const char *c) {
    if (!strcmp(c, "none")) return LZMA_CHECK_NONE;
    if (!strcmp(c, "crc32")) return LZMA_CHECK_CRC32;
    if (!strcmp(c, "sha256")) return LZMA_CHECK_SHA256;
    return LZMA_CHECK_CRC64;
}

static int run(lzma_stream *s, const uint8_t *in, size_t n, uint8_t **out, size_t *outn) {
    size_t cap = n + n / 2 + (1 << 16), len = 0;
    uint8_t *b = malloc(cap);
    s->next_in = in;
    s->avail_in = n;
    for (;;) {
        s->next_out = b + len;
        s->avail_out = cap - len;
        lzma_ret r = lzma_code(s, LZMA_FINISH);
        len = cap - s->avail_out;
        if (r == LZMA_STREAM_END) break;
        if (r == LZMA_OK || r == LZMA_BUF_ERROR) {
            if (s->avail_out == 0) { cap *= 2; b = realloc(b, cap); continue; }
            if (r == LZMA_BUF_ERROR) { *out = b; *outn = len; return -2; }
            continue;
        }
        *out = b;
        *outn = len;
        return (int)r;
    }
    *out = b;
    *outn = len;
    return 0;
}

int main(int argc, char **argv) {
    if (argc >= 7 && !strcmp(argv[1], "enc")) {
        size_t n;
        uint8_t *in = slurp(argv[5], &n);
        lzma_options_lzma o;
        if (parse_spec(argv[3], &o)) { fprintf(stderr, "bad spec\n"); return 3; }
        lzma_stream s = LZMA_STREAM_INIT;
        lzma_ret r;
        lzma_filter f[2] = { { .id = LZMA_FILTER_LZMA2, .options = &o }, { .id = LZMA_VLI_UNKNOWN } };
        if (!strcmp(argv[2], "xz")) r = lzma_stream_encoder(&s, f, parse_check(argv[4]));
        else if (!strcmp(argv[2], "alone")) r = lzma_alone_encoder(&s, &o);
        else {
            f[0].id = !strcmp(argv[2], "raw1") ? LZMA_FILTER_LZMA1 : LZMA_FILTER_LZMA2;
            r = lzma_raw_encoder(&s, f);
        }
        if (r != LZMA_OK) { fprintf(stderr, "init %s\n", status(r)); return 2; }
        uint8_t *out;
        size_t outn;
        int rc = run(&s, in, n, &out, &outn);
        if (rc) { fprintf(stderr, "encode %d\n", rc); return 2; }
        spit(argv[6], out, outn);
        lzma_end(&s);
        return 0;
    }
    if (argc >= 5 && !strcmp(argv[1], "dec")) {
        size_t n;
        uint8_t *in = slurp(argv[3], &n);
        lzma_stream s = LZMA_STREAM_INIT;
        lzma_ret r;
        if (!strcmp(argv[2], "alone")) r = lzma_alone_decoder(&s, UINT64_MAX);
        else r = lzma_auto_decoder(&s, UINT64_MAX, !strcmp(argv[2], "xz") ? LZMA_CONCATENATED : 0);
        if (!strcmp(argv[2], "xz")) { lzma_end(&s); s = (lzma_stream)LZMA_STREAM_INIT; r = lzma_stream_decoder(&s, UINT64_MAX, LZMA_CONCATENATED); }
        if (r != LZMA_OK) { printf("ERR init %s\n", status(r)); return 0; }
        uint8_t *out;
        size_t outn;
        int rc = run(&s, in, n, &out, &outn);
        if (rc) printf("ERR %s %zu\n", rc == -2 ? "BUF_ERROR" : status((lzma_ret)rc), outn);
        else printf("OK %zu\n", outn);
        spit(argv[4], out, outn);
        return 0;
    }
    if (argc >= 7 && !strcmp(argv[1], "raw1")) {
        size_t n;
        uint8_t *in = slurp(argv[5], &n);
        uint8_t props[5];
        for (int i = 0; i < 5; i++) { unsigned v; sscanf(argv[2] + 2 * i, "%2x", &v); props[i] = (uint8_t)v; }
        lzma_filter ff = { .id = LZMA_FILTER_LZMA1 };
        if (lzma_properties_decode(&ff, NULL, props, 5) != LZMA_OK) { printf("ERR props\n"); return 0; }
        lzma_filter f[2] = { { .id = LZMA_FILTER_LZMA1EXT, .options = ff.options }, { .id = LZMA_VLI_UNKNOWN } };
        long long size = atoll(argv[3]);
        lzma_options_lzma *lo = ff.options;
        lo->ext_flags = atoi(argv[4]) ? LZMA_LZMA1EXT_ALLOW_EOPM : 0;
        lzma_set_ext_size(*lo, size < 0 ? UINT64_MAX : (uint64_t)size);
        lzma_stream s = LZMA_STREAM_INIT;
        lzma_ret r = lzma_raw_decoder(&s, f);
        if (r != LZMA_OK) { printf("ERR init %s\n", status(r)); return 0; }
        uint8_t *out;
        size_t outn;
        int rc = run(&s, in, n, &out, &outn);
        if (rc) printf("ERR %s %zu\n", rc == -2 ? "BUF_ERROR" : status((lzma_ret)rc), outn);
        else printf("OK %zu\n", outn);
        spit(argv[6], out, outn);
        return 0;
    }
    fprintf(stderr, "usage: see header\n");
    return 3;
}
