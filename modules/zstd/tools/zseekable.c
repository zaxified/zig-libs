/* SPDX-License-Identifier: MIT */
/* zseekable -- differential oracle for modules/zstd `seekable.zig`: libzstd
 * 1.5.7's contrib/seekable_format driven the way `seekable_test.zig` drives
 * `SeekableStream` and `Seekable`.
 *
 *   zseekable c <level> <checksum 0|1> <maxFrameSize> <in> <out> <schedule>
 *       ZSTD_seekable_initCStream, then the schedule, comma-separated:
 *         oN   later calls get an output buffer of N bytes (default 1 << 20)
 *         cN   ZSTD_seekable_compressStream with the next N input bytes
 *              ("c*": all the rest), called until they are consumed
 *         f    ZSTD_seekable_endFrame, called until it returns 0
 *         e    ZSTD_seekable_endStream, called until it returns 0; last
 *       every output buffer's contents are appended to <out>.
 *   zseekable d <in> <offset> <len> [file]
 *       ZSTD_seekable_initBuff (or initFile), then ZSTD_seekable_decompress
 *       of <len> bytes at <offset>, and again of the same range (the second
 *       call continues where the first stopped when it can); prints
 *       "OK <n> <fnv1a64>" or "ERR <ZSTD_ErrorCode>".
 *   zseekable t <in>
 *       prints the seek table: "frames <n> checksum <0|1>", then per frame
 *       "<cOffset> <dOffset> <cSize> <dSize>", or "ERR <code>".
 *
 * Build against the pinned libzstd checkout (see gen-seekable-goldens.sh):
 *   cc -O2 -I "$R/lib" -I "$R/lib/common" -I "$R/contrib/seekable_format" \
 *      -o zseekable zseekable.c "$R/contrib/seekable_format/zstdseek_compress.c" \
 *      "$R/contrib/seekable_format/zstdseek_decompress.c" "$R/lib/libzstd.a"
 *
 * This file is a foreign-toolchain instrument (CONVENTIONS.md §2, §9): no
 * module build compiles it.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "zstd.h"
#include "zstd_errors.h"
#include "zstd_seekable.h"

static unsigned char* readAll(const char* path, size_t* size)
{
    FILE* f = fopen(path, "rb");
    if (!f) { perror(path); exit(2); }
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    unsigned char* b = malloc((size_t)n + 1);
    if ((long)fread(b, 1, (size_t)n, f) != n) { perror(path); exit(2); }
    fclose(f);
    *size = (size_t)n;
    return b;
}

static unsigned long long fnv(const unsigned char* p, size_t n)
{
    unsigned long long h = 0xcbf29ce484222325ULL;
    for (size_t i = 0; i < n; i++) { h ^= p[i]; h *= 0x100000001b3ULL; }
    return h;
}

static int compressMode(int argc, char** argv)
{
    if (argc != 8) return 2;
    int const level = atoi(argv[2]);
    int const checksum = atoi(argv[3]);
    unsigned const maxFrame = (unsigned)strtoul(argv[4], NULL, 10);
    size_t srcSize;
    unsigned char* const src = readAll(argv[5], &srcSize);
    FILE* const out = fopen(argv[6], "wb");
    ZSTD_seekable_CStream* const zcs = ZSTD_seekable_createCStream();
    size_t r = ZSTD_seekable_initCStream(zcs, level, checksum, maxFrame);
    if (ZSTD_isError(r)) { printf("ERR %d\n", (int)ZSTD_getErrorCode(r)); return 1; }
    size_t ocap = 1 << 20;
    unsigned char* obuf = malloc(1 << 24);
    size_t fed = 0;
    char* sched = strdup(argv[7]);
    for (char* tok = strtok(sched, ","); tok; tok = strtok(NULL, ",")) {
        if (tok[0] == 'o') { ocap = strtoul(tok + 1, NULL, 10); continue; }
        if (tok[0] == 'c') {
            size_t const n = tok[1] == '*' ? srcSize - fed : strtoul(tok + 1, NULL, 10);
            ZSTD_inBuffer in = { src + fed, n, 0 };
            while (in.pos < in.size) {
                ZSTD_outBuffer o = { obuf, ocap, 0 };
                r = ZSTD_seekable_compressStream(zcs, &o, &in);
                fwrite(obuf, 1, o.pos, out);
                if (ZSTD_isError(r)) { printf("ERR %d\n", (int)ZSTD_getErrorCode(r)); return 1; }
            }
            fed += n;
            continue;
        }
        if (tok[0] == 'f' || tok[0] == 'e') {
            do {
                ZSTD_outBuffer o = { obuf, ocap, 0 };
                r = tok[0] == 'f' ? ZSTD_seekable_endFrame(zcs, &o) : ZSTD_seekable_endStream(zcs, &o);
                fwrite(obuf, 1, o.pos, out);
                if (ZSTD_isError(r)) { printf("ERR %d\n", (int)ZSTD_getErrorCode(r)); return 1; }
            } while (r != 0);
            continue;
        }
        fprintf(stderr, "bad token %s\n", tok);
        return 2;
    }
    fclose(out);
    ZSTD_seekable_freeCStream(zcs);
    printf("OK\n");
    return 0;
}

static int decompressMode(int argc, char** argv)
{
    if (argc != 5 && argc != 6) return 2;
    unsigned long long const offset = strtoull(argv[3], NULL, 10);
    size_t const len = strtoul(argv[4], NULL, 10);
    ZSTD_seekable* const zs = ZSTD_seekable_create();
    size_t size;
    unsigned char* buf = NULL;
    FILE* f = NULL;
    size_t r;
    if (argc == 6) {
        f = fopen(argv[2], "rb");
        r = ZSTD_seekable_initFile(zs, f);
    } else {
        buf = readAll(argv[2], &size);
        r = ZSTD_seekable_initBuff(zs, buf, size);
    }
    if (ZSTD_isError(r)) { printf("ERR %d\n", (int)ZSTD_getErrorCode(r)); return 1; }
    unsigned char* const dst = malloc(len + 1);
    for (int round = 0; round < 2; round++) {
        r = ZSTD_seekable_decompress(zs, dst, len, offset);
        if (ZSTD_isError(r)) { printf("ERR %d\n", (int)ZSTD_getErrorCode(r)); return 1; }
    }
    printf("OK %zu %016llx\n", r, fnv(dst, r));
    return 0;
}

static int tableMode(int argc, char** argv)
{
    if (argc != 3) return 2;
    size_t size;
    unsigned char* const buf = readAll(argv[2], &size);
    ZSTD_seekable* const zs = ZSTD_seekable_create();
    size_t const r = ZSTD_seekable_initBuff(zs, buf, size);
    if (ZSTD_isError(r)) { printf("ERR %d\n", (int)ZSTD_getErrorCode(r)); return 1; }
    unsigned const n = ZSTD_seekable_getNumFrames(zs);
    ZSTD_seekTable* const st = ZSTD_seekTable_create_fromSeekable(zs);
    printf("frames %u\n", n);
    for (unsigned i = 0; i < n; i++)
        printf("%llu %llu %zu %zu\n", ZSTD_seekTable_getFrameCompressedOffset(st, i),
               ZSTD_seekTable_getFrameDecompressedOffset(st, i),
               ZSTD_seekTable_getFrameCompressedSize(st, i),
               ZSTD_seekTable_getFrameDecompressedSize(st, i));
    return 0;
}

int main(int argc, char** argv)
{
    if (argc < 2) return 2;
    switch (argv[1][0]) {
    case 'c': return compressMode(argc, argv);
    case 'd': return decompressMode(argc, argv);
    case 't': return tableMode(argc, argv);
    default: return 2;
    }
}
