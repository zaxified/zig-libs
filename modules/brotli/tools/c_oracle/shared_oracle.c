// SPDX-License-Identifier: MIT
//
// google/brotli (libbrotlienc / libbrotlidec, 1.1.0+) as an oracle for what
// its Python binding cannot reach: raw prefix dictionaries (RFC 9841 §3.2,
// what RFC 9842 `dcb` uses) and the large window (RFC 9841 §6). Driven by
// `tools/interop.zig`; built there with `zig cc` against the system library.
//
//   shared_oracle enc <quality> <lgwin> <large 0|1> <dict|-> <in> <out>
//   shared_oracle dec <large 0|1> <dict|-> <in> <out>
//
// A dictionary argument `s:<path>` is a serialized shared dictionary (RFC
// 9841 §5); any other path a raw prefix dictionary.
//
// Exit 0 on success; 2 when the library refuses the stream (dec) or the
// parameters (enc); 1 on any other failure (I/O, memory).
#include <brotli/decode.h>
#include <brotli/encode.h>
#include <brotli/shared_dictionary.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* The dictionary type and path an argument names. */
static BrotliSharedDictionaryType dict_type(const char **path) {
    if (strncmp(*path, "s:", 2) == 0) {
        *path += 2;
        return BROTLI_SHARED_DICTIONARY_SERIALIZED;
    }
    return BROTLI_SHARED_DICTIONARY_RAW;
}

static unsigned char *slurp(const char *path, size_t *len) {
    *len = 0;
    if (strcmp(path, "-") == 0) return NULL;
    FILE *f = fopen(path, "rb");
    if (!f) exit(1);
    size_t cap = 1 << 16, n = 0;
    unsigned char *buf = malloc(cap);
    if (!buf) exit(1);
    for (;;) {
        if (n == cap) {
            cap *= 2;
            buf = realloc(buf, cap);
            if (!buf) exit(1);
        }
        size_t got = fread(buf + n, 1, cap - n, f);
        if (got == 0) break;
        n += got;
    }
    fclose(f);
    *len = n;
    return buf;
}

static void spill(const char *path, const unsigned char *data, size_t len) {
    FILE *f = fopen(path, "wb");
    if (!f || fwrite(data, 1, len, f) != len || fclose(f) != 0) exit(1);
}

static int enc(int quality, int lgwin, int large, const char *dict_path, const char *in_path, const char *out_path) {
    size_t dict_len, in_len;
    BrotliSharedDictionaryType type = dict_type(&dict_path);
    unsigned char *dict = slurp(dict_path, &dict_len);
    unsigned char *in = slurp(in_path, &in_len);
    BrotliEncoderState *s = BrotliEncoderCreateInstance(NULL, NULL, NULL);
    if (!s) return 1;
    if (!BrotliEncoderSetParameter(s, BROTLI_PARAM_QUALITY, (uint32_t)quality) ||
        !BrotliEncoderSetParameter(s, BROTLI_PARAM_LARGE_WINDOW, (uint32_t)large) ||
        !BrotliEncoderSetParameter(s, BROTLI_PARAM_LGWIN, (uint32_t)lgwin))
        return 2;
    BrotliEncoderPreparedDictionary *pd = NULL;
    if (dict) {
        pd = BrotliEncoderPrepareDictionary(type, dict_len, dict, BROTLI_MAX_QUALITY, NULL, NULL, NULL);
        if (!pd || !BrotliEncoderAttachPreparedDictionary(s, pd)) return 2;
    }
    size_t cap = in_len + (in_len >> 2) + 1024, out_len = 0;
    unsigned char *out = malloc(cap);
    if (!out) return 1;
    size_t avail_in = in_len, avail_out = cap;
    const uint8_t *next_in = in;
    uint8_t *next_out = out;
    while (!BrotliEncoderIsFinished(s)) {
        if (!BrotliEncoderCompressStream(s, BROTLI_OPERATION_FINISH, &avail_in, &next_in, &avail_out, &next_out, NULL)) return 2;
        if (avail_out == 0) {
            out_len = cap;
            cap *= 2;
            out = realloc(out, cap);
            if (!out) return 1;
            next_out = out + out_len;
            avail_out = cap - out_len;
        }
    }
    out_len = (size_t)(next_out - out);
    spill(out_path, out, out_len);
    BrotliEncoderDestroyInstance(s);
    if (pd) BrotliEncoderDestroyPreparedDictionary(pd);
    return 0;
}

static int dec(int large, const char *dict_path, const char *in_path, const char *out_path) {
    size_t dict_len, in_len;
    BrotliSharedDictionaryType type = dict_type(&dict_path);
    unsigned char *dict = slurp(dict_path, &dict_len);
    unsigned char *in = slurp(in_path, &in_len);
    BrotliDecoderState *s = BrotliDecoderCreateInstance(NULL, NULL, NULL);
    if (!s) return 1;
    if (!BrotliDecoderSetParameter(s, BROTLI_DECODER_PARAM_LARGE_WINDOW, (uint32_t)large)) return 2;
    if (dict && !BrotliDecoderAttachDictionary(s, type, dict_len, dict)) return 2;
    size_t cap = (in_len < 1024 ? 1024 : in_len) * 4, out_len = 0;
    unsigned char *out = malloc(cap);
    if (!out) return 1;
    size_t avail_in = in_len, avail_out = cap;
    const uint8_t *next_in = in;
    uint8_t *next_out = out;
    for (;;) {
        BrotliDecoderResult r = BrotliDecoderDecompressStream(s, &avail_in, &next_in, &avail_out, &next_out, NULL);
        if (r == BROTLI_DECODER_RESULT_SUCCESS) break;
        if (r == BROTLI_DECODER_RESULT_NEEDS_MORE_OUTPUT) {
            out_len = (size_t)(next_out - out);
            cap *= 2;
            out = realloc(out, cap);
            if (!out) return 1;
            next_out = out + out_len;
            avail_out = cap - out_len;
            continue;
        }
        return 2; // error, or input ended mid-stream
    }
    if (avail_in != 0) return 2; // bytes after the stream
    out_len = (size_t)(next_out - out);
    spill(out_path, out, out_len);
    BrotliDecoderDestroyInstance(s);
    return 0;
}

int main(int argc, char **argv) {
    if (argc == 8 && strcmp(argv[1], "enc") == 0)
        return enc(atoi(argv[2]), atoi(argv[3]), atoi(argv[4]), argv[5], argv[6], argv[7]);
    if (argc == 6 && strcmp(argv[1], "dec") == 0)
        return dec(atoi(argv[2]), argv[3], argv[4], argv[5]);
    fprintf(stderr, "usage: shared_oracle enc Q LGWIN LARGE DICT|- IN OUT | dec LARGE DICT|- IN OUT\n");
    return 1;
}
