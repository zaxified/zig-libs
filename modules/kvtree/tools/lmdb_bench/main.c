// SPDX-License-Identifier: MIT
//
// LMDB side of `zig build bench-kvtree` (modules/kvtree/tools/bench.zig): the
// "fastest in the field" of the card. Times LMDB through its public C API for
// the one workload named by the second argument, in the directory given as the
// first. Prints one line: name, ns/op, result count (tab-separated); the banner
// (library and version) on stderr.
//
// Links the host's liblmdb.so.0 (Ubuntu liblmdb0, LMDB 0.9.31); nothing of
// LMDB is compiled or copied here. The -dev header is not installed, so the
// few prototypes below are LMDB's documented public API (lmdb.h, 0.9.x ABI).
//
// Data and timing are those of tools/go_bench/main.go: N = 100000 keys
// "k%08d" of the splitmix64 permutation (seed 0x6b767472), 100-byte values
// with byte i = (id+i) % 251, loaded in one synced transaction before the row.
// Rows:
//
//	get_hit        getN gets, permuted order, one read txn per op; the value
//	               is copied out of the mmap into a reused buffer
//	bucket_get     the same (LMDB's unnamed main database plays the bucket)
//	scan           full ordered cursor scan
//	put_txn_1k     one write txn of 1000 puts of NEW keys + commit (fsync:
//	               default flags, no MDB_NOSYNC)
//	update_txn_1k  the same, overwriting 1000 existing keys
//
// Timing: double the batch until one batch takes over 100 ms, then keep the
// best of five.
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

typedef struct MDB_env MDB_env;
typedef struct MDB_txn MDB_txn;
typedef struct MDB_cursor MDB_cursor;
typedef unsigned int MDB_dbi;
typedef struct MDB_val {
    size_t mv_size;
    void *mv_data;
} MDB_val;
int mdb_env_create(MDB_env **env);
int mdb_env_set_mapsize(MDB_env *env, size_t size);
int mdb_env_open(MDB_env *env, const char *path, unsigned int flags, mode_t mode);
void mdb_env_close(MDB_env *env);
int mdb_txn_begin(MDB_env *env, MDB_txn *parent, unsigned int flags, MDB_txn **txn);
int mdb_txn_commit(MDB_txn *txn);
void mdb_txn_abort(MDB_txn *txn);
int mdb_dbi_open(MDB_txn *txn, const char *name, unsigned int flags, MDB_dbi *dbi);
int mdb_get(MDB_txn *txn, MDB_dbi dbi, MDB_val *key, MDB_val *data);
int mdb_put(MDB_txn *txn, MDB_dbi dbi, MDB_val *key, MDB_val *data, unsigned int flags);
int mdb_cursor_open(MDB_txn *txn, MDB_dbi dbi, MDB_cursor **cursor);
void mdb_cursor_close(MDB_cursor *cursor);
int mdb_cursor_get(MDB_cursor *cursor, MDB_val *key, MDB_val *data, int op);
const char *mdb_strerror(int err);
char *mdb_version(int *major, int *minor, int *patch);
#define MDB_NOSUBDIR 0x4000
#define MDB_RDONLY 0x20000
#define MDB_FIRST 0
#define MDB_NEXT 8

enum { N_KEYS = 100000, VAL_LEN = 100, GET_N = 20000, BATCH_W = 1000 };
static const uint64_t SEED = 0x6b767472;

static uint32_t perm[N_KEYS];
static char keys[N_KEYS][9];
static MDB_env *env;
static MDB_dbi dbi;
static volatile long sink;
static long pos, gen;
static unsigned char vbuf[VAL_LEN], out[VAL_LEN];

static void chk(int rc, const char *what) {
    if (rc) {
        fprintf(stderr, "%s: %s\n", what, mdb_strerror(rc));
        exit(1);
    }
}

static uint64_t splitmix(uint64_t *s) {
    uint64_t z = (*s += 0x9e3779b97f4a7c15ull);
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ull;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebull;
    return z ^ (z >> 31);
}

static void put_key(char *b, uint32_t id) {
    b[0] = 'k';
    for (int i = 8; i >= 1; i--) {
        b[i] = (char)('0' + id % 10);
        id /= 10;
    }
}

static void fill_val(unsigned char *v, uint32_t id) {
    for (int i = 0; i < VAL_LEN; i++) v[i] = (unsigned char)(((uint64_t)id + (uint64_t)i) % 251);
}

static double now_ns(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (double)t.tv_sec * 1e9 + (double)t.tv_nsec;
}

static long write_txn(int update) {
    long s = 0;
    MDB_txn *t;
    char kb[9];
    chk(mdb_txn_begin(env, NULL, 0, &t), "txn");
    for (int j = 0; j < BATCH_W; j++) {
        uint32_t id;
        MDB_val k = {9, NULL};
        if (update) {
            id = perm[(pos + j) % N_KEYS];
            k.mv_data = keys[id];
        } else {
            id = (uint32_t)(N_KEYS + pos + j);
            put_key(kb, id);
            k.mv_data = kb;
        }
        fill_val(vbuf, id + (uint32_t)gen);
        MDB_val v = {VAL_LEN, vbuf};
        chk(mdb_put(t, dbi, &k, &v, 0), "put");
        s += 1 + VAL_LEN;
    }
    chk(mdb_txn_commit(t), "commit");
    pos += BATCH_W;
    gen++;
    return s;
}

static long op(const char *name) {
    if (!strcmp(name, "get_hit") || !strcmp(name, "bucket_get")) {
        MDB_txn *t;
        chk(mdb_txn_begin(env, NULL, MDB_RDONLY, &t), "rtxn");
        long s = 0;
        for (int i = 0; i < GET_N; i++) {
            MDB_val k = {9, keys[perm[i]]}, v;
            if (mdb_get(t, dbi, &k, &v) == 0) {
                memcpy(out, v.mv_data, v.mv_size);
                s += 1 + (long)v.mv_size;
            }
        }
        mdb_txn_abort(t);
        return s;
    }
    if (!strcmp(name, "scan")) {
        MDB_txn *t;
        MDB_cursor *c;
        chk(mdb_txn_begin(env, NULL, MDB_RDONLY, &t), "rtxn");
        chk(mdb_cursor_open(t, dbi, &c), "cursor");
        long s = 0;
        MDB_val k, v;
        for (int rc = mdb_cursor_get(c, &k, &v, MDB_FIRST); rc == 0; rc = mdb_cursor_get(c, &k, &v, MDB_NEXT))
            s += 1 + (long)v.mv_size;
        mdb_cursor_close(c);
        mdb_txn_abort(t);
        return s;
    }
    if (!strcmp(name, "put_txn_1k")) return write_txn(0);
    if (!strcmp(name, "update_txn_1k")) return write_txn(1);
    fprintf(stderr, "unknown workload %s\n", name);
    exit(2);
}

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "usage: lmdb_bench <work dir> <workload>\n");
        return 2;
    }
    const char *name = argv[2];
    fprintf(stderr, "%s\n", mdb_version(NULL, NULL, NULL));
    for (uint32_t i = 0; i < N_KEYS; i++) {
        perm[i] = i;
        put_key(keys[i], i);
    }
    uint64_t st = SEED;
    for (int i = N_KEYS - 1; i > 0; i--) {
        int j = (int)(splitmix(&st) % (uint64_t)(i + 1));
        uint32_t x = perm[i];
        perm[i] = perm[j];
        perm[j] = x;
    }
    char path[4096], lock[4200];
    snprintf(path, sizeof path, "%s/lmdb-%s.db", argv[1], name);
    snprintf(lock, sizeof lock, "%s-lock", path);
    unlink(path);
    unlink(lock);

    chk(mdb_env_create(&env), "env_create");
    chk(mdb_env_set_mapsize(env, (size_t)1 << 32), "mapsize");
    chk(mdb_env_open(env, path, MDB_NOSUBDIR, 0600), "env_open");
    MDB_txn *t;
    chk(mdb_txn_begin(env, NULL, 0, &t), "txn");
    chk(mdb_dbi_open(t, NULL, 0, &dbi), "dbi");
    for (int i = 0; i < N_KEYS; i++) {
        uint32_t id = perm[i];
        fill_val(vbuf, id);
        MDB_val k = {9, keys[id]}, v = {VAL_LEN, vbuf};
        chk(mdb_put(t, dbi, &k, &v, 0), "put");
    }
    chk(mdb_txn_commit(t), "commit");

    long n = 1, count = 0;
    for (;;) {
        double t0 = now_ns();
        for (long i = 0; i < n; i++) sink += op(name);
        if (now_ns() - t0 > 100e6) break;
        n *= 2;
    }
    double best = 1e300;
    for (int r = 0; r < 5; r++) {
        double t0 = now_ns();
        for (long i = 0; i < n; i++) count = op(name);
        double d = now_ns() - t0;
        if (d < best) best = d;
    }
    mdb_env_close(env);
    unlink(path);
    unlink(lock);
    printf("%s\t%.1f\t%ld\n", name, best / (double)n, count);
    return 0;
}
