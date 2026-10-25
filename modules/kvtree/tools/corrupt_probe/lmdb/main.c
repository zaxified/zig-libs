// SPDX-License-Identifier: MIT
// LMDB side of the damaged-file probe (backs the kvtree "never crashes on a
// damaged file" Ahead claim); liblmdb.so.0 with hand-written prototypes.
// Exit: 0 CLEAN, 10 WRONG, 11 ERROR.
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
typedef struct MDB_env MDB_env; typedef struct MDB_txn MDB_txn; typedef struct MDB_cursor MDB_cursor;
typedef unsigned int MDB_dbi;
typedef struct MDB_val { size_t mv_size; void *mv_data; } MDB_val;
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
int mdb_cursor_get(MDB_cursor *cursor, MDB_val *key, MDB_val *data, int op);
const char *mdb_strerror(int err);
#define MDB_NOSUBDIR 0x4000
#define MDB_NOTFOUND (-30798)
#define MDB_FIRST 0
#define MDB_NEXT 8
#define N 2000
static void fail(const char *what, int rc) { fprintf(stderr, "ERROR %s %d %s\n", what, rc, mdb_strerror(rc)); exit(11); }
static void key(char *b, int id) { snprintf(b, 10, "k%08d", id); }
static void val(unsigned char *v, int id) { for (int i = 0; i < 100; i++) v[i] = (unsigned char)((id + i) % 251); }
int main(int argc, char **argv) {
    if (argc < 3) return 2;
    char path[512]; snprintf(path, sizeof path, "%s/t.mdb", argv[2]);
    int build = !strcmp(argv[1], "build"), rc;
    MDB_env *env; MDB_txn *t; MDB_dbi dbi;
    if ((rc = mdb_env_create(&env))) fail("create", rc);
    mdb_env_set_mapsize(env, 64u << 20);
    if ((rc = mdb_env_open(env, path, MDB_NOSUBDIR, 0644))) fail("open", rc);
    if ((rc = mdb_txn_begin(env, NULL, 0, &t))) fail("txn", rc);
    if ((rc = mdb_dbi_open(t, NULL, 0, &dbi))) fail("dbi", rc);
    char kb[10]; unsigned char vb[100], exp[100];
    if (build) {
        for (int i = 0; i < N; i++) {
            key(kb, i); val(vb, i);
            MDB_val k = {9, kb}, v = {100, vb};
            if ((rc = mdb_put(t, dbi, &k, &v, 0))) fail("put", rc);
        }
        if ((rc = mdb_txn_commit(t))) fail("commit", rc);
        mdb_env_close(env);
        return 0;
    }
    const char *wrong = NULL; int structural = 0;
    for (int i = 0; i < N; i++) {
        key(kb, i); val(exp, i);
        MDB_val k = {9, kb}, v;
        rc = mdb_get(t, dbi, &k, &v);
        if (rc == MDB_NOTFOUND) structural = 1;
        else if (rc) fail("get", rc);
        else if (v.mv_size != 100 || memcmp(v.mv_data, exp, 100)) wrong = "value-only";
    }
    MDB_cursor *c;
    if ((rc = mdb_cursor_open(t, dbi, &c))) fail("cursor", rc);
    MDB_val k, v; int n = 0;
    rc = mdb_cursor_get(c, &k, &v, MDB_FIRST);
    while (rc == 0) {
        if (n >= N) { structural = 1; break; }
        key(kb, n); val(exp, n);
        if (k.mv_size != 9 || memcmp(k.mv_data, kb, 9)) structural = 1; else if (v.mv_size != 100 || memcmp(v.mv_data, exp, 100)) wrong = "value-only";
        n++;
        rc = mdb_cursor_get(c, &k, &v, MDB_NEXT);
    }
    if (rc && rc != MDB_NOTFOUND) fail("scan", rc);
    if (n != N) structural = 1;
    if (structural) wrong = "structural";
    mdb_txn_abort(t);
    mdb_env_close(env);
    if (wrong) { fprintf(stderr, "WRONG %s\n", wrong); return 10; }
    return 0;
}
