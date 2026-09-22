#include "tidesdb_migration_format.h"
#include <ctype.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <tidesdb/db.h>
#include <unistd.h>

struct seen_key {
  uint32_t cf, size;
  unsigned char *data;
  struct seen_key *next;
};
struct stream_info {
  uint64_t records;
  uint32_t cfs;
};
static int fail(const char *s) {
  fprintf(stderr, "tidesdb10 import: %s\n", s);
  return 1;
}
static int bytes(FILE *f, SHA256_CTX *s, unsigned char **p, uint32_t n) {
  *p = malloc(n ? n : 1);
  return *p && ptm_read(f, s, *p, n);
}
static int safe_cf_name(const unsigned char *p, uint32_t n) {
  for (uint32_t i = 0; i < n; i++)
    if (!(isalnum(p[i]) || p[i] == '_'))
      return 0;
  return n != 0;
}
static void free_keys(struct seen_key *p) {
  while (p) {
    struct seen_key *next = p->next;
    free(p->data);
    free(p);
    p = next;
  }
}
static int start_db(const char *path, tidesdb_t **db) {
  tidesdb_config_t c = tidesdb_default_config();
  c.db_path = path;
  c.log_level = TDB_LOG_NONE;
  c.memtable_sync_mode = TDB_SYNC_FULL;
  return tidesdb_open(&c, db) == TDB_SUCCESS;
}
static int stream_sha256(const char *path,
                         char hex[SHA256_DIGEST_LENGTH * 2 + 1]) {
  FILE *f = fopen(path, "rb");
  SHA256_CTX sha;
  unsigned char b[4096], digest[SHA256_DIGEST_LENGTH];
  size_t n;
  if (!f || SHA256_Init(&sha) != 1)
    return 0;
  while ((n = fread(b, 1, sizeof(b), f)) != 0)
    if (SHA256_Update(&sha, b, n) != 1) {
      fclose(f);
      return 0;
    }
  if (ferror(f) || fclose(f) || SHA256_Final(digest, &sha) != 1)
    return 0;
  for (size_t i = 0; i < sizeof(digest); i++)
    sprintf(hex + i * 2, "%02x", digest[i]);
  return 1;
}

/* Validate the complete untrusted stream before a destination is ever created.
 */
static int scan_stream(const char *stream, struct stream_info *info) {
  FILE *in = fopen(stream, "rb");
  SHA256_CTX sha;
  char *cfs[128] = {0};
  struct seen_key *keys = 0;
  uint32_t cf = 0, ncf = 0;
  uint64_t records = 0;
  int ok = 0;
  if (!in || !ptm_header_read(in, &sha))
    goto done;
  for (;;) {
    unsigned char type;
    if (fread(&type, 1, 1, in) != 1)
      goto done;
    if (type == PRODIGY_TIDES_MIGRATION_END) {
      if (fseek(in, -1, SEEK_CUR) || !ptm_finish_read(in, &sha, records))
        goto done;
      info->records = records;
      info->cfs = ncf;
      ok = 1;
      goto done;
    }
    if (SHA256_Update(&sha, &type, 1) != 1)
      goto done;
    if (type == PRODIGY_TIDES_MIGRATION_CF) {
      uint32_t n;
      unsigned char *name = 0;
      if (!ptm_u32_read(in, &sha, &n) || n > PRODIGY_TIDES_MIGRATION_MAX_NAME ||
          !bytes(in, &sha, &name, n) || ncf == 128 || !safe_cf_name(name, n)) {
        free(name);
        goto done;
      }
      for (uint32_t i = 0; i < ncf; i++)
        if (strlen(cfs[i]) == n && !memcmp(cfs[i], name, n)) {
          free(name);
          goto done;
        }
      cfs[ncf] = malloc(n + 1);
      if (!cfs[ncf]) {
        free(name);
        goto done;
      }
      memcpy(cfs[ncf], name, n);
      cfs[ncf++][n] = 0;
      free(name);
      cf = ncf;
      continue;
    }
    if (type != PRODIGY_TIDES_MIGRATION_RECORD || cf == 0)
      goto done;
    uint32_t ks, vs;
    unsigned char *k = 0, *v = 0;
    if (!ptm_u32_read(in, &sha, &ks) || !ptm_u32_read(in, &sha, &vs) ||
        ks == 0 || ks > PRODIGY_TIDES_MIGRATION_MAX_BYTES ||
        vs > PRODIGY_TIDES_MIGRATION_MAX_BYTES || !bytes(in, &sha, &k, ks) ||
        !bytes(in, &sha, &v, vs)) {
      free(k);
      free(v);
      goto done;
    }
    free(v);
    for (struct seen_key *x = keys; x; x = x->next)
      if (x->cf == cf && x->size == ks && !memcmp(x->data, k, ks)) {
        free(k);
        goto done;
      }
    struct seen_key *x = calloc(1, sizeof(*x));
    if (!x) {
      free(k);
      goto done;
    }
    x->cf = cf;
    x->size = ks;
    x->data = k;
    x->next = keys;
    keys = x;
    ++records;
  }
done:
  for (uint32_t i = 0; i < ncf; i++)
    free(cfs[i]);
  free_keys(keys);
  if (in)
    fclose(in);
  return ok;
}

static int count_actual(tidesdb_t *db, uint64_t *records, uint32_t *cfs) {
  char **names = 0;
  int n = 0;
  if (tidesdb_list_column_families(db, &names, &n) != TDB_SUCCESS)
    return 0;
  *records = 0;
  *cfs = (uint32_t)n;
  for (int i = 0; i < n; i++) {
    tidesdb_txn_t *tx = 0;
    tidesdb_iter_t *it = 0;
    int seek;
    if (!names[i] || (tidesdb_txn_begin(db, &tx) != TDB_SUCCESS) ||
        (tidesdb_iter_new(tx, tidesdb_get_column_family(db, names[i]), &it) !=
         TDB_SUCCESS)) {
      if (tx)
        tidesdb_txn_free(tx);
      goto bad;
    }
    seek = tidesdb_iter_seek_to_first(it);
    if (seek != TDB_SUCCESS && seek != TDB_ERR_NOT_FOUND) {
      tidesdb_iter_free(it);
      tidesdb_txn_rollback(tx);
      tidesdb_txn_free(tx);
      goto bad;
    }
    while (tidesdb_iter_valid(it)) {
      ++*records;
      int next = tidesdb_iter_next(it);
      if (next != TDB_SUCCESS) {
        if (next != TDB_ERR_NOT_FOUND) {
          tidesdb_iter_free(it);
          tidesdb_txn_rollback(tx);
          tidesdb_txn_free(tx);
          goto bad;
        }
        break;
      }
    }
    tidesdb_iter_free(it);
    tidesdb_txn_rollback(tx);
    tidesdb_txn_free(tx);
  }
  for (int i = 0; i < n; i++)
    tidesdb_free(names[i]);
  tidesdb_free(names);
  return 1;
bad:
  for (int j = 0; j < n; j++)
    tidesdb_free(names[j]);
  tidesdb_free(names);
  return 0;
}

/* Each expected get catches omissions/changes; enumeration catches additions.
 */
static int verify(const char *stream, const char *path,
                  const struct stream_info *info) {
  FILE *in = fopen(stream, "rb");
  SHA256_CTX sha;
  tidesdb_t *db = 0;
  tidesdb_column_family_t *cf = 0;
  uint64_t count = 0, actual = 0;
  uint32_t cfs = 0;
  int ok = 0;
  if (!in || !ptm_header_read(in, &sha) || !start_db(path, &db))
    goto done;
  for (;;) {
    unsigned char type;
    if (fread(&type, 1, 1, in) != 1)
      goto done;
    if (type == PRODIGY_TIDES_MIGRATION_END) {
      if (fseek(in, -1, SEEK_CUR) || !ptm_finish_read(in, &sha, count))
        goto done;
      ok = count_actual(db, &actual, &cfs) && actual == info->records &&
           cfs == info->cfs;
      goto done;
    }
    if (SHA256_Update(&sha, &type, 1) != 1)
      goto done;
    if (type == PRODIGY_TIDES_MIGRATION_CF) {
      uint32_t n;
      unsigned char *name = 0;
      char z[129];
      if (!ptm_u32_read(in, &sha, &n) || n > 128 ||
          !bytes(in, &sha, &name, n)) {
        free(name);
        goto done;
      }
      memcpy(z, name, n);
      z[n] = 0;
      free(name);
      cf = tidesdb_get_column_family(db, z);
      if (!cf)
        goto done;
      continue;
    }
    uint32_t ks, vs;
    unsigned char *k = 0, *want = 0, *got = 0;
    size_t gs = 0;
    tidesdb_txn_t *tx = 0;
    int rc;
    if (type != PRODIGY_TIDES_MIGRATION_RECORD || !cf ||
        !ptm_u32_read(in, &sha, &ks) || !ptm_u32_read(in, &sha, &vs) ||
        !bytes(in, &sha, &k, ks) || !bytes(in, &sha, &want, vs)) {
      free(k);
      free(want);
      goto done;
    }
    rc = tidesdb_txn_begin(db, &tx);
    if (rc == TDB_SUCCESS)
      rc = tidesdb_txn_get(tx, cf, k, ks, &got, &gs);
    if (tx) {
      tidesdb_txn_rollback(tx);
      tidesdb_txn_free(tx);
    }
    if (rc != TDB_SUCCESS || gs != vs || memcmp(got, want, vs)) {
      free(k);
      free(want);
      tidesdb_free(got);
      goto done;
    }
    free(k);
    free(want);
    tidesdb_free(got);
    ++count;
  }
done:
  if (db && tidesdb_close(db) != TDB_SUCCESS)
    ok = 0;
  if (in)
    fclose(in);
  return ok;
}

int main(int argc, char **argv) {
  struct stream_info info = {0};
  if (argc == 4 && strcmp(argv[1], "--verify") == 0) {
    char hex[SHA256_DIGEST_LENGTH * 2 + 1];
    if (!scan_stream(argv[2], &info) || !verify(argv[2], argv[3], &info) ||
        !stream_sha256(argv[2], hex))
      return fail("logical verification failed");
    printf("{\"records\":%llu,\"columnFamilies\":%u,\"streamSHA256\":\"%s\"}\n",
           (unsigned long long)info.records, info.cfs, hex);
    return 0;
  }
  if (argc != 3)
    return fail("usage STREAM NEW_DB | --verify STREAM DB");
  if (access(argv[1], R_OK) || access(argv[2], F_OK) == 0)
    return fail("stream unreadable or destination exists");
  if (!scan_stream(argv[1], &info))
    return fail("invalid stream");
  umask(0077);
  FILE *in = fopen(argv[1], "rb");
  SHA256_CTX sha;
  tidesdb_t *db = 0;
  tidesdb_column_family_t *cf = 0;
  uint64_t count = 0;
  if (!in || !ptm_header_read(in, &sha) || !start_db(argv[2], &db))
    return fail("cannot create v10 database");
  for (;;) {
    unsigned char type;
    if (fread(&type, 1, 1, in) != 1)
      return fail("truncated stream");
    if (type == PRODIGY_TIDES_MIGRATION_END) {
      if (fseek(in, -1, SEEK_CUR) || !ptm_finish_read(in, &sha, count))
        return fail("stream digest");
      break;
    }
    if (SHA256_Update(&sha, &type, 1) != 1)
      return fail("stream hash");
    if (type == PRODIGY_TIDES_MIGRATION_CF) {
      uint32_t n;
      unsigned char *name = 0;
      char z[129];
      tidesdb_column_family_config_t c;
      if (!ptm_u32_read(in, &sha, &n) || !bytes(in, &sha, &name, n))
        return fail("invalid cf");
      memcpy(z, name, n);
      z[n] = 0;
      free(name);
      c = tidesdb_default_column_family_config();
      if (tidesdb_create_column_family(db, z, &c) != TDB_SUCCESS)
        return fail("create cf");
      cf = tidesdb_get_column_family(db, z);
      continue;
    }
    uint32_t ks, vs;
    unsigned char *k = 0, *v = 0;
    tidesdb_txn_t *tx = 0;
    int rc;
    if (!ptm_u32_read(in, &sha, &ks) || !ptm_u32_read(in, &sha, &vs) ||
        !bytes(in, &sha, &k, ks) || !bytes(in, &sha, &v, vs))
      return fail("invalid record");
    rc = tidesdb_txn_begin(db, &tx);
    if (rc == TDB_SUCCESS)
      rc = tidesdb_txn_put(tx, cf, k, ks, v, vs, 0);
    if (rc == TDB_SUCCESS)
      rc = tidesdb_txn_commit(tx);
    else if (tx)
      tidesdb_txn_rollback(tx);
    if (tx)
      tidesdb_txn_free(tx);
    free(k);
    free(v);
    if (rc != TDB_SUCCESS)
      return fail("write record");
    ++count;
  }
  if (tidesdb_close(db) != TDB_SUCCESS || fclose(in) != 0)
    return fail("import close");
  if (!verify(argv[1], argv[2], &info))
    return fail("reopen readback validation");
  return 0;
}
