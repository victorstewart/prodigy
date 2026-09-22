#define _XOPEN_SOURCE 700
#define _POSIX_C_SOURCE 200809L
#include "tidesdb_migration_format.h"
#include <ctype.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <tidesdb/db.h>
#include <time.h>
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
static int verify(const char *stream, const char *path,
                  const struct stream_info *info);
static int stream_sha256(const char *path,
                         char hex[SHA256_DIGEST_LENGTH * 2 + 1]);
static int scan_stream(const char *stream, struct stream_info *info);
static int fail(const char *s) {
  fprintf(stderr, "tidesdb10 import: %s\n", s);
  return 1;
}
static int compact_fail(const char *stage, int rc) {
  if (rc == INT_MIN)
    fprintf(stderr, "tidesdb10 import: compact stage=%s rc=unavailable\n", stage);
  else
    fprintf(stderr, "tidesdb10 import: compact stage=%s rc=%d\n", stage, rc);
  return 1;
}
static int bytes(FILE *f, SHA256_CTX *s, unsigned char **p, uint32_t n) {
  // Reject impossible lengths before allocating, including truncated streams
  // that declare a multi-gigabyte value. Valid snapshots use the full wire range.
  struct stat st;
  off_t offset = ftello(f);
  if (offset < 0 || fstat(fileno(f), &st) || !S_ISREG(st.st_mode) ||
      st.st_size < offset || (uint64_t)n > (uint64_t)(st.st_size - offset))
    return 0;
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
static int open_db(const char *path, tidesdb_t **db) {
  tidesdb_config_t c = tidesdb_default_config();
  c.db_path = path;
  c.log_level = TDB_LOG_NONE;
  c.memtable_sync_mode = TDB_SYNC_FULL;
  return tidesdb_open(&c, db);
}
static int start_db(const char *path, tidesdb_t **db) {
  return open_db(path, db) == TDB_SUCCESS;
}

static int compare_cf_names(const void *a, const void *b) {
  const char *const *left = a;
  const char *const *right = b;
  return strcmp(*left, *right);
}

/* Mothership fences the caller.  Do not let the engine's create-on-open
 * behavior turn a typo into a new database. */
static int compact_db_path_ok(const char *path) {
  struct stat st;
  char *resolved;
  int fd;
  if (!path || path[0] != '/' || !(resolved = realpath(path, 0)))
    return 0;
  if (strcmp(resolved, path) != 0 || lstat(path, &st) || !S_ISDIR(st.st_mode) ||
      st.st_uid != 0 || S_ISLNK(st.st_mode)) {
    free(resolved);
    return 0;
  }
  free(resolved);
  fd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
  if (fd < 0)
    return 0;
  close(fd);
  return 1;
}

static int fsync_parent_directory(const char *path) {
  char *parent = strdup(path);
  char *slash;
  int fd, ok;
  if (!parent)
    return 0;
  slash = strrchr(parent, '/');
  if (!slash)
    strcpy(parent, ".");
  else if (slash == parent)
    slash[1] = 0;
  else
    *slash = 0;
  fd = open(parent, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  free(parent);
  if (fd < 0)
    return 0;
  ok = fsync(fd) == 0;
  close(fd);
  return ok;
}

static char *compact_partial_path(const char *path) {
  const size_t n = strlen(path);
  char *partial = malloc(n + sizeof(".partial"));
  if (partial) {
    memcpy(partial, path, n);
    memcpy(partial + n, ".partial", sizeof(".partial"));
  }
  return partial;
}

/* The compact receipt is the existing PT9T10KV format.  Keeping the same
 * codec makes a durable pre-maintenance snapshot directly verifier-readable. */
static int export_actual(tidesdb_t *db, const char *stream,
                         struct stream_info *info) {
  FILE *out = 0;
  char **names = 0;
  tidesdb_txn_t *tx = 0;
  tidesdb_iter_t *it = 0;
  char *partial = 0;
  int n = 0, fd = -1, ok = 0;
  uint64_t count = 0;
  SHA256_CTX sha;
  if (!db || !stream || tidesdb_list_column_families(db, &names, &n) != TDB_SUCCESS ||
      n < 0 || n > 128)
    goto done;
  for (int i = 0; i < n; ++i)
    if (!names[i] || !safe_cf_name((const unsigned char *)names[i],
                                   (uint32_t)strlen(names[i])))
      goto done;
  if (n)
    qsort(names, (size_t)n, sizeof(*names), compare_cf_names);
  if (!(partial = compact_partial_path(stream)))
    goto done;
  fd = open(partial, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
            0600);
  if (fd < 0 || fchmod(fd, 0600) || !(out = fdopen(fd, "wb")))
    goto done;
  fd = -1;
  if (!ptm_header_write(out, &sha))
    goto done;
  for (int i = 0; i < n; ++i) {
    tidesdb_column_family_t *cf;
    unsigned char type = PRODIGY_TIDES_MIGRATION_CF;
    size_t name_size = names[i] ? strlen(names[i]) : 0;
    int seek;
    if (!name_size || name_size > PRODIGY_TIDES_MIGRATION_MAX_NAME ||
        !ptm_write(out, &sha, &type, 1) ||
        !ptm_u32_write(out, &sha, (uint32_t)name_size) ||
        !ptm_write(out, &sha, names[i], name_size))
      goto done;
    cf = tidesdb_get_column_family(db, names[i]);
    if (!cf || tidesdb_txn_begin(db, &tx) != TDB_SUCCESS ||
        tidesdb_iter_new(tx, cf, &it) != TDB_SUCCESS)
      goto done;
    seek = tidesdb_iter_seek_to_first(it);
    if (seek != TDB_SUCCESS && seek != TDB_ERR_NOT_FOUND)
      goto done;
    while (tidesdb_iter_valid(it)) {
      uint8_t *key = 0, *value = 0;
      size_t key_size = 0, value_size = 0;
      type = PRODIGY_TIDES_MIGRATION_RECORD;
      if (tidesdb_iter_key_value(it, &key, &key_size, &value, &value_size) !=
              TDB_SUCCESS ||
          key_size > PRODIGY_TIDES_MIGRATION_MAX_BYTES ||
          value_size > PRODIGY_TIDES_MIGRATION_MAX_BYTES ||
          !ptm_write(out, &sha, &type, 1) ||
          !ptm_u32_write(out, &sha, (uint32_t)key_size) ||
          !ptm_u32_write(out, &sha, (uint32_t)value_size) ||
          !ptm_write(out, &sha, key, key_size) ||
          !ptm_write(out, &sha, value, value_size)) {
        tidesdb_free(key);
        tidesdb_free(value);
        goto done;
      }
      tidesdb_free(key);
      tidesdb_free(value);
      ++count;
      int next = tidesdb_iter_next(it);
      if (next != TDB_SUCCESS) {
        if (next != TDB_ERR_NOT_FOUND)
          goto done;
        break;
      }
    }
    tidesdb_iter_free(it);
    it = 0;
    tidesdb_txn_rollback(tx);
    tidesdb_txn_free(tx);
    tx = 0;
  }
  if (!ptm_finish_write(out, &sha, count) || fflush(out) || fsync(fileno(out)) ||
      fclose(out) || !fsync_parent_directory(partial) || rename(partial, stream) ||
      !fsync_parent_directory(stream)) {
    out = 0;
    goto done;
  }
  out = 0;
  info->records = count;
  info->cfs = (uint32_t)n;
  ok = 1;
done:
  if (it)
    tidesdb_iter_free(it);
  if (tx) {
    tidesdb_txn_rollback(tx);
    tidesdb_txn_free(tx);
  }
  if (out)
    fclose(out);
  else if (fd >= 0)
    close(fd);
  if (names) {
    for (int i = 0; i < n; ++i)
      tidesdb_free(names[i]);
    tidesdb_free(names);
  }
  free(partial);
  return ok;
}

static int compact_all_column_families(tidesdb_t *db, char **names, int n) {
  for (int i = 0; i < n; ++i) {
    tidesdb_column_family_t *cf = names[i] ? tidesdb_get_column_family(db, names[i]) : 0;
    int rc;
    if (!cf)
      return INT_MIN;
    rc = tidesdb_compact(db, cf);
    if (rc != TDB_SUCCESS)
      return rc;
  }
  return TDB_SUCCESS;
}

static int compact_wait_for_cf_idle(tidesdb_t *db, char **names, int n) {
  const int attempts = 100; /* one bounded ten-second wait before one retry */
  struct timespec pause = {.tv_sec = 0, .tv_nsec = 100000000};
  for (int i = 0; i < attempts; ++i) {
    int busy = tidesdb_is_flushing(db);
    for (int cf_index = 0; !busy && cf_index < n; ++cf_index) {
      tidesdb_column_family_t *cf = tidesdb_get_column_family(db, names[cf_index]);
      if (!cf)
        return 0;
      busy = tidesdb_is_compacting(cf);
    }
    if (!busy)
      return 1;
    nanosleep(&pause, 0);
  }
  return 0;
}

static int compact_wait_for_vlog(tidesdb_t *db, char **names, int n,
                                 uint64_t reclaim_calls_before,
                                 tidesdb_db_stats_t *stats) {
  const int attempts = 300; /* 30 seconds; the engine ticks its reaper each second. */
  const uint64_t reclaim_threshold = 256ULL * 1024 * 1024;
  struct timespec pause = {.tv_sec = 0, .tv_nsec = 100000000};
  int saw_actionable = 0, followup_compaction = 0;
  for (int i = 0; i < attempts; ++i) {
    if (tidesdb_get_db_stats(db, stats) != TDB_SUCCESS)
      return 0;
    if (stats->vlog_dead_bytes >= reclaim_threshold &&
        stats->vlog_segment_count >= 2)
      saw_actionable = 1;
    int compacting = tidesdb_is_flushing(db);
    for (int cf_index = 0; !compacting && cf_index < n; ++cf_index) {
      tidesdb_column_family_t *cf = tidesdb_get_column_family(db, names[cf_index]);
      if (!cf)
        return 0;
      compacting = tidesdb_is_compacting(cf);
    }
    /* Two reaper ticks give a scheduled VLOG pass time to begin.  If it marks
     * drainable segments, one further forced CF pass carries those values out. */
    if (i >= 20 && !compacting && stats->vlog_segments_drainable &&
        !followup_compaction) {
      if (compact_all_column_families(db, names, n) != TDB_SUCCESS)
        return 0;
      followup_compaction = 1;
      continue;
    }
    if (i >= 20 && !compacting && stats->compaction_pending_count == 0 &&
        stats->vlog_segments_drainable == 0 &&
        (!saw_actionable || stats->vlog_reclaim_calls > reclaim_calls_before))
      return 1;
    nanosleep(&pause, 0);
  }
  return tidesdb_get_db_stats(db, stats) == TDB_SUCCESS ? -1 : 0;
}

static int compact_database(const char *path, const char *baseline) {
  tidesdb_t *db = 0;
  char **names = 0;
  int n = 0, wait;
  struct stream_info info = {0};
  tidesdb_db_stats_t before = {0}, after = {0};
  char digest[SHA256_DIGEST_LENGTH * 2 + 1];
  struct stat receipt_st, partial_st;
  char *partial = 0;
  int have_receipt, receipt_errno, partial_exists;
  const char *failure_stage = "unknown";
  int failure_rc = INT_MIN;
  int rc;
  int ok = 0;
  if (!compact_db_path_ok(path) || !baseline)
    return fail("compact requires an existing root-owned database");
  have_receipt = lstat(baseline, &receipt_st) == 0;
  receipt_errno = errno;
  partial = compact_partial_path(baseline);
  partial_exists = partial && lstat(partial, &partial_st) == 0;
  if (!partial || partial_exists || errno != ENOENT) {
    free(partial);
    return fail("compact baseline partial receipt exists");
  }
  free(partial);
  if ((!have_receipt && receipt_errno != ENOENT) ||
      (have_receipt && (!S_ISREG(receipt_st.st_mode) ||
                        S_ISLNK(receipt_st.st_mode) || receipt_st.st_uid != 0 ||
                        receipt_st.st_nlink != 1 ||
                        (receipt_st.st_mode & 0777) != 0600)))
    return fail("compact baseline is not an absent or root-owned regular file");
  if (have_receipt) {
    if (!scan_stream(baseline, &info) || !verify(baseline, path, &info) ||
        !stream_sha256(baseline, digest)) {
      failure_stage = "baselineVerify";
      goto done;
    }
  }
  if ((rc = open_db(path, &db)) != TDB_SUCCESS) {
    failure_stage = "open";
    failure_rc = rc;
    goto done;
  }
  if ((rc = tidesdb_get_db_stats(db, &before)) != TDB_SUCCESS) {
    failure_stage = "beforeStats";
    failure_rc = rc;
    goto done;
  }
  if (!have_receipt &&
      (!export_actual(db, baseline, &info) || !scan_stream(baseline, &info) ||
       !stream_sha256(baseline, digest))) {
    failure_stage = "baselineExport";
    goto done;
  }
  if ((rc = tidesdb_flush_memtable(db)) != TDB_SUCCESS) {
    failure_stage = "flush";
    failure_rc = rc;
    goto done;
  }
  if ((rc = tidesdb_list_column_families(db, &names, &n)) != TDB_SUCCESS || n < 0) {
    failure_stage = "listColumnFamilies";
    failure_rc = rc;
    goto done;
  }
  for (int i = 0; i < n; ++i)
    if (!names[i]) {
      failure_stage = "listColumnFamilies";
      goto done;
    }
  if (n)
    qsort(names, (size_t)n, sizeof(*names), compare_cf_names);
  rc = compact_all_column_families(db, names, n);
  if (rc == TDB_ERR_LOCKED && compact_wait_for_cf_idle(db, names, n))
    rc = compact_all_column_families(db, names, n);
  if (rc != TDB_SUCCESS) {
    failure_stage = "compact";
    failure_rc = rc;
    goto done;
  }
  wait = compact_wait_for_vlog(db, names, n, before.vlog_reclaim_calls, &after);
  if (wait == 0) {
    failure_stage = "vlogWait";
    goto done;
  }
  if (wait < 0) {
    printf("{\"reclaimComplete\":false,\"vlogFileBytes\":%llu,\"vlogSegments\":%llu,\"vlogDeadBytes\":%llu,\"vlogDrainableSegments\":%llu,\"vlogReclaimCalls\":%llu,\"vlogSegmentsRetired\":%llu,\"compactionPending\":%d}\n",
           (unsigned long long)after.vlog_file_size,
           (unsigned long long)after.vlog_segment_count,
           (unsigned long long)after.vlog_dead_bytes,
           (unsigned long long)after.vlog_segments_drainable,
           (unsigned long long)after.vlog_reclaim_calls,
           (unsigned long long)after.vlog_segments_retired,
           after.compaction_pending_count);
    failure_stage = "vlogTimeout";
    goto done;
  }
  if ((rc = tidesdb_close(db)) != TDB_SUCCESS) {
    db = 0;
    failure_stage = "close";
    failure_rc = rc;
    goto done;
  }
  db = 0;
  if (!compact_db_path_ok(path) || !verify(baseline, path, &info)) {
    failure_stage = "readbackVerify";
    goto done;
  }
  printf("{\"reclaimComplete\":true,\"records\":%llu,\"columnFamilies\":%u,\"logicalSHA256\":\"%s\",\"vlogFileBytesBefore\":%llu,\"vlogFileBytesAfter\":%llu,\"vlogSegmentsBefore\":%llu,\"vlogSegmentsAfter\":%llu,\"vlogDeadBytesBefore\":%llu,\"vlogDeadBytesAfter\":%llu,\"vlogDrainableSegmentsAfter\":%llu,\"vlogReclaimCallsBefore\":%llu,\"vlogReclaimCallsAfter\":%llu,\"vlogSegmentsRetiredBefore\":%llu,\"vlogSegmentsRetiredAfter\":%llu,\"compactionPendingAfter\":%d}\n",
         (unsigned long long)info.records, info.cfs, digest,
         (unsigned long long)before.vlog_file_size,
         (unsigned long long)after.vlog_file_size,
         (unsigned long long)before.vlog_segment_count,
         (unsigned long long)after.vlog_segment_count,
         (unsigned long long)before.vlog_dead_bytes,
         (unsigned long long)after.vlog_dead_bytes,
         (unsigned long long)after.vlog_segments_drainable,
         (unsigned long long)before.vlog_reclaim_calls,
         (unsigned long long)after.vlog_reclaim_calls,
         (unsigned long long)before.vlog_segments_retired,
         (unsigned long long)after.vlog_segments_retired,
         after.compaction_pending_count);
  ok = 1;
done:
  if (names) {
    for (int i = 0; i < n; ++i)
      tidesdb_free(names[i]);
    tidesdb_free(names);
  }
  if (db)
    tidesdb_close(db);
  return ok ? 0 : compact_fail(failure_stage, failure_rc);
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
  if (argc == 4 && strcmp(argv[1], "--compact") == 0)
    return compact_database(argv[2], argv[3]);
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
    return fail("usage STREAM NEW_DB | --verify STREAM DB | --compact DB BASELINE_STREAM");
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
