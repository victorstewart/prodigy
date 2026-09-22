#include "tidesdb_migration_format.h"
#include <stdlib.h>
#include <sys/stat.h>
#include <tidesdb/db.h>
#include <unistd.h>

static int fail(const char *s) {
  fprintf(stderr, "tidesdb9 export: %s\n", s);
  return 1;
}

/* The Prodigy control-state contract uses the default CF settings.  The legacy
 * per-CF sync setting is intentionally normalized to v10's stronger DB-wide
 * FULL WAL setting; every other persisted tuning or comparator is rejected. */
static int supported_cf(tidesdb_column_family_t *cf) {
  tidesdb_stats_t *stats = 0;
  tidesdb_column_family_config_t d = tidesdb_default_column_family_config();
  int ok =
      tidesdb_get_stats(cf, &stats) == TDB_SUCCESS && stats && stats->config;
  if (ok) {
    tidesdb_column_family_config_t *c = stats->config;
    ok = c->write_buffer_size == d.write_buffer_size &&
         c->level_size_ratio == d.level_size_ratio &&
         c->min_levels == d.min_levels &&
         c->dividing_level_offset == d.dividing_level_offset &&
         c->klog_value_threshold == d.klog_value_threshold &&
         c->compression_algorithm == d.compression_algorithm &&
         c->enable_bloom_filter == d.enable_bloom_filter &&
         c->bloom_fpr == d.bloom_fpr &&
         c->enable_block_indexes == d.enable_block_indexes &&
         c->index_sample_ratio == d.index_sample_ratio &&
         c->block_index_prefix_len == d.block_index_prefix_len &&
         strcmp(c->comparator_name, d.comparator_name) == 0 &&
         strcmp(c->comparator_ctx_str, d.comparator_ctx_str) == 0 &&
         c->skip_list_max_level == d.skip_list_max_level &&
         c->skip_list_probability == d.skip_list_probability &&
         c->default_isolation_level == d.default_isolation_level &&
         c->min_disk_space == d.min_disk_space &&
         c->l1_file_count_trigger == d.l1_file_count_trigger &&
         c->l0_queue_stall_threshold == d.l0_queue_stall_threshold &&
         c->tombstone_density_trigger == d.tombstone_density_trigger &&
         c->tombstone_density_min_entries == d.tombstone_density_min_entries &&
         c->use_btree == d.use_btree &&
         c->object_target_file_size == d.object_target_file_size &&
         c->object_lazy_compaction == d.object_lazy_compaction &&
         c->object_prefetch_compaction == d.object_prefetch_compaction;
  }
  if (stats)
    tidesdb_free_stats(stats);
  return ok;
}

int main(int argc, char **argv) {
  FILE *out = 0;
  tidesdb_t *db = 0;
  char **names = 0;
  int n = 0;
  int result = 1;
  int stream_created = 0;
  uint64_t count = 0;
  SHA256_CTX sha;
  if (argc != 3)
    return fail("usage COPY_DB STREAM");
  if (access(argv[1], R_OK | X_OK) || access(argv[2], F_OK) == 0)
    return fail("source copy unreadable or stream exists");
  out = fopen(argv[2], "wbx");
  if (!out || fchmod(fileno(out), 0600))
    goto done;
  stream_created = 1;
  tidesdb_config_t config = tidesdb_default_config();
  config.db_path = argv[1];
  config.log_level = TDB_LOG_NONE;
  if (tidesdb_open(&config, &db) != TDB_SUCCESS ||
      !ptm_header_write(out, &sha) ||
      tidesdb_list_column_families(db, &names, &n) != TDB_SUCCESS)
    goto done;
  for (int i = 0; i < n; ++i) {
    tidesdb_column_family_t *cf;
    tidesdb_txn_t *tx = 0;
    tidesdb_iter_t *it = 0;
    unsigned char type = PRODIGY_TIDES_MIGRATION_CF;
    size_t name_size = names[i] ? strlen(names[i]) : 0;
    int seek;
    if (!name_size || name_size > PRODIGY_TIDES_MIGRATION_MAX_NAME ||
        !ptm_write(out, &sha, &type, 1) ||
        !ptm_u32_write(out, &sha, (uint32_t)name_size) ||
        !ptm_write(out, &sha, names[i], name_size))
      goto done;
    cf = tidesdb_get_column_family(db, names[i]);
    if (!cf || !supported_cf(cf) || tidesdb_txn_begin(db, &tx) != TDB_SUCCESS ||
        tidesdb_iter_new(tx, cf, &it) != TDB_SUCCESS) {
      if (it)
        tidesdb_iter_free(it);
      if (tx) {
        tidesdb_txn_rollback(tx);
        tidesdb_txn_free(tx);
      }
      goto done;
    }
    seek = tidesdb_iter_seek_to_first(it);
    if (seek != TDB_SUCCESS && seek != TDB_ERR_NOT_FOUND) {
      tidesdb_iter_free(it);
      tidesdb_txn_rollback(tx);
      tidesdb_txn_free(tx);
      goto done;
    }
    while (tidesdb_iter_valid(it)) {
      uint8_t *key = 0, *value = 0;
      size_t key_size = 0, value_size = 0;
      type = PRODIGY_TIDES_MIGRATION_RECORD;
      if (tidesdb_iter_key(it, &key, &key_size) != TDB_SUCCESS ||
          tidesdb_iter_value(it, &value, &value_size) != TDB_SUCCESS ||
          key_size > PRODIGY_TIDES_MIGRATION_MAX_BYTES ||
          value_size > PRODIGY_TIDES_MIGRATION_MAX_BYTES ||
          !ptm_write(out, &sha, &type, 1) ||
          !ptm_u32_write(out, &sha, (uint32_t)key_size) ||
          !ptm_u32_write(out, &sha, (uint32_t)value_size) ||
          !ptm_write(out, &sha, key, key_size) ||
          !ptm_write(out, &sha, value, value_size)) {
        tidesdb_iter_free(it);
        tidesdb_txn_rollback(tx);
        tidesdb_txn_free(tx);
        goto done;
      }
      ++count;
      int next = tidesdb_iter_next(it);
      if (next != TDB_SUCCESS) {
        if (next != TDB_ERR_NOT_FOUND) {
          tidesdb_iter_free(it);
          tidesdb_txn_rollback(tx);
          tidesdb_txn_free(tx);
          goto done;
        }
        break;
      }
    }
    tidesdb_iter_free(it);
    tidesdb_txn_rollback(tx);
    tidesdb_txn_free(tx);
  }
  if (!ptm_finish_write(out, &sha, count) || fflush(out) || fsync(fileno(out)) ||
      fclose(out)) {
    out = 0;
    goto done;
  }
  out = 0;
  result = 0;
done:
  if (names) {
    for (int i = 0; i < n; ++i)
      tidesdb_free(names[i]);
    tidesdb_free(names);
  }
  if (db && tidesdb_close(db) != TDB_SUCCESS)
    result = 1;
  db = 0;
  if (out)
    fclose(out);
  if (result && stream_created)
    unlink(argv[2]);
  if (result)
    return fail("could not export copied v9 database");
  return 0;
}
