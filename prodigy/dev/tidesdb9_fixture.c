#include <stdio.h>
#include <string.h>
#include <tidesdb/db.h>

static int fail(const char *s) {
  fprintf(stderr, "tidesdb9 fixture: %s\n", s);
  return 1;
}
static int put(tidesdb_t *db, tidesdb_column_family_t *cf,
               const unsigned char *k, size_t ks, const unsigned char *v,
               size_t vs) {
  tidesdb_txn_t *tx = 0;
  int rc = tidesdb_txn_begin(db, &tx);
  if (rc == TDB_SUCCESS)
    rc = tidesdb_txn_put(tx, cf, k, ks, v, vs, 0);
  if (rc == TDB_SUCCESS)
    rc = tidesdb_txn_commit(tx);
  else if (tx)
    tidesdb_txn_rollback(tx);
  if (tx)
    tidesdb_txn_free(tx);
  return rc == TDB_SUCCESS;
}
int main(int argc, char **argv) {
  tidesdb_config_t cfg;
  tidesdb_t *db = 0;
  if (argc != 2 && (argc != 3 || strcmp(argv[2], "--empty")))
    return fail("usage DB [--empty]");
  cfg = tidesdb_default_config();
  cfg.db_path = argv[1];
  cfg.log_level = TDB_LOG_NONE;
  cfg.unified_memtable_sync_mode = TDB_SYNC_FULL;
  if (tidesdb_open(&cfg, &db) != TDB_SUCCESS)
    return fail("open");
  if (argc == 2) {
    tidesdb_column_family_config_t c = tidesdb_default_column_family_config();
    const unsigned char binary_key[] = {0x00, 0x6b, 0xff, 0x79};
    const unsigned char binary_value[] = {0xff, 0x00, 0x76, 0x01};
    const unsigned char unknown_key[] = {0x75, 0x6e, 0x6b, 0x6e,
                                         0x6f, 0x77, 0x6e};
    const unsigned char unknown_value[] = {0x7f, 0x00, 0xfe};
    if (tidesdb_create_column_family(db, "empty", &c) != TDB_SUCCESS ||
        tidesdb_create_column_family(db, "binary", &c) != TDB_SUCCESS ||
        tidesdb_create_column_family(db, "unknown", &c) != TDB_SUCCESS ||
        !put(db, tidesdb_get_column_family(db, "binary"), binary_key,
             sizeof(binary_key), binary_value, sizeof(binary_value)) ||
        !put(db, tidesdb_get_column_family(db, "unknown"), unknown_key,
             sizeof(unknown_key), unknown_value, sizeof(unknown_value)))
      return fail("fixture write");
  }
  if (tidesdb_close(db) != TDB_SUCCESS)
    return fail("close");
  return 0;
}
