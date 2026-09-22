#define _GNU_SOURCE
#include <tidesdb/db.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int fail(const char *message) { fprintf(stderr, "tidesdb9 lock compatibility: %s\n", message); return 1; }
int main(void) {
  char directory[] = "./prodigy-tidesdb9-lock-XXXXXX";
  char lock_path[sizeof(directory) + 6];
  tidesdb_config_t config = tidesdb_default_config();
  tidesdb_t *db = 0;
  struct flock lock = {.l_type = F_WRLCK, .l_whence = SEEK_SET};
  int fd;
  if (!mkdtemp(directory)) return fail("temporary directory");
  config.db_path = directory;
  config.log_level = TDB_LOG_NONE;
  if (tidesdb_open(&config, &db) != TDB_SUCCESS) return fail("v9 open");
  snprintf(lock_path, sizeof(lock_path), "%s/LOCK", directory);
  fd = open(lock_path, O_RDWR | O_CLOEXEC | O_NOFOLLOW);
  if (fd < 0) return fail("open lock");
  errno = 0;
  if (fcntl(fd, F_SETLK, &lock) == 0 || (errno != EACCES && errno != EAGAIN)) return fail("v9 lock did not exclude migration lock");
  if (tidesdb_close(db) != TDB_SUCCESS) return fail("v9 close");
  if (fcntl(fd, F_SETLK, &lock) != 0) return fail("migration lock unavailable after v9 close");
  lock.l_type = F_UNLCK;
  if (fcntl(fd, F_SETLK, &lock) != 0 || close(fd) != 0) return fail("unlock");
  char cleanup[sizeof(directory) + 16];
  snprintf(cleanup, sizeof(cleanup), "rm -rf -- %s", directory);
  if (system(cleanup) != 0) return fail("cleanup");
  return 0;
}
