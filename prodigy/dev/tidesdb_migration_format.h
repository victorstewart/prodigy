#pragma once
#include <errno.h>
#include <openssl/sha.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define PRODIGY_TIDES_MIGRATION_MAX_BYTES UINT32_MAX // wire lengths; control snapshots can exceed 64 MiB
#define PRODIGY_TIDES_MIGRATION_MAX_NAME 128U
#define PRODIGY_TIDES_MIGRATION_CF 1U
#define PRODIGY_TIDES_MIGRATION_RECORD 2U
#define PRODIGY_TIDES_MIGRATION_END 255U

static const unsigned char prodigy_tides_migration_magic[8] = {
    'P', 'T', '9', 'T', '1', '0', 'K', 'V'};
static int ptm_write(FILE *f, SHA256_CTX *sha, const void *p, size_t n) {
  return fwrite(p, 1, n, f) == n && SHA256_Update(sha, p, n) == 1;
}
static int ptm_read(FILE *f, SHA256_CTX *sha, void *p, size_t n) {
  return fread(p, 1, n, f) == n && SHA256_Update(sha, p, n) == 1;
}
static int ptm_u32_write(FILE *f, SHA256_CTX *s, uint32_t v) {
  unsigned char b[4] = {v, v >> 8, v >> 16, v >> 24};
  return ptm_write(f, s, b, 4);
}
static int ptm_u32_read(FILE *f, SHA256_CTX *s, uint32_t *v) {
  unsigned char b[4];
  if (!ptm_read(f, s, b, 4))
    return 0;
  *v = (uint32_t)b[0] | ((uint32_t)b[1] << 8) | ((uint32_t)b[2] << 16) |
       ((uint32_t)b[3] << 24);
  return 1;
}
static int ptm_u64_write(FILE *f, SHA256_CTX *s, uint64_t v) {
  unsigned char b[8];
  for (int i = 0; i < 8; i++)
    b[i] = (unsigned char)(v >> (8 * i));
  return ptm_write(f, s, b, 8);
}
static int ptm_u64_read(FILE *f, SHA256_CTX *s, uint64_t *v) {
  unsigned char b[8];
  if (!ptm_read(f, s, b, 8))
    return 0;
  *v = 0;
  for (int i = 0; i < 8; i++)
    *v |= (uint64_t)b[i] << (8 * i);
  return 1;
}
static int ptm_header_write(FILE *f, SHA256_CTX *s) {
  return SHA256_Init(s) == 1 &&
         ptm_write(f, s, prodigy_tides_migration_magic, 8);
}
static int ptm_header_read(FILE *f, SHA256_CTX *s) {
  unsigned char b[8];
  return SHA256_Init(s) == 1 && ptm_read(f, s, b, 8) &&
         memcmp(b, prodigy_tides_migration_magic, 8) == 0;
}
static int ptm_raw_u64_write(FILE *f, uint64_t v) {
  unsigned char b[8];
  for (int i = 0; i < 8; i++)
    b[i] = (unsigned char)(v >> (8 * i));
  return fwrite(b, 1, 8, f) == 8;
}
static int ptm_raw_u64_read(FILE *f, uint64_t *v) {
  unsigned char b[8];
  if (fread(b, 1, 8, f) != 8)
    return 0;
  *v = 0;
  for (int i = 0; i < 8; i++)
    *v |= (uint64_t)b[i] << (8 * i);
  return 1;
}
static int ptm_finish_write(FILE *f, SHA256_CTX *s, uint64_t records) {
  unsigned char digest[SHA256_DIGEST_LENGTH], tag = PRODIGY_TIDES_MIGRATION_END;
  if (SHA256_Final(digest, s) != 1)
    return 0;
  return fwrite(&tag, 1, 1, f) == 1 &&
         fwrite(digest, 1, sizeof(digest), f) == sizeof(digest) &&
         ptm_raw_u64_write(f, records) && fflush(f) == 0;
}
static int ptm_finish_read(FILE *f, SHA256_CTX *s, uint64_t records) {
  unsigned char tag, digest[SHA256_DIGEST_LENGTH], actual[SHA256_DIGEST_LENGTH];
  uint64_t declared;
  if (fread(&tag, 1, 1, f) != 1 || tag != PRODIGY_TIDES_MIGRATION_END ||
      fread(digest, 1, sizeof(digest), f) != sizeof(digest) ||
      !ptm_raw_u64_read(f, &declared) || fgetc(f) != EOF)
    return 0;
  return declared == records && SHA256_Final(actual, s) == 1 &&
         memcmp(digest, actual, sizeof(digest)) == 0;
}
