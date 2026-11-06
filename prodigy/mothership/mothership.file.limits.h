#pragma once

#include <cstdio>

extern "C" {
#include <tidesdb/db.h>
}

// Recovery opens the value-log segments before background descriptor eviction
// starts. Allow two registries' 4096-segment budgets plus SSTs and network I/O.
constexpr long mothershipRequiredOpenFiles = 16'384;

static inline bool mothershipPrepareFileLimit(FILE *errors = stderr)
{
  const long available = tidesdb_raise_open_file_limit(mothershipRequiredOpenFiles);
  if (available >= mothershipRequiredOpenFiles)
  {
    return true;
  }

  std::fprintf(errors,
               "mothership requires at least %ld open files; effective limit is %ld. "
               "Raise the launching shell's hard nofile limit or the service's LimitNOFILE before retrying.\n",
               mothershipRequiredOpenFiles, available);
  return false;
}
