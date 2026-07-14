#pragma once

#include <cstdio>

#if PRODIGY_DEBUG
#define PRODIGY_DEBUG_LOG(...) std::fprintf(stderr, __VA_ARGS__)
#define PRODIGY_DEBUG_FLUSH() std::fflush(stderr)
#else
#define PRODIGY_DEBUG_LOG(...) ((void)0)
#define PRODIGY_DEBUG_FLUSH() ((void)0)
#endif
