#pragma once

#ifdef __BPF__

typedef __u8 __be8;

#include <stdbool.h>

// #define bool __u8
// #define true 1
// #define false 0

#else

typedef uint8_t __be8;
typedef uint8_t __u8;
typedef uint16_t __u16;
typedef uint32_t __u32;
typedef uint32_t __be32;

#endif