#pragma once

#include <prodigy/types.h>

static inline MachineCpuArchitecture nametagCurrentBuildMachineArchitecture(void)
{
#if defined(__x86_64__) || defined(_M_X64)
   return MachineCpuArchitecture::x86_64;
#elif defined(__aarch64__) || defined(_M_ARM64)
   return MachineCpuArchitecture::aarch64;
#elif defined(__riscv) && (__riscv_xlen == 64)
   return MachineCpuArchitecture::riscv64;
#else
   return MachineCpuArchitecture::unknown;
#endif
}
