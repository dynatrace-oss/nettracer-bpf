#pragma once

// Get rid of unsupported in Clang asm_inline (added in https://github.com/torvalds/linux/commit/eb111869301e15b737315a46c913ae82bd19eb9d)
// which is defined in "include/linux/compiler_types.h" if the kernel's CC supports it.

#include <linux/types.h>

#ifdef asm_inline
    #undef asm_inline
    #define asm_inline asm
#endif
