/*
 * Copyright 2025 Dynatrace LLC
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */
#pragma once

// Get rid of unsupported in Clang asm_inline (added in https://github.com/torvalds/linux/commit/eb111869301e15b737315a46c913ae82bd19eb9d)
// which is defined in "include/linux/compiler_types.h" if the kernel's CC supports it.

#include <linux/types.h>

#ifdef asm_inline
    #undef asm_inline
    #define asm_inline asm
#endif
