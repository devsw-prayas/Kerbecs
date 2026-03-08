/*
* Copyright (c) 2025 StormWeaver
*
* This file is part of the Kerbecs Address Sanitizer API
*
* Licensed under the MIT License. You may obtain a copy of the License at
* https://opensource.org/licenses/MIT
*
* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files (the "Software"), to deal
* in the Software without restriction, including without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
* copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in all
* copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND...
*/
#pragma once

#if defined(_MSC_VER)
#define KERBECS_COMPILER_MSVC 1
#else
#define KERBECS_COMPILER_MSVC 0
#endif

#if defined(__clang__)
#define KERBECS_COMPILER_CLANG 1
#else
#define KERBECS_COMPILER_CLANG 0
#endif

#if defined(__GNUC__) && !defined(__clang__)
#define KERBECS_COMPILER_GCC 1
#else
#define KERBECS_COMPILER_GCC 0
#endif

#if KERBECS_COMPILER_MSVC
#define KERBECS_FORCEINLINE __forceinline
#define KERBECS_NOINLINE    __declspec(noinline)
#elif KERBECS_COMPILER_CLANG || KERBECS_COMPILER_GCC
#define KERBECS_FORCEINLINE inline __attribute__((always_inline))
#define KERBECS_NOINLINE    __attribute__((noinline))
#else
#define KERBECS_FORCEINLINE inline
#define KERBECS_NOINLINE
#endif

#define KERBECS_INLINE inline

#if KERBECS_COMPILER_CLANG || KERBECS_COMPILER_GCC
#define KERBECS_LIKELY(x)   __builtin_expect(!!(x), 1)
#define KERBECS_UNLIKELY(x) __builtin_expect(!!(x), 0)
#else
#define KERBECS_LIKELY(x)   (x)
#define KERBECS_UNLIKELY(x) (x)
#endif

#if KERBECS_COMPILER_MSVC
#define KERBECS_DEBUG_BREAK() __debugbreak()
#define KERBECS_TRAP()        __debugbreak()
#elif KERBECS_COMPILER_CLANG || KERBECS_COMPILER_GCC
#define KERBECS_DEBUG_BREAK() __builtin_trap()
#define KERBECS_TRAP()        __builtin_trap()
#else
#include <cstdlib>
#define KERBECS_DEBUG_BREAK() std::abort()
#define KERBECS_TRAP()        std::abort()
#endif

#if KERBECS_COMPILER_MSVC
#define KERBECS_UNREACHABLE() __assume(0)
#elif KERBECS_COMPILER_CLANG || KERBECS_COMPILER_GCC
#define KERBECS_UNREACHABLE() __builtin_unreachable()
#else
#define KERBECS_UNREACHABLE() KERBECS_TRAP()
#endif

#if defined(__has_cpp_attribute)
#if __has_cpp_attribute(nodiscard)
#define KERBECS_NODISCARD [[nodiscard]]
#if __cplusplus >= 202002L
#define KERBECS_NODISCARD_MSG(msg) [[nodiscard(msg)]]
#else
#define KERBECS_NODISCARD_MSG(msg) [[nodiscard]]
#endif
#else
#define KERBECS_NODISCARD
#define KERBECS_NODISCARD_MSG(msg)
#endif
#else
#define KERBECS_NODISCARD
#define KERBECS_NODISCARD_MSG(msg)
#endif

#if defined(__has_cpp_attribute)
#if __has_cpp_attribute(maybe_unused)
#define KERBECS_MAYBE_UNUSED [[maybe_unused]]
#else
#define KERBECS_MAYBE_UNUSED
#endif
#else
#define KERBECS_MAYBE_UNUSED
#endif

#if defined(__has_cpp_attribute)
#if __has_cpp_attribute(fallthrough)
#define KERBECS_FALLTHROUGH [[fallthrough]]
#else
#define KERBECS_FALLTHROUGH
#endif
#else
#define KERBECS_FALLTHROUGH
#endif

#if defined(__has_cpp_attribute)
#if __has_cpp_attribute(noreturn)
#define KERBECS_NORETURN [[noreturn]]
#else
#define KERBECS_NORETURN
#endif
#else
#define KERBECS_NORETURN
#endif

#if defined(__has_cpp_attribute)
#if __has_cpp_attribute(deprecated)
#define KERBECS_DEPRECATED [[deprecated]]
#define KERBECS_DEPRECATED_MSG(msg) [[deprecated(msg)]]
#else
#define KERBECS_DEPRECATED
#define KERBECS_DEPRECATED_MSG(msg)
#endif
#else
#define KERBECS_DEPRECATED
#define KERBECS_DEPRECATED_MSG(msg)
#endif

#if KERBECS_COMPILER_MSVC
#define KERBECS_RESTRICT __restrict
#elif KERBECS_COMPILER_CLANG || KERBECS_COMPILER_GCC
#define KERBECS_RESTRICT __restrict__
#else
#define KERBECS_RESTRICT
#endif
