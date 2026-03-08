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
#include <KerbecsCompiler.h>

#if defined(_DEBUG) || defined(DEBUG)
#define KERBECS_BUILD_DEBUG 1
#define KERBECS_BUILD_RELEASE 0
#else
#define KERBECS_BUILD_DEBUG 0
#define KERBECS_BUILD_RELEASE 1
#endif

#if KERBECS_BUILD_DEBUG
#define KERBECS_ASSERT(expr)                        \
        do {                                            \
            if (!(expr)) {                             \
                KERBECS_DEBUG_BREAK();                 \
                KERBECS_TRAP();                        \
            }                                           \
        } while (0)
#else
#define KERBECS_ASSERT(expr) do { (void)sizeof(expr); } while (0)
#endif

#if KERBECS_BUILD_DEBUG
#define KERBECS_ASSUME(expr) KERBECS_ASSERT(expr)
#else
#if KERBECS_COMPILER_MSVC
#define KERBECS_ASSUME(expr) __assume(expr)
#else
#define KERBECS_ASSUME(expr) do { if (!(expr)) KERBECS_UNREACHABLE(); } while (0)
#endif
#endif

#if KERBECS_BUILD_DEBUG
#define KERBECS_DEBUG_ASSERT(expr) KERBECS_ASSERT(expr)
#define KERBECS_DEBUG_ASSUME(expr) KERBECS_ASSUME(expr)
#else
#define KERBECS_DEBUG_ASSERT(expr) do {} while (0)
#define KERBECS_DEBUG_ASSUME(expr) do {} while (0)
#endif

#define KERBECS_STATIC_ASSERT(expr, msg) static_assert(expr, msg)
#define KERBECS_UNUSED(x) (void)(x)
