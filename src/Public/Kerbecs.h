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

#if defined(KERBECS_SHARED)

#if KERBECS_COMPILER_MSVC
#if defined(KERBECS_BUILDING_RUNTIME)
#define KERBECS_RUNTIME_API __declspec(dllexport)
#else
#define KERBECS_RUNTIME_API __declspec(dllimport)
#endif
#elif KERBECS_COMPILER_CLANG || KERBECS_COMPILER_GCC
#define KERBECS_RUNTIME_API __attribute__((visibility("default")))
#else
#define KERBECS_RUNTIME_API
#endif

#else
// Static build -> no import/export
#define KERBECS_RUNTIME_API
#endif

#include <concepts>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <atomic>		   
#include <algorithm>
#include <limits>
#include <bit>
#include <mutex>
