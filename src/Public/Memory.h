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
#include "Kerbecs.h"

namespace Kerbecs::Memory {
	constexpr size_t KERBECS operator""_KB(unsigned long long v_KB) {
		return v_KB * 1000ULL;
	}

	constexpr size_t KERBECS operator""_MB(unsigned long long v_MB) {
		return v_MB * 1000ULL * 1000ULL;
	}

	constexpr size_t KERBECS operator""_GB(unsigned long long v_GB) {
		return v_GB * 1000ULL * 1000ULL * 1000ULL;
	}

	constexpr size_t KERBECS operator""_KiB(unsigned long long v_KiB) {
		return v_KiB * 1024ULL;
	}

	constexpr size_t KERBECS operator""_MiB(unsigned long long v_MiB) {
		return v_MiB * 1024ULL * 1024ULL;
	}

	constexpr size_t KERBECS operator""_GiB(unsigned long long v_GiB) {
		return v_GiB * 1024ULL * 1024ULL * 1024ULL;
	}

	constexpr size_t KERBECS PAGE_FILE = 4_KiB;

	constexpr size_t KERBECS alignToPage(unsigned long long v_Bytes) {
		return (v_Bytes + PAGE_FILE - 1) / PAGE_FILE * PAGE_FILE;
	}

	constexpr size_t KERBECS KILO_BYTE = 1_KB;
	constexpr size_t KERBECS MEGA_BYTE = 1_MB;
	constexpr size_t KERBECS GIGA_BYTE = 1_GB;

	constexpr size_t KERBECS KIBI_BYTE = 1_KiB;
	constexpr size_t KERBECS MEBI_BYTE = 1_MiB;
	constexpr size_t KERBECS GIBI_BYTE = 1_GiB;

	enum class KERBECS PageState: uint8_t {
		FREE, RESERVED, COMMITTED, UNKNOWN
	};

	inline KERBECS void* allocate(size_t v_Bytes);
	inline KERBECS void*  reserve(size_t v_Bytes);
	inline bool KERBECS commit(void* p_Memory, size_t v_Bytes, size_t v_Offset);
	inline bool KERBECS decommit(void* p_Memory, size_t v_Bytes, size_t v_Offset);
	inline bool KERBECS release(void* p_Memory, size_t v_Bytes);

	inline KERBECS void* allocateHeap(size_t v_Bytes);
	inline bool KERBECS deallocateHeap(void* p_Memory);
	inline [[nodiscard]] PageState KERBECS queryPage(const void* p_Memory);
}
 