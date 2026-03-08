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
#include <cstdint>

namespace Kerbecs::Memory {

	constexpr size_t operator""_KB(unsigned long long v) noexcept { return v * 1000ULL; }
	constexpr size_t operator""_MB(unsigned long long v) noexcept { return v * 1000ULL * 1000ULL; }
	constexpr size_t operator""_GB(unsigned long long v) noexcept { return v * 1000ULL * 1000ULL * 1000ULL; }

	constexpr size_t operator""_KiB(unsigned long long v) noexcept { return v * 1024ULL; }
	constexpr size_t operator""_MiB(unsigned long long v) noexcept { return v * 1024ULL * 1024ULL; }
	constexpr size_t operator""_GiB(unsigned long long v) noexcept { return v * 1024ULL * 1024ULL * 1024ULL; }


	constexpr size_t KILO_BYTE = 1_KB;
	constexpr size_t MEGA_BYTE = 1_MB;
	constexpr size_t GIGA_BYTE = 1_GB;

	constexpr size_t KIBI_BYTE = 1_KiB;
	constexpr size_t MEBI_BYTE = 1_MiB;
	constexpr size_t GIBI_BYTE = 1_GiB;

	constexpr size_t PAGE_SIZE = 4_KiB;

	KERBECS_NODISCARD_MSG("Cannot discard page-aligned size")
		constexpr size_t alignToPage(size_t v_Bytes) noexcept {
		return (v_Bytes + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
	}

	KERBECS_NODISCARD_MSG("Cannot discard aligned value")
		constexpr size_t alignUp(size_t v_Value, size_t v_Align) noexcept {
		return (v_Value + v_Align - 1) & ~(v_Align - 1);
	}

	KERBECS_NODISCARD_MSG("Cannot discard aligned pointer")
		constexpr uintptr_t alignUpPtr(uintptr_t v_Value, size_t v_Align) noexcept {
		return (v_Value + v_Align - 1) & ~static_cast<uintptr_t>(v_Align - 1);
	}

	enum class KERBECS_RUNTIME_API PageState : uint8_t {
		Free,
		Reserved,
		Committed,
		Unknown
	};


	KERBECS_NODISCARD_MSG("Cannot discard allocated memory pointer")
		KERBECS_RUNTIME_API void* allocate(size_t v_Bytes) noexcept;

	KERBECS_NODISCARD_MSG("Cannot discard reserved memory pointer")
		KERBECS_RUNTIME_API void* reserve(size_t v_Bytes) noexcept;

	KERBECS_NODISCARD_MSG("Cannot discard reserved memory pointer")
		KERBECS_RUNTIME_API void* reserveAt(void* p_Hint, size_t v_Bytes) noexcept;

	KERBECS_NODISCARD_MSG("Cannot discard commit result")
		KERBECS_RUNTIME_API bool commit(void* p_Base, size_t v_Bytes, size_t v_Offset) noexcept;

	KERBECS_NODISCARD_MSG("Cannot discard decommit result")
		KERBECS_RUNTIME_API bool decommit(void* p_Base, size_t v_Bytes, size_t v_Offset) noexcept;

	KERBECS_NODISCARD_MSG("Cannot discard release result")
		KERBECS_RUNTIME_API bool release(void* p_Memory, size_t v_Bytes) noexcept;

	KERBECS_NODISCARD_MSG("Cannot discard heap allocated pointer")
		KERBECS_RUNTIME_API void* allocateHeap(size_t v_Bytes) noexcept;

	KERBECS_RUNTIME_API bool deallocateHeap(void* p_Memory) noexcept;

	KERBECS_NODISCARD_MSG("Cannot discard page state")
		KERBECS_RUNTIME_API PageState queryPage(const void* p_Memory) noexcept;

	KERBECS_NODISCARD_MSG("Cannot discard commit-on-demand result")
		KERBECS_RUNTIME_API bool commitPageIfNeeded(void* p_Address) noexcept;

} 