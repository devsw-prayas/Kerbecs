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

#include "Kerbecs.h"
#include "KerbecsMemory.h"

#include "KerbecsDiagnostics.h"

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>
#elif defined(__linux__)
#include <sys/mman.h>
#include <unistd.h>
#endif

namespace Kerbecs::Memory {
	void* allocate(size_t v_Bytes) noexcept {
#ifdef _WIN32
		return VirtualAlloc(nullptr, v_Bytes, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
#elif defined(__linux__)
		void* p = mmap(nullptr, v_Bytes, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		return (p == MAP_FAILED) ? nullptr : p;
#else
		return std::malloc(v_Bytes);
#endif
	}

	void* reserve(size_t v_Bytes) noexcept {
#ifdef _WIN32
		return VirtualAlloc(nullptr, v_Bytes, MEM_RESERVE, PAGE_NOACCESS);
#elif defined(__linux__)
		void* p = mmap(nullptr, v_Bytes, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		return (p == MAP_FAILED) ? nullptr : p;
#else
		return nullptr;
#endif
	}

	void* reserveAt(void* p_Hint, size_t v_Bytes) noexcept {
#ifdef _WIN32
		void* p = VirtualAlloc(p_Hint, v_Bytes, MEM_RESERVE, PAGE_NOACCESS);
		if (!p) p = VirtualAlloc(nullptr, v_Bytes, MEM_RESERVE, PAGE_NOACCESS);
		return p;
#elif defined(__linux__)
		void* p = mmap(p_Hint, v_Bytes, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (p == MAP_FAILED) {
			p = mmap(nullptr, v_Bytes, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		}
		return (p == MAP_FAILED) ? nullptr : p;
#else
		return nullptr;
#endif
	}

	bool commit(void* p_Base, size_t v_Bytes, size_t v_Offset) noexcept {
		if (!p_Base || v_Bytes == 0) return false;
		auto* base = static_cast<std::byte*>(p_Base) + v_Offset;
#ifdef _WIN32
		return VirtualAlloc(base, v_Bytes, MEM_COMMIT, PAGE_READWRITE) != nullptr;
#elif defined(__linux__)
		return mprotect(base, v_Bytes, PROT_READ | PROT_WRITE) == 0;
#else
		return false;
#endif
	}

	bool decommit(void* p_Base, size_t v_Bytes, size_t v_Offset) noexcept {
		if (!p_Base || v_Bytes == 0) return false;
		auto* base = static_cast<std::byte*>(p_Base) + v_Offset;
#ifdef _WIN32
		return VirtualFree(base, v_Bytes, MEM_DECOMMIT) != 0;
#elif defined(__linux__)
		return mprotect(base, v_Bytes, PROT_NONE) == 0 &&
			madvise(base, v_Bytes, MADV_DONTNEED) == 0;
#else
		return false;
#endif
	}

	bool release(void* p_Memory, size_t v_Bytes) noexcept {
		if (!p_Memory) return false;
#ifdef _WIN32
		KERBECS_UNUSED(v_Bytes); // MEM_RELEASE requires size = 0 on Windows
		return VirtualFree(p_Memory, 0, MEM_RELEASE) != 0;
#elif defined(__linux__)
		return munmap(p_Memory, v_Bytes) == 0;
#else
		std::free(p_Memory);
		return true;
#endif
	}

	void* allocateHeap(size_t v_Bytes) noexcept {
#ifdef _WIN32
		return HeapAlloc(GetProcessHeap(), 0, v_Bytes);
#elif defined(__linux__)
		return std::malloc(v_Bytes);
#else
		return std::malloc(v_Bytes);
#endif
	}

	bool deallocateHeap(void* p_Memory) noexcept {
		if (!p_Memory) return false;
#ifdef _WIN32
		return HeapFree(GetProcessHeap(), 0, p_Memory) != 0;
#elif defined(__linux__)
		std::free(p_Memory);
		return true;
#else
		std::free(p_Memory);
		return true;
#endif
	}

	PageState queryPage(const void* p_Memory) noexcept {
		if (!p_Memory) return PageState::Unknown;
#ifdef _WIN32
		MEMORY_BASIC_INFORMATION mbi{};
		if (!VirtualQuery(p_Memory, &mbi, sizeof(mbi))) return PageState::Unknown;
		if (mbi.State & MEM_COMMIT)   return PageState::Committed;
		if (mbi.State & MEM_RESERVE)  return PageState::Reserved;
		return PageState::Free;
#elif defined(__linux__)
		const long pageSize = sysconf(_SC_PAGESIZE);
		if (pageSize <= 0) return PageState::Unknown;

		uintptr_t aligned = reinterpret_cast<uintptr_t>(p_Memory) & ~static_cast<uintptr_t>(pageSize - 1);
		unsigned char vec = 0;
		if (mincore(reinterpret_cast<void*>(aligned), static_cast<size_t>(pageSize), &vec) == 0)
			return (vec & 1) ? PageState::Committed : PageState::Reserved;
		return PageState::Free;
#else
		return PageState::Unknown;
#endif
	}

	bool commitPageIfNeeded(void* p_Address) noexcept {
		if (!p_Address) return false;

		switch (queryPage(p_Address)) {
		case PageState::Committed:
		return true;

		case PageState::Reserved:
		{
			uintptr_t pageBase = reinterpret_cast<uintptr_t>(p_Address) & ~(PAGE_SIZE - 1);
			return commit(reinterpret_cast<void*>(pageBase), PAGE_SIZE, 0);
		}

		case PageState::Free:
		case PageState::Unknown: break;
		}
		KERBECS_UNREACHABLE();
	}
}