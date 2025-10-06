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
#include "Memory.h"
#include <cstddef>

#if defined(_WIN32)
#include <Windows.h>
#elif defined(__linux__)
#include <pthread.h>
#include <unistd.h>
#include <sys/mman.h>
#include <time.h>
#include <sched.h>
#endif

namespace Kerbecs::Memory {
	void*  allocate(size_t v_Bytes) {
		void* memory = nullptr;
#if defined(_WIN32)
		memory = VirtualAlloc(nullptr, v_Bytes, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
		if (!memory) return nullptr;
#elif defined(__linux__)
		memory = mmap(nullptr, v_Bytes, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (memory == MAP_FAILED) return nullptr;
#else
		memory = malloc(v_Bytes);
		if (!memory) return nullptr;
#endif
		return memory;
	}

	void* reserve(size_t v_Bytes) {
		void* memory = nullptr;
#if defined(_WIN32)
		memory = VirtualAlloc(nullptr, v_Bytes, MEM_RESERVE, PAGE_NOACCESS);
		if (!memory) return nullptr;
#elif defined(__linux__)
		memory = mmap(nullptr, v_Bytes, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (memory == MAP_FAILED) return nullptr;
#endif
		return memory;
	}

	bool commit(void* p_Memory, size_t v_Bytes, size_t v_Offset) {
		auto memory = static_cast<std::byte*>(p_Memory);
#if defined(_WIN32)
		return VirtualAlloc(memory + v_Offset, v_Bytes, MEM_COMMIT, PAGE_READWRITE) != nullptr;
#elif defined(__linux__)
		return mprotect(reinterpret_cast<void*>(memory + v_Offset), v_Bytes, PROT_READ | PROT_WRITE) != -1;
#else
		return false;
#endif
	}

	bool decommit(void* p_Memory, size_t v_Bytes, size_t v_Offset) {
		auto memory = static_cast<std::byte*>(p_Memory);
#if defined(_WIN32)
		return VirtualFree(memory + v_Offset, v_Bytes, MEM_DECOMMIT) != 0;
#elif defined(__linux__)
		return (mprotect(reinterpret_cast<void*>(memory + v_Offset), v_Bytes, PROT_NONE) != -1 &&
			madvise(reinterpret_cast<void*>(memory + v_Offset), v_Bytes, MADV_DONTNEED) != -1);
#else
		return false;
#endif
	}

	bool KERBECS release(void* p_Memory, size_t v_Bytes) {
#if defined(_WIN32)
		return VirtualFree(p_Memory, 0, MEM_RELEASE) != 0;
#elif defined(__linux__)
		return munmap(p_Memory, v_Bytes) == 0;
#else
		::free(p_Memory);
		return true;
#endif
	}

	PageState queryPage(const void* p_Memory) {
#if defined(_WIN32)
		MEMORY_BASIC_INFORMATION mem{};
		if (!VirtualQuery(p_Memory, &mem, sizeof(mem))) return PageState::UNKNOWN;
		if (mem.State & MEM_COMMIT) return PageState::COMMITTED;
		if (mem.State & MEM_RESERVE) return PageState::RESERVED;
		return PageState::FREE;
#elif(__linux__)
		usigned char vec;
		if (mincore((void*) ((uintptr_t) addr & ~(getpagesize() - 1)),
			getpagesize(), &vec) == 0)
			return (vec & 1) ? PageState::COMMITTED : PageState::RESERVED;
		return PageState::FREE;
#endif
	}

	void* allocateHeap(size_t v_Bytes) {
#if defined(_WIN32)
		void* memory = HeapAlloc(GetProcessHeap(), 0, v_Bytes);
		return memory ? memory : nullptr;
#elif defined(__linux__)
		void* memory = malloc(v_Bytes);
		return memory ? memory : nullptr;
#endif
	}

	bool deallocateHeap(void* p_Memory) {
#if defined(_WIN32)
		return HeapFree(GetProcessHeap(), 0, p_Memory);
#elif defined(__linux__)
		free(p_Memory);
		return true;
#endif
	}

}