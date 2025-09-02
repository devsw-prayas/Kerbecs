#include <cstddef>

#include "Kerbecs.h"

#if defined(_WIN32)
#include <Windows.h>
#elif defined(__linux__)
#include <pthread.h>
#include <unistd.h>
#include <sys/mman.h>
#include <time.h>
#include <sched.h>
#endif

namespace Kerbecs::Memory{
	void* KERBECS allocate(size_t v_Bytes) {
		void* memory = nullptr;
#if defined(_WIN32)
		memory = VirtualAlloc(nullptr, v_Bytes, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE );
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

	void* KERBECS reserve(size_t v_Bytes) {
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

	bool KERBECS commit(void* p_Memory, size_t v_Bytes, size_t v_Offset) {
		auto memory = reinterpret_cast<std::byte*>(p_Memory);
#if defined(_WIN32)
		return VirtualAlloc(reinterpret_cast<void*>(memory + v_Offset), v_Bytes, MEM_COMMIT, PAGE_READWRITE) != nullptr;
#elif defined(__linux__)
		return mprotect(reinterpret_cast<void*>(memory + v_Offset), v_Bytes, PROT_READ | PROT_WRITE) != -1;
#else
		return false;
#endif
	}

	bool KERBECS decommit(void* p_Memory, size_t v_Bytes, size_t v_Offset) {
		auto memory = reinterpret_cast<std::byte*>(p_Memory);
#if defined(_WIN32)
		return VirtualFree(reinterpret_cast<void*>(memory + v_Offset), v_Bytes, MEM_DECOMMIT) != 0;
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
}
