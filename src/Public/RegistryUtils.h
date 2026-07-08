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
#include "Violation.h"

namespace Kerbecs::Tracing::Internal {
	inline thread_local const uint8_t t_ThreadAnchor = 0;

	KERBECS_FORCEINLINE uint32_t currentThreadID() noexcept {
		const uintptr_t addr = reinterpret_cast<uintptr_t>(&t_ThreadAnchor);
		return static_cast<uint32_t>((addr * 0x9e3779b97f4a7c15ULL) >> 32);
	}

	// AllocationState
	//
	//  Empty      - node is unused in the pool, never been assigned
	//  Live       - block is allocated, all objects valid, safe to access
	//  Retiring   - dtor cycle is in progress on this block; the thread that
	//               won m_DtorLock owns the transition. Any other thread
	//               attempting to access this block must treat it as a
	//               RetiredBoundaryViolation and fail fast. Transitions back
	//               to Live if m_LiveCount > 0 after the dtor cycle, or
	//               forward to Quarantine if m_LiveCount == 0.
	//  Quarantine - block is freed from the user perspective but memory is
	//               not yet reclaimed. Use-after-free detection window.
	//               Waits 2 epoch cycles before transitioning to Dead.
	//  Dead       - node is fully retired. Slot remains in the bucket chain
	//               but is skipped by all lookups. Memory has been released
	//               via the stored dealloc thunk.
	enum class KERBECS_RUNTIME_API AllocationState : uint8_t {
		Empty = 0,
		Live = 1,
		Retiring = 2,
		Quarantine = 3,
		Dead = 4
	};

	struct alignas(64) SpinLock {
		std::atomic_flag m_Flag = ATOMIC_FLAG_INIT;

		KERBECS_FORCEINLINE void lock() noexcept {
			while (m_Flag.test_and_set(std::memory_order_acquire)) {
#if KERBECS_COMPILER_MSVC
				_mm_pause();
#elif defined(__x86_64__) || defined(__i386__)
				__builtin_ia32_pause();
#endif
			}
		}

		KERBECS_FORCEINLINE void unlock() noexcept {
			m_Flag.clear(std::memory_order_release);
		}

		KERBECS_FORCEINLINE bool tryLock() noexcept {
			return !m_Flag.test_and_set(std::memory_order_acquire);
		}
	};

	struct alignas(128) RegistryNode {
		void* m_BlockBase = nullptr;
		void* m_UserPtr = nullptr;
		size_t       m_BlockSize = 0;
		size_t       m_UserSize = 0;
		uint64_t     m_AllocatorID = 0;
		StackTrace   m_AllocTrace = {};
		StackTrace   m_FreeTrace = {};
		const char* m_Name = nullptr;
		uint32_t     m_ThreadID = 0;

		std::atomic<AllocationState> m_State{ AllocationState::Empty };
		std::atomic<size_t> m_LiveCount{ 0 };
		SpinLock m_DtorLock;
		RegistryNode* m_Next = nullptr;
	};

	struct alignas(64) Bucket {
		std::atomic<RegistryNode*> m_Head{ nullptr };
		SpinLock                   m_Lock;
	};
}
