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
#include "KerbecsMemory.h"
#include "RegistryUtils.h"
#include "ShadowUtils.h"
#include "Violation.h"

namespace Kerbecs::Tracing {
	static constexpr size_t kBucketCount = 2048;    // 2^11

	static_assert((kBucketCount& (kBucketCount - 1)) == 0);

	struct KERBECS_RUNTIME_API NodePoolSegment {
		Internal::RegistryNode* m_Pool = nullptr;
		size_t                  m_Capacity = 0;
	};

	// Striped concurrent hash map (2048 buckets, intrusive node pool) owned one-per-Region.
	// Configurable capacity avoids sizing small regions for large pools, making
	// two-tier wild-pointer resolution (RegionRecord) cheap by rejecting wild pointers
	// before searching node pools. Reads are lock-free; inserts acquire per-bucket SpinLock + CAS.
	// State transitions use CAS; dtor cycle serialised via per-node m_DtorLock.
	class KERBECS_RUNTIME_API AllocationRegistry {
	public:
		explicit AllocationRegistry(size_t v_NodeCapacity) noexcept
			: m_NodeCapacity(v_NodeCapacity) {
		}
		~AllocationRegistry() = default;

		AllocationRegistry(const AllocationRegistry&) = delete;
		AllocationRegistry& operator=(const AllocationRegistry&) = delete;

		bool init() noexcept;
		void shutdown() noexcept;

		bool insert(
			void* p_BlockBase,
			void* p_UserPtr,
			size_t            v_BlockSize,
			size_t            v_UserSize,
			uint64_t          v_AllocatorID,
			uint32_t          v_ThreadID,
			const char* p_Name,
			size_t            v_ObjectCount) noexcept;

		Internal::RegistryNode* beginRetiring(
			void* p_BlockBase,
			uint32_t v_CallerThreadID,
			Shadow::Utils::ThreadPolicy v_Policy) noexcept;

		void endRetiring(
			void* p_BlockBase,
			uint64_t v_Epoch,
			void* p_Allocator,
			void   (*p_Thunk)(void*, void*, size_t)) noexcept;

		bool retire(void* p_BlockBase) noexcept;

		Internal::RegistryNode* find(const void* p_BlockBase) noexcept;
		const Internal::RegistryNode* find(const void* p_BlockBase) const noexcept;

		// p_BlockBase is the block base (not an interior pointer) — hashed to the
		// correct bucket, then range-checked against [m_UserPtr, m_UserPtr + m_UserSize).
		Internal::RegistryNode* findRange(const void* p_BlockBase, const void* p_Address) noexcept;
		const Internal::RegistryNode* findRange(const void* p_BlockBase, const void* p_Address) const noexcept;

		size_t liveCount() const noexcept {
			return m_Count.load(std::memory_order_relaxed);
		}

		size_t nodeCapacity() const noexcept { return m_NodeCapacity; }

		NodePoolSegment poolSegment() const noexcept {
			return { m_NodePool, m_NodeCapacity };
		}

	private:
		alignas(64) Internal::Bucket m_Buckets[kBucketCount];

		size_t m_NodeCapacity = 0;

		alignas(64) std::atomic<size_t> m_NodeCursor{ 0 };
		std::atomic<size_t>             m_Count{ 0 };

		Internal::RegistryNode* m_NodePool = nullptr;

		// Shift by 6 to ignore sub-cache-line bits before Fibonacci hash.
		KERBECS_FORCEINLINE static size_t _index(const void* p) noexcept {
			uintptr_t key = reinterpret_cast<uintptr_t>(p) >> 6;
			key *= 0x9e3779b97f4a7c15ULL;
			return key & (kBucketCount - 1);
		}

		Internal::RegistryNode* _allocateNode() noexcept;
	};
}
