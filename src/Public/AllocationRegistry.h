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
#include "Violation.h"

namespace Kerbecs::Tracing {

	static constexpr size_t kBucketCount = 2048;    // 2^11
	static constexpr size_t kNodeCapacity = 131072;  // 2^17

	static_assert((kBucketCount& (kBucketCount - 1)) == 0);
	static_assert((kNodeCapacity& (kNodeCapacity - 1)) == 0);

	// =========================================================================
	// NodePoolSegment
	//
	// Passed by the QuarantineQueue into its flush path so it can CAS
	// Quarantine -> Dead directly on the node without any back-reference
	// to AllocationRegistry as a class. The queue scans the contiguous
	// pool for a matching m_BlockBase and transitions the state in place.
	// =========================================================================
	struct KERBECS_RUNTIME_API NodePoolSegment {
		Internal::RegistryNode* m_Pool = nullptr;
		size_t                  m_Capacity = 0;
	};

	// =========================================================================
	// AllocationRegistry
	//
	// Striped concurrent hash map over a contiguous bump-allocated node pool.
	//
	// Structure:
	//   2048 buckets, each owning an intrusive linked list of RegistryNode*
	//   into the pool. Nodes are prepended at insert and never removed from
	//   the chain - they transition through AllocationState in place.
	//
	// Concurrency:
	//   Reads  (find / findRange)  - fully lock-free.
	//   Writes (insert)            - acquire per-bucket SpinLock, duplicate
	//                                check, CAS prepend, release lock.
	//   State transitions          - always CAS: acq_rel on success,
	//                                acquire on failure. Never plain store.
	//   m_LiveCount decrements     - fetch_sub(acq_rel) in shadowDestroy,
	//                                no bucket lock needed.
	//   Dtor cycle                 - beginRetiring / endRetiring, serialised
	//                                by per-node m_DtorLock.
	//
	// findRange fix:
	//   Receives the block base pointer (always available on the ShadowPtr as
	//   m_BlockBase). Hashes that to the correct bucket, then range-checks
	//   m_UserPtr within that bucket's chain. This is correct because the
	//   block base is what was inserted and hashed at insert time.
	// =========================================================================
	class KERBECS_RUNTIME_API AllocationRegistry {
	public:
		AllocationRegistry() = default;
		~AllocationRegistry() = default;

		AllocationRegistry(const AllocationRegistry&) = delete;
		AllocationRegistry& operator=(const AllocationRegistry&) = delete;

		// Allocates the node pool via Memory::allocate. Must be called once
		// during KerbecsMemoryZone::init before any other method.
		bool init() noexcept;

		// Releases the node pool via Memory::release. Called at teardown.
		void shutdown() noexcept;

		// Insert a new Live node for p_BlockBase. Acquires the bucket lock,
		// checks for duplicates, prepends via CAS. Returns false if the pool
		// is exhausted or p_BlockBase is already tracked.
		bool insert(
			void* p_BlockBase,
			void* p_UserPtr,
			size_t            v_BlockSize,
			size_t            v_UserSize,
			uint64_t          v_AllocatorID,
			uint32_t          v_ThreadID,
			const char* p_Name,
			const StackTrace& v_AllocTrace,
			size_t            v_ObjectCount) noexcept;

		// Attempt to begin the dtor cycle on p_BlockBase.
		// Finds the node, calls tryLock on m_DtorLock.
		//   - If the lock is already held: ThreadOwnership violation, fail fast.
		//   - If state is not Live: appropriate violation, fail fast.
		//   - On success: CAS Live -> Retiring (acq_rel/acquire), return node.
		// Returns nullptr on any failure (violation already fired by caller).
		Internal::RegistryNode* beginRetiring(
			void* p_BlockBase,
			uint32_t v_CallerThreadID) noexcept;

		// Complete the dtor cycle on p_BlockBase.
		// Reads m_LiveCount with acquire.
		//   - If > 0: CAS Retiring -> Live, release m_DtorLock. Block survives.
		//   - If == 0: CAS Retiring -> Quarantine, enqueue into quarantine
		//              (caller passes epoch + thunk info), release m_DtorLock.
		// v_Epoch, v_Allocator, v_Thunk are forwarded to the quarantine enqueue
		// and are only used on the Quarantine path.
		void endRetiring(
			void* p_BlockBase,
			uint64_t v_Epoch,
			void* p_Allocator,
			void   (*p_Thunk)(void*, void*, size_t)) noexcept;

		// CAS Quarantine -> Dead. Called directly by the QuarantineQueue
		// flush path via NodePoolSegment - no AllocationRegistry pointer needed
		// at that call site.
		bool retire(void* p_BlockBase) noexcept;

		// Lock-free reads. Hash p_BlockBase to its bucket, walk the chain.
		// Dead nodes are skipped (state check on each node).
		Internal::RegistryNode* find(const void* p_BlockBase) noexcept;
		const Internal::RegistryNode* find(const void* p_BlockBase) const noexcept;

		// Lock-free range lookup. p_BlockBase must be the block base pointer
		// (from ShadowPtr::m_BlockBase), not an interior user pointer.
		// Hashes p_BlockBase to the correct bucket, then checks whether
		// p_Address falls within [m_UserPtr, m_UserPtr + m_UserSize).
		Internal::RegistryNode* findRange(const void* p_BlockBase, const void* p_Address) noexcept;
		const Internal::RegistryNode* findRange(const void* p_BlockBase, const void* p_Address) const noexcept;

		size_t liveCount() const noexcept {
			return m_Count.load(std::memory_order_relaxed);
		}

		// Returns a segment descriptor for the node pool so the quarantine
		// flush path can CAS Quarantine -> Dead without a back-pointer here.
		NodePoolSegment poolSegment() const noexcept {
			return { m_NodePool, kNodeCapacity };
		}

	private:
		alignas(64) Internal::Bucket m_Buckets[kBucketCount];

		alignas(64) std::atomic<size_t> m_NodeCursor{ 0 };
		std::atomic<size_t>             m_Count{ 0 };

		Internal::RegistryNode* m_NodePool = nullptr;

		// Fibonacci hashing - shift by 6 to ignore sub-cache-line bits,
		// multiply by golden ratio, mask to bucket count.
		KERBECS_FORCEINLINE static size_t _index(const void* p) noexcept {
			uintptr_t key = reinterpret_cast<uintptr_t>(p) >> 6;
			key *= 0x9e3779b97f4a7c15ULL;
			return key & (kBucketCount - 1);
		}

		// Bump-allocate one node from the pool. Atomic, never returns the
		// same index twice. Returns nullptr if the pool is exhausted.
		Internal::RegistryNode* _allocateNode() noexcept;
	};

}