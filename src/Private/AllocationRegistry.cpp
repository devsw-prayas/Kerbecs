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
#include "AllocationRegistry.h"
#include "KerbecsDiagnostics.h"
#include "MemoryZone.h"

namespace Kerbecs::Tracing {
	// init / shutdown

	bool AllocationRegistry::init() noexcept {
		m_NodePool = static_cast<Internal::RegistryNode*>(
			Memory::allocate(kNodeCapacity * sizeof(Internal::RegistryNode)));

		if (!m_NodePool)
			return false;

		std::memset(m_NodePool, 0,
					kNodeCapacity * sizeof(Internal::RegistryNode));

		m_NodeCursor.store(0, std::memory_order_relaxed);
		m_Count.store(0, std::memory_order_relaxed);

		return true;
	}

	void AllocationRegistry::shutdown() noexcept {
		if (m_NodePool) {
			KERBECS_UNUSED(Memory::release(
				m_NodePool,
				kNodeCapacity * sizeof(Internal::RegistryNode)));
			m_NodePool = nullptr;
		}

		m_NodeCursor.store(0, std::memory_order_relaxed);
		m_Count.store(0, std::memory_order_relaxed);
	}

	// _allocateNode

	Internal::RegistryNode* AllocationRegistry::_allocateNode() noexcept {
		size_t idx = m_NodeCursor.fetch_add(1, std::memory_order_relaxed);

		if (idx >= kNodeCapacity) {
			KERBECS_ASSERT(false && "AllocationRegistry node pool exhausted");
			return nullptr;
		}

		return &m_NodePool[idx];
	}

	// insert
	//
	// Acquires the bucket lock to prevent lost-update on concurrent prepends
	// to the same bucket head. The duplicate check also runs under the lock
	// so two racing inserts with the same block base cannot both succeed.
	//
	// The node is fully initialised before its state is set to Live and before
	// it is published to the bucket head. m_State store uses release so that
	// any acquire load of m_Head that reaches this node also sees all fields.

	bool AllocationRegistry::insert(
		void* p_BlockBase,
		void* p_UserPtr,
		size_t            v_BlockSize,
		size_t            v_UserSize,
		uint64_t          v_AllocatorID,
		uint32_t          v_ThreadID,
		const char* p_Name,
		const StackTrace& v_AllocTrace,
		size_t            v_ObjectCount) noexcept {
		if (!p_BlockBase)
			return false;

		const size_t       bucketIdx = _index(p_BlockBase);
		Internal::Bucket& bucket = m_Buckets[bucketIdx];

		// Acquire bucket lock for the duration of the duplicate check + prepend.
		bucket.m_Lock.lock();

		// Duplicate check under the lock.
		{
			Internal::RegistryNode* cur =
				bucket.m_Head.load(std::memory_order_relaxed);

			while (cur) {
				if (cur->m_BlockBase == p_BlockBase) {
					// Only fail if the node is NOT Dead. Dead nodes are skipped
					// to allow virtual address reuse at the same base pointer.
					if (cur->m_State.load(std::memory_order_acquire) !=
						Internal::AllocationState::Dead) {
						bucket.m_Lock.unlock();
						return false; // already tracked - caller reports overlap
					}
				}
				cur = cur->m_Next;
			}
		}

		Internal::RegistryNode* newNode = _allocateNode();
		if (!newNode) {
			bucket.m_Lock.unlock();
			return false;
		}

		// Populate all fields before publishing.
		newNode->m_BlockBase = p_BlockBase;
		newNode->m_UserPtr = p_UserPtr;
		newNode->m_BlockSize = v_BlockSize;
		newNode->m_UserSize = v_UserSize;
		newNode->m_AllocatorID = v_AllocatorID;
		newNode->m_ThreadID = v_ThreadID;
		newNode->m_Name = p_Name;
		newNode->m_AllocTrace = v_AllocTrace;
		newNode->m_LiveCount.store(v_ObjectCount, std::memory_order_relaxed);

		std::memset(&newNode->m_FreeTrace, 0, sizeof(StackTrace));

		// Publish state as Live with release so readers that acquire m_Head
		// observe the fully initialised node.
		newNode->m_State.store(
			Internal::AllocationState::Live,
			std::memory_order_release);

		// CAS prepend under the bucket lock. Lock prevents concurrent inserts
		// to this bucket from racing on m_Head; the CAS is still correct as
		// the canonical publication primitive.
		Internal::RegistryNode* head;
		do {
			head = bucket.m_Head.load(std::memory_order_relaxed);
			newNode->m_Next = head;
		} while (!bucket.m_Head.compare_exchange_weak(
			head,
			newNode,
			std::memory_order_release,
			std::memory_order_relaxed));

		bucket.m_Lock.unlock();

		m_Count.fetch_add(1, std::memory_order_relaxed);
		Kerbecs::statsOnInit(&Kerbecs::MemoryZone::instance().m_Stats, v_BlockSize);
		return true;
	}

	// beginRetiring
	//
	// Attempts to begin the dtor cycle. Returns the node pointer on success
	// so the caller (shadowDestroy) can decrement m_LiveCount and proceed.
	// Returns nullptr and fires the appropriate violation on any failure:
	//   - tryLock fails  -> ThreadOwnership (concurrent dtor attempt)
	//   - state != Live  -> appropriate violation (DoubleFree, UseAfterFree...)

	Internal::RegistryNode* AllocationRegistry::beginRetiring(
		void* p_BlockBase,
		uint32_t v_CallerThreadID,
		Shadow::Utils::ThreadPolicy v_Policy) noexcept {
		if (!p_BlockBase)
			return nullptr;

		Internal::RegistryNode* node = find(p_BlockBase);
		if (!node)
			return nullptr;

		// Thread ownership check. IF the policy is Strict, we reject destructions
		// from threads other than the one that allocated the block.
		if (v_Policy == Shadow::Utils::ThreadPolicy::Strict) {
			if (v_CallerThreadID != node->m_ThreadID) {
				return nullptr; // Caller fires ThreadOwnership violation
			}
		}

		// Non-blocking lock attempt. A false return means another thread is
		// already in the dtor cycle for this block - that is a violation.
		if (!node->m_DtorLock.tryLock())
			return nullptr; // caller fires ThreadOwnership violation

		// Verify state is Live under the dtor lock. Any other state is a
		// violation the caller must handle after we release the lock.
		Internal::AllocationState expected = Internal::AllocationState::Live;
		if (!node->m_State.compare_exchange_strong(
			expected,
			Internal::AllocationState::Retiring,
			std::memory_order_acq_rel,
			std::memory_order_acquire)) {
			// State was not Live - unlock and let caller fire the violation.
			node->m_DtorLock.unlock();
			return nullptr;
		}

		return node;
	}

	// endRetiring
	//
	// Called after the dtor cycle completes (destructor called, tombstone
	// stamped). Reads m_LiveCount with acquire to decide the next state:
	//
	//   m_LiveCount > 0  -> Retiring -> Live   (block has surviving objects)
	//   m_LiveCount == 0 -> Retiring -> Quarantine (block is fully dead,
	//                       enqueue into quarantine with thunk for dealloc)
	//
	// The dtor lock is released after the transition regardless of path.
	// The quarantine enqueue happens before lock release so that the block
	// cannot be accessed again before it is safely in the queue.

	void AllocationRegistry::endRetiring(
		void* p_BlockBase,
		uint64_t v_Epoch,
		void* p_Allocator,
		void   (*p_Thunk)(void*, void*, size_t)) noexcept {
		if (!p_BlockBase)
			return;

		Internal::RegistryNode* node = find(p_BlockBase);
		if (!node)
			return;

		const size_t liveCount =
			node->m_LiveCount.load(std::memory_order_acquire);

		if (liveCount > 0) {
			// Objects remain - transition back to Live.
			Internal::AllocationState expected = Internal::AllocationState::Retiring;
			KERBECS_UNUSED(node->m_State.compare_exchange_strong(
				expected,
				Internal::AllocationState::Live,
				std::memory_order_acq_rel,
				std::memory_order_acquire));

			node->m_DtorLock.unlock();
			return;
		}

		// No objects remain - transition to Quarantine.
		Internal::AllocationState expected = Internal::AllocationState::Retiring;
		if (!node->m_State.compare_exchange_strong(
			expected,
			Internal::AllocationState::Quarantine,
			std::memory_order_acq_rel,
			std::memory_order_acquire)) {
			node->m_DtorLock.unlock();
			return;
		}

		// Store free-site trace.
		std::memset(&node->m_FreeTrace, 0, sizeof(StackTrace));

		// Quarantine enqueue is done by the caller (shadowDestroy) which has
		// access to the zone's quarantine instance. We release the dtor lock
		// here so the caller can safely enqueue before returning.
		node->m_DtorLock.unlock();

		// Decrement live count at the zone level.
		m_Count.fetch_sub(1, std::memory_order_relaxed);

		// Caller is responsible for enqueuing to the quarantine with
		// (p_BlockBase, node->m_BlockSize, v_Epoch, p_Allocator, p_Thunk).
		KERBECS_UNUSED(v_Epoch);
		KERBECS_UNUSED(p_Allocator);
		KERBECS_UNUSED(p_Thunk);
	}

	// retire  (Quarantine -> Dead)
	//
	// Called by the QuarantineQueue flush path via NodePoolSegment scan,
	// or directly here. CAS Quarantine -> Dead.

	bool AllocationRegistry::retire(void* p_BlockBase) noexcept {
		if (!p_BlockBase)
			return false;

		Internal::RegistryNode* node = find(p_BlockBase);
		if (!node)
			return false;

		Internal::AllocationState expected = Internal::AllocationState::Quarantine;

		if (!node->m_State.compare_exchange_strong(
			expected,
			Internal::AllocationState::Dead,
			std::memory_order_acq_rel,
			std::memory_order_acquire)) {
			return false;
		}

		return true;
	}

	// find  (lock-free)

	Internal::RegistryNode*
		AllocationRegistry::find(const void* p_BlockBase) noexcept {
		if (!p_BlockBase)
			return nullptr;

		const size_t idx = _index(p_BlockBase);

		Internal::RegistryNode* node =
			m_Buckets[idx].m_Head.load(std::memory_order_acquire);

		while (node) {
			// Skip Dead and Empty nodes.
			const auto state = node->m_State.load(std::memory_order_acquire);
			if (state != Internal::AllocationState::Dead &&
				state != Internal::AllocationState::Empty &&
				node->m_BlockBase == p_BlockBase)
				return node;

			node = node->m_Next;
		}

		return nullptr;
	}

	const Internal::RegistryNode*
		AllocationRegistry::find(const void* p_BlockBase) const noexcept {
		if (!p_BlockBase)
			return nullptr;

		const size_t idx = _index(p_BlockBase);

		const Internal::RegistryNode* node =
			m_Buckets[idx].m_Head.load(std::memory_order_acquire);

		while (node) {
			const auto state = node->m_State.load(std::memory_order_acquire);
			if (state != Internal::AllocationState::Dead &&
				state != Internal::AllocationState::Empty &&
				node->m_BlockBase == p_BlockBase)
				return node;

			node = node->m_Next;
		}

		return nullptr;
	}

	// findRange  (lock-free)
	//
	// p_BlockBase is hashed to find the correct bucket (same hash as insert).
	// p_Address is the interior address being range-checked against
	// [m_UserPtr, m_UserPtr + m_UserSize) within that bucket.

	Internal::RegistryNode* AllocationRegistry::findRange(const void* p_BlockBase, const void* p_Address) noexcept {
		if (!p_BlockBase || !p_Address) return nullptr;
		const size_t idx = _index(p_BlockBase);

		Internal::RegistryNode* node = m_Buckets[idx].m_Head.load(std::memory_order_acquire);

		const uintptr_t addr = reinterpret_cast<uintptr_t>(p_Address);

		while (node) {
			const auto state = node->m_State.load(std::memory_order_acquire);
			if (state != Internal::AllocationState::Dead &&
				state != Internal::AllocationState::Empty &&
				node->m_BlockBase == p_BlockBase) {
				const uintptr_t start = reinterpret_cast<uintptr_t>(node->m_UserPtr);

				if (addr >= start && (addr - start) < node->m_UserSize) return node;
			}
			node = node->m_Next;
		}

		return nullptr;
	}

	const Internal::RegistryNode*
		AllocationRegistry::findRange(
			const void* p_BlockBase,
			const void* p_Address) const noexcept {
		if (!p_BlockBase || !p_Address)
			return nullptr;

		const size_t idx = _index(p_BlockBase);

		const Internal::RegistryNode* node =
			m_Buckets[idx].m_Head.load(std::memory_order_acquire);

		const uintptr_t addr =
			reinterpret_cast<uintptr_t>(p_Address);

		while (node) {
			const auto state = node->m_State.load(std::memory_order_acquire);
			if (state != Internal::AllocationState::Dead &&
				state != Internal::AllocationState::Empty &&
				node->m_BlockBase == p_BlockBase) {
				const uintptr_t start =
					reinterpret_cast<uintptr_t>(node->m_UserPtr);

				if (addr >= start && (addr - start) < node->m_UserSize)
					return node;
			}

			node = node->m_Next;
		}

		return nullptr;
	}
} // namespace Kerbecs::Tracing