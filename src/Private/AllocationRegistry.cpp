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
#include "KerbecsRuntime.h"

namespace Kerbecs::Tracing {
	bool AllocationRegistry::init() noexcept {
		if (m_NodeCapacity == 0)
			return false;

		m_NodePool = static_cast<Internal::RegistryNode*>(
			Memory::allocate(m_NodeCapacity * sizeof(Internal::RegistryNode)));

		if (!m_NodePool)
			return false;

		std::memset(m_NodePool, 0,
					m_NodeCapacity * sizeof(Internal::RegistryNode));

		m_NodeCursor.store(0, std::memory_order_relaxed);
		m_Count.store(0, std::memory_order_relaxed);

		return true;
	}

	void AllocationRegistry::shutdown() noexcept {
		if (m_NodePool) {
			KERBECS_UNUSED(Memory::release(
				m_NodePool,
				m_NodeCapacity * sizeof(Internal::RegistryNode)));
			m_NodePool = nullptr;
		}

		m_NodeCursor.store(0, std::memory_order_relaxed);
		m_Count.store(0, std::memory_order_relaxed);
	}

	Internal::RegistryNode* AllocationRegistry::_allocateNode() noexcept {
		size_t idx = m_NodeCursor.fetch_add(1, std::memory_order_relaxed);

		if (idx >= m_NodeCapacity) {
			KERBECS_ASSERT(false && "AllocationRegistry node pool exhausted");
			return nullptr;
		}

		return &m_NodePool[idx];
	}

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

		bucket.m_Lock.lock();

		// Highest generation among nodes at this base carried forward +1 so stale
		// ShadowedMemory<T> handles from recycled addresses never match new nodes.
		// _allocateNode() bump-allocates fresh nodes rather than reusing Dead ones in-place.
		uint64_t nextGeneration = 1;

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
						return false;
					}

					const uint64_t priorGen = cur->m_Generation.load(std::memory_order_relaxed);
					if (priorGen + 1 > nextGeneration)
						nextGeneration = priorGen + 1;
				}
				cur = cur->m_Next;
			}
		}

		Internal::RegistryNode* newNode = _allocateNode();
		if (!newNode) {
			bucket.m_Lock.unlock();
			return false;
		}

		newNode->m_Generation.store(nextGeneration, std::memory_order_relaxed);
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

		newNode->m_State.store(
			Internal::AllocationState::Live,
			std::memory_order_release);

		// Both a lock AND a CAS: lock prevents concurrent inserts to the same
		// bucket racing on m_Head; CAS is the canonical publication primitive.
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
		Kerbecs::statsOnInit(&Kerbecs::Runtime::instance().m_Stats, v_BlockSize);
		return true;
	}

	Internal::RegistryNode* AllocationRegistry::beginRetiring(
		void* p_BlockBase,
		uint32_t v_CallerThreadID,
		Shadow::Utils::ThreadPolicy v_Policy) noexcept {
		if (!p_BlockBase)
			return nullptr;

		Internal::RegistryNode* node = find(p_BlockBase);
		if (!node)
			return nullptr;

		if (v_Policy == Shadow::Utils::ThreadPolicy::Strict) {
			if (v_CallerThreadID != node->m_ThreadID) {
				return nullptr;
			}
		}

		// tryLock failure = concurrent dtor on the same block, caller fires violation.
		if (!node->m_DtorLock.tryLock())
			return nullptr;

		Internal::AllocationState expected = Internal::AllocationState::Live;
		if (!node->m_State.compare_exchange_strong(
			expected,
			Internal::AllocationState::Retiring,
			std::memory_order_acq_rel,
			std::memory_order_acquire)) {
			node->m_DtorLock.unlock();
			return nullptr;
		}

		return node;
	}

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
			Internal::AllocationState expected = Internal::AllocationState::Retiring;
			KERBECS_UNUSED(node->m_State.compare_exchange_strong(
				expected,
				Internal::AllocationState::Live,
				std::memory_order_acq_rel,
				std::memory_order_acquire));

			node->m_DtorLock.unlock();
			return;
		}

		Internal::AllocationState expected = Internal::AllocationState::Retiring;
		if (!node->m_State.compare_exchange_strong(
			expected,
			Internal::AllocationState::Quarantine,
			std::memory_order_acq_rel,
			std::memory_order_acquire)) {
			node->m_DtorLock.unlock();
			return;
		}

		std::memset(&node->m_FreeTrace, 0, sizeof(StackTrace));
		node->m_DtorLock.unlock();

		m_Count.fetch_sub(1, std::memory_order_relaxed);
		Runtime::quarantine().enqueue(p_BlockBase, node->m_BlockSize, v_Epoch, p_Allocator, p_Thunk, this);
	}

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

	Internal::RegistryNode*
		AllocationRegistry::find(const void* p_BlockBase) noexcept {
		if (!p_BlockBase)
			return nullptr;

		const size_t idx = _index(p_BlockBase);

		Internal::RegistryNode* node =
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
