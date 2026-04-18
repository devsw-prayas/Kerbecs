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
#include "QuarantineQueue.h"
#include "KerbecsDiagnostics.h"
#include "MemoryZone.h"
#include "RegistryUtils.h"

namespace Kerbecs::Quarantine {
	bool QuarantineQueue::init(
		size_t        v_Capacity,
		KerbecsStats* p_Stats) noexcept {
		if (v_Capacity == 0 || !p_Stats)
			return false;

		KERBECS_ASSERT((v_Capacity & (v_Capacity - 1)) == 0);

		m_Slots = static_cast<QuarantineEntry*>(
			Memory::allocate(v_Capacity * sizeof(QuarantineEntry)));

		if (!m_Slots)
			return false;

		std::memset(m_Slots, 0, v_Capacity * sizeof(QuarantineEntry));

		m_Capacity = v_Capacity;
		m_Stats = p_Stats;

		m_Head.store(0, std::memory_order_relaxed);
		m_Tail.store(0, std::memory_order_relaxed);

		return true;
	}

	void QuarantineQueue::shutdown() noexcept {
		if (m_Slots) {
			KERBECS_UNUSED(Memory::release(
				m_Slots,
				m_Capacity * sizeof(QuarantineEntry)));
			m_Slots = nullptr;
			m_Capacity = 0;
		}

		m_Head.store(0, std::memory_order_relaxed);
		m_Tail.store(0, std::memory_order_relaxed);
		m_Stats = nullptr;
	}

	bool QuarantineQueue::enqueue(
		void* p_BlockBase,
		size_t   v_BlockSize,
		uint64_t v_Epoch,
		void* p_Allocator,
		void   (*p_DeallocThunk)(void*, void*, size_t)) noexcept {
		if (!m_Slots || !p_BlockBase)
			return false;

		const size_t mask = m_Capacity - 1;
		const size_t tail = m_Tail.fetch_add(1, std::memory_order_acq_rel);
		const size_t idx = tail & mask;

		QuarantineEntry& slot = m_Slots[idx];

		// Check for saturation before writing. If the slot is still occupied
		// the queue is full - fail fast, no graceful eviction.
		void* existing = slot.m_BlockBase.load(std::memory_order_acquire);
		if (existing != nullptr)
			_onSaturation(); // never returns

		// Write all non-atomic fields BEFORE the atomic store of m_BlockBase.
		// Any thread that observes a non-null m_BlockBase with acquire will
		// also see these fields due to the release/acquire pair.
		slot.m_BlockSize = v_BlockSize;
		slot.m_Epoch = v_Epoch;
		slot.m_Allocator = p_Allocator;
		slot.m_DeallocThunk = p_DeallocThunk;

		// Publish the entry. Release semantics guarantee the fields above
		// are visible to any subsequent acquire load of m_BlockBase.
		slot.m_BlockBase.store(p_BlockBase, std::memory_order_release);

		statsOnQuarantineEnqueue(m_Stats);
		return true;
	}

	size_t QuarantineQueue::flushEligible(
		Tracing::NodePoolSegment v_Segment,
		size_t                   v_MaxCount) noexcept {
		if (!m_Slots)
			return 0;

		m_FlushLock.lock();

		size_t flushed = 0;

		while (flushed < v_MaxCount) {
			const size_t head = m_Head.load(std::memory_order_acquire);
			const size_t tail = m_Tail.load(std::memory_order_acquire);

			if (head >= tail)
				break;

			const size_t     idx = head & (m_Capacity - 1);
			QuarantineEntry& slot = m_Slots[idx];

			void* base = slot.m_BlockBase.load(std::memory_order_acquire);
			if (!base)
				break;

			// Hardcoded 2-epoch delay.
			const uint64_t curEpoch = MemoryZone::instance().m_Epoch.load(std::memory_order_acquire);
			if (slot.m_Epoch + 2 > curEpoch)
				break;

			_retireSlot(slot, v_Segment);

			m_Head.fetch_add(1, std::memory_order_release);
			flushed++;
		}

		m_FlushLock.unlock();
		return flushed;
	}

	void QuarantineQueue::_retireSlot(
		QuarantineEntry& v_Entry,
		Tracing::NodePoolSegment v_Segment) noexcept {
		void* base = v_Entry.m_BlockBase.load(std::memory_order_acquire);
		KERBECS_ASSERT(base != nullptr);

		// Scan the contiguous node pool for the matching block base and
		// CAS Quarantine -> Dead directly. No back-pointer to AllocationRegistry
		// needed - the pool is a plain array we can walk.
		if (v_Segment.m_Pool && v_Segment.m_Capacity > 0) {
			bool found = false;
			for (size_t i = 0; i < v_Segment.m_Capacity; ++i) {
				Tracing::Internal::RegistryNode& node = v_Segment.m_Pool[i];

				if (node.m_BlockBase != base)
					continue;

				found = true;
				Tracing::Internal::AllocationState expected =
					Tracing::Internal::AllocationState::Quarantine;
				node.m_State.compare_exchange_strong(
					expected,
					Tracing::Internal::AllocationState::Dead,
					std::memory_order_acq_rel,
					std::memory_order_acquire);
				break;
			}
			KERBECS_UNUSED(found);
		}

		// Type-erased deallocation. Thunk casts p_Allocator back to the
		// concrete MemorySupport<A>* and calls deallocate.
		if (v_Entry.m_DeallocThunk && v_Entry.m_Allocator)
			v_Entry.m_DeallocThunk(v_Entry.m_Allocator, base, v_Entry.m_BlockSize);

		statsOnQuarantineDequeue(m_Stats);

		// Null the entry. m_BlockBase last with release so a concurrent
		// enqueue that observes null knows the slot is fully cleared.
		v_Entry.m_BlockSize = 0;
		v_Entry.m_Epoch = 0;
		v_Entry.m_Allocator = nullptr;
		v_Entry.m_DeallocThunk = nullptr;

		v_Entry.m_BlockBase.store(nullptr, std::memory_order_release);
	}

	KERBECS_NORETURN void QuarantineQueue::_onSaturation() const noexcept {
		if (m_Stats)
			statsOnViolation(m_Stats);
		KERBECS_TRAP();
	}

	size_t QuarantineQueue::depth() const noexcept {
		const size_t tail = m_Tail.load(std::memory_order_acquire);
		const size_t head = m_Head.load(std::memory_order_acquire);
		return (tail >= head) ? (tail - head) : 0;
	}

	bool QuarantineQueue::full() const noexcept {
		return depth() >= m_Capacity;
	}

	bool QuarantineQueue::empty() const noexcept {
		return depth() == 0;
	}
}