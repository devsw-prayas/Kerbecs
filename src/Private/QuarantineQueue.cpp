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

namespace Kerbecs::Quarantine {
	bool QuarantineQueue::init(
		QuarantineEntry* p_Slots,
		size_t              v_Capacity,
		Tracing::AllocationRegistry* p_Registry,
		KerbecsStats* p_Stats,
		FreeCallback        p_FreeCallback) noexcept {
		if (!p_Slots || v_Capacity == 0 || !p_Registry || !p_FreeCallback) return false;

		// Capacity must be a power of two
		KERBECS_ASSERT((v_Capacity & (v_Capacity - 1)) == 0);

		std::memset(p_Slots, 0, v_Capacity * sizeof(QuarantineEntry));

		m_Slots = p_Slots;
		m_Capacity = v_Capacity;
		m_Registry = p_Registry;
		m_Stats = p_Stats;
		m_FreeCallback = p_FreeCallback;
		m_Head.store(0, std::memory_order_relaxed);
		m_Tail.store(0, std::memory_order_relaxed);

		return true;
	}

	bool QuarantineQueue::enqueue(void* p_BlockBase, size_t v_BlockSize) noexcept {
		if (!m_Slots || !p_BlockBase) return false;

		size_t mask = m_Capacity - 1;

		// CAS loop to claim the next tail slot
		size_t tail = m_Tail.load(std::memory_order_relaxed);
		for (;;) {
			if (m_Tail.compare_exchange_weak(
				tail,
				tail + 1,
				std::memory_order_acq_rel,
				std::memory_order_relaxed)) {
				break;
			}
		}

		size_t idx = tail & mask;
		QuarantineEntry& slot = m_Slots[idx];

		if (slot.m_BlockBase != nullptr) {
			_retireSlot(slot);
			m_Head.fetch_add(1, std::memory_order_release);
		}

		// Write new entry
		slot.m_BlockBase = p_BlockBase;
		slot.m_BlockSize = v_BlockSize;

		statsOnQuarantineEnqueue(m_Stats);
		return true;
	}

	bool QuarantineQueue::flushOne() noexcept {
		if (!m_Slots) return false;

		size_t head = m_Head.load(std::memory_order_acquire);
		size_t tail = m_Tail.load(std::memory_order_acquire);

		if (head >= tail) return false;

		size_t idx = head & (m_Capacity - 1);
		QuarantineEntry& slot = m_Slots[idx];

		if (slot.m_BlockBase == nullptr) return false;

		_retireSlot(slot);

		m_Head.fetch_add(1, std::memory_order_release);
		return true;
	}

	size_t QuarantineQueue::flush(size_t v_MaxCount) noexcept {
		size_t flushed = 0;
		while (flushed < v_MaxCount && flushOne())
			flushed++;
		return flushed;
	}

	void QuarantineQueue::_retireSlot(QuarantineEntry& v_Entry)const noexcept {
		KERBECS_ASSERT(v_Entry.m_BlockBase != nullptr);

		bool retired = m_Registry->retire(v_Entry.m_BlockBase);
		KERBECS_DEBUG_ASSERT(retired);
		KERBECS_UNUSED(retired);

		if (m_FreeCallback)
			m_FreeCallback(v_Entry.m_BlockBase, v_Entry.m_BlockSize);

		statsOnQuarantineDequeue(m_Stats);

		v_Entry.m_BlockBase = nullptr;
		v_Entry.m_BlockSize = 0;
	}

	size_t QuarantineQueue::depth() const noexcept {
		size_t tail = m_Tail.load(std::memory_order_acquire);
		size_t head = m_Head.load(std::memory_order_acquire);
		return (tail >= head) ? (tail - head) : 0;
	}

	bool QuarantineQueue::full() const noexcept {
		return depth() >= m_Capacity;
	}

	bool QuarantineQueue::empty() const noexcept {
		return depth() == 0;
	}
}