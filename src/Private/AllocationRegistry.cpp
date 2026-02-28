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

namespace Kerbecs::Tracing {
	bool AllocationRegistry::init(RegistryEntry* p_Slots, size_t v_Capacity) noexcept {
		if (!p_Slots || v_Capacity == 0) return false;

		KERBECS_ASSERT((v_Capacity & (v_Capacity - 1)) == 0);
		std::memset(p_Slots, 0, v_Capacity * sizeof(RegistryEntry));

		m_Slots = p_Slots;
		m_Capacity = v_Capacity;
		m_Count.store(0, std::memory_order_relaxed);

		return true;
	}

	size_t AllocationRegistry::_probe(const void* p_BlockBase) const noexcept {
		if (!m_Slots || m_Capacity == 0) return m_Capacity;

		size_t mask = m_Capacity - 1;
		size_t start = _hash(p_BlockBase);

		for (size_t i = 0; i < m_Capacity; i++) {
			size_t idx = (start + i) & mask;
			const RegistryEntry& slot = m_Slots[idx];

			AllocationState state = slot.m_State.load(std::memory_order_acquire);

			if (state == AllocationState::Empty)
				return m_Capacity; // key definitely not present

			if (state == AllocationState::Dead)
				continue;

			if (slot.m_BlockBase == p_BlockBase)
				return idx; // found
		}

		return m_Capacity; // table fully probed, not found
	}

	bool AllocationRegistry::insert(
		void* p_BlockBase,
		void* p_UserPtr,
		size_t            v_BlockSize,
		size_t            v_UserSize,
		uint64_t          v_AllocatorID,
		uint32_t          v_ThreadID,
		const char* p_Name,
		const StackTrace& v_AllocTrace) noexcept {
		if (!m_Slots || !p_BlockBase) return false;

		if (_probe(p_BlockBase) != m_Capacity) return false;

		size_t mask = m_Capacity - 1;
		size_t start = _hash(p_BlockBase);

		for (size_t i = 0; i < m_Capacity; i++) {
			size_t idx = (start + i) & mask;
			RegistryEntry& slot = m_Slots[idx];

			AllocationState expected = slot.m_State.load(std::memory_order_acquire);

			if (expected != AllocationState::Empty && expected != AllocationState::Dead)
				continue;

			if (!slot.m_State.compare_exchange_strong(
				expected,
				AllocationState::Live,
				std::memory_order_acq_rel,
				std::memory_order_acquire)) {
				continue;
			}

			slot.m_BlockBase = p_BlockBase;
			slot.m_UserPtr = p_UserPtr;
			slot.m_BlockSize = v_BlockSize;
			slot.m_UserSize = v_UserSize;
			slot.m_AllocatorID = v_AllocatorID;
			slot.m_ThreadID = v_ThreadID;
			slot.m_Name = p_Name;
			slot.m_AllocTrace = v_AllocTrace;
			std::memset(&slot.m_FreeTrace, 0, sizeof(StackTrace));

			m_Count.fetch_add(1, std::memory_order_relaxed);
			return true;
		}

		return false;
	}

	bool AllocationRegistry::remove(void* p_BlockBase, const StackTrace& v_FreeTrace) const noexcept {
		if (!m_Slots || !p_BlockBase) return false;

		size_t idx = _probe(p_BlockBase);
		if (idx == m_Capacity) return false; // not found

		RegistryEntry& slot = m_Slots[idx];

		AllocationState expected = AllocationState::Live;
		if (!slot.m_State.compare_exchange_strong(
			expected,
			AllocationState::Quarantine,
			std::memory_order_acq_rel,
			std::memory_order_acquire)) {
			return false;
		}

		slot.m_FreeTrace = v_FreeTrace;
		return true;
	}

	bool AllocationRegistry::retire(void* p_BlockBase) noexcept {
		if (!m_Slots || !p_BlockBase) return false;

		size_t idx = _probe(p_BlockBase);
		if (idx == m_Capacity) return false;

		RegistryEntry& slot = m_Slots[idx];

		AllocationState expected = AllocationState::Quarantine;
		if (!slot.m_State.compare_exchange_strong(
			expected,
			AllocationState::Dead,
			std::memory_order_acq_rel,
			std::memory_order_acquire)) {
			return false;
		}

		m_Count.fetch_sub(1, std::memory_order_relaxed);
		return true;
	}

	const RegistryEntry* AllocationRegistry::find(const void* p_BlockBase) const noexcept {
		if (!m_Slots || !p_BlockBase) return nullptr;

		size_t idx = _probe(p_BlockBase);
		if (idx == m_Capacity) return nullptr;

		const RegistryEntry& slot = m_Slots[idx];
		AllocationState state = slot.m_State.load(std::memory_order_acquire);

		if (state == AllocationState::Live || state == AllocationState::Quarantine)
			return &slot;

		return nullptr;
	}

	RegistryEntry* AllocationRegistry::find(const void* p_BlockBase) noexcept {
		return const_cast<RegistryEntry*>(
			const_cast<const AllocationRegistry*>(this)->find(p_BlockBase));
	}

	const RegistryEntry* AllocationRegistry::findRange(const void* p_Address) const noexcept {
		if (!m_Slots || !p_Address) return nullptr;

		uintptr_t addr = reinterpret_cast<uintptr_t>(p_Address);

		for (size_t i = 0; i < m_Capacity; i++) {
			const RegistryEntry& slot = m_Slots[i];
			AllocationState state = slot.m_State.load(std::memory_order_acquire);

			if (state != AllocationState::Live && state != AllocationState::Quarantine)
				continue;

			uintptr_t start = reinterpret_cast<uintptr_t>(slot.m_UserPtr);
			uintptr_t end = start + slot.m_UserSize;

			if (addr >= start && addr < end)
				return &slot;
		}

		return nullptr;
	}

	size_t AllocationRegistry::liveCount() const noexcept {
		if (!m_Slots) return 0;
		size_t count = 0;
		for (size_t i = 0; i < m_Capacity; i++) {
			if (m_Slots[i].m_State.load(std::memory_order_relaxed) == AllocationState::Live)
				count++;
		}
		return count;
	}

	size_t AllocationRegistry::quarantineCount() const noexcept {
		if (!m_Slots) return 0;
		size_t count = 0;
		for (size_t i = 0; i < m_Capacity; i++) {
			if (m_Slots[i].m_State.load(std::memory_order_relaxed) == AllocationState::Quarantine)
				count++;
		}
		return count;
	}

	float AllocationRegistry::loadFactor() const noexcept {
		if (m_Capacity == 0) return 0.0f;
		return static_cast<float>(m_Count.load(std::memory_order_relaxed))
			/ static_cast<float>(m_Capacity);
	}
}