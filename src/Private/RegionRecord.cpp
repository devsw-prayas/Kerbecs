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
#include "RegionRecord.h"
#include "KerbecsDiagnostics.h"
#include "KerbecsMemory.h"

#ifndef REGION_TABLE_CAPACITY
#error "REGION_TABLE_CAPACITY must be defined (see common/Kerbecs/CMakeLists.txt)"
#endif

namespace Kerbecs::Tracing {

	namespace {
		RegionRecord* s_Records = nullptr;
		std::atomic<size_t> s_Count{ 0 };
		Internal::SpinLock s_RegisterLock;
	}

	bool initRegionTable() noexcept {
		if (s_Records)
			return true;

		s_Records = static_cast<RegionRecord*>(
			Memory::allocate(REGION_TABLE_CAPACITY * sizeof(RegionRecord)));

		if (!s_Records)
			return false;

		std::memset(s_Records, 0, REGION_TABLE_CAPACITY * sizeof(RegionRecord));
		s_Count.store(0, std::memory_order_relaxed);
		return true;
	}

	void shutdownRegionTable() noexcept {
		if (s_Records) {
			KERBECS_UNUSED(Memory::release(
				s_Records,
				REGION_TABLE_CAPACITY * sizeof(RegionRecord)));
			s_Records = nullptr;
		}
		s_Count.store(0, std::memory_order_relaxed);
	}

	bool registerRegionRecord(
		void* p_Region,
		void* p_ShadowMapBase,
		void* p_MetadataMapBase,
		void* p_RegionBase,
		size_t v_RegionSize) noexcept {
		if (!s_Records || !p_Region)
			return false;

		s_RegisterLock.lock();

		const size_t idx = s_Count.load(std::memory_order_relaxed);
		if (idx >= REGION_TABLE_CAPACITY) {
			s_RegisterLock.unlock();
			KERBECS_ASSERT(false && "Region-lookup table exhausted - raise KERBECS_REGION_TABLE_CAPACITY");
			return false;
		}

		RegionRecord& rec = s_Records[idx];
		rec.m_RegionPtr = p_Region;
		rec.m_ShadowMapBase = p_ShadowMapBase;
		rec.m_MetadataMapBase = p_MetadataMapBase;
		rec.m_RegionBase = p_RegionBase;
		rec.m_RegionSize = v_RegionSize;

		// Published last, with release - resolveRegion's relaxed read of
		// s_Count only ever observes fully-populated records.
		s_Count.store(idx + 1, std::memory_order_release);

		s_RegisterLock.unlock();
		return true;
	}

	const RegionRecord* resolveRegion(const void* p_Address) noexcept {
		if (!s_Records || !p_Address)
			return nullptr;

		const uintptr_t addr = reinterpret_cast<uintptr_t>(p_Address);
		const size_t count = s_Count.load(std::memory_order_acquire);

		for (size_t i = 0; i < count; ++i) {
			const RegionRecord& rec = s_Records[i];
			if (!rec.m_RegionBase) continue;

			const uintptr_t base = reinterpret_cast<uintptr_t>(rec.m_RegionBase);
			if (addr >= base && (addr - base) < rec.m_RegionSize)
				return &rec;
		}

		return nullptr;
	}
}
