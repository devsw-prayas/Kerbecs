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
#include "MemoryZone.h"
#include "ShadowUtils.h"

namespace Kerbecs::Shadow::Enhanced {
	typedef MemoryZone::EnhancedShadow* ESHP;

	bool KERBECS poison(ESHP po_EnhancedShadow, size_t v_Offset);
	bool KERBECS unPoison(ESHP po_EnhancedShadow, size_t v_Offset);
	bool KERBECS poisonRange(ESHP po_EnhancedShadow, size_t v_Offset, size_t v_Length);
	bool KERBECS unPoisonRange(ESHP po_EnhancedShadow, size_t v_Offset, size_t v_Length);
	bool KERBECS redzone(ESHP po_EnhancedShadow, size_t v_Offset);
	bool KERBECS deRedzone(ESHP po_EnhancedShadow, size_t v_Offset);
	bool KERBECS redzoneRange(ESHP po_EnhancedShadow, size_t v_Offset, size_t v_Length);
	bool KERBECS deRedzoneRange(ESHP po_EnhancedShadow, size_t v_Offset, size_t v_Length);
	bool KERBECS verifyRedzone(ESHP po_EnhancedShadow);
	bool KERBECS verifyCanaries(ESHP po_EnhancedShadow);
	bool KERBECS tombstone(ESHP po_EnhancedShadow, size_t v_Offset);
	bool KERBECS tombstoneRange(ESHP po_EnhancedShadow, size_t v_Offset, size_t v_Length);
	bool KERBECS initMetadata(ESHP po_EnhancedShadow, size_t v_AllocatorID, size_t v_ThreadID);

	bool KERBECS verifyMetadata(ESHP po_EnhancedShadow, size_t expectedAllocatorID, size_t expectedThreadID, Utils::ThreadPolicy policy);
	bool KERBECS verifyTombstone(ESHP po_EnhancedShadow, size_t v_Offset, size_t v_Length);
	template<typename T>
	Utils::MemoryState KERBECS getMemoryState(ESHP po_EnhancedShadow, size_t v_Idx = 0) {
		if (!po_EnhancedShadow || !po_EnhancedShadow->m_RawPtr) return Utils::MemoryState::CORRUPTED;

		size_t offset = v_Idx * sizeof(T);

		// Shadow poison check
		size_t poisoned = Utils::countShadowPoisons(po_EnhancedShadow, offset, sizeof(T));
		if (poisoned == sizeof(T)) return Utils::MemoryState::UNINITIALIZED;
		if (poisoned > 0 && poisoned < sizeof(T)) return Utils::MemoryState::CORRUPTED;

		// Tombstone check
		if (verifyTombstone(po_EnhancedShadow ,offset, sizeof(T))) return Utils::MemoryState::DESTROYED;

		// Guard checks
		if (!verifyRedzone(po_EnhancedShadow)) return Utils::MemoryState::CORRUPTED;
		if (!verifyCanaries(po_EnhancedShadow)) return Utils::MemoryState::CORRUPTED;

		return Utils::MemoryState::CONSTRUCTED;
	}

	template<typename T>
	Utils::MemoryState KERBECS verifyBlockState(ESHP po_EnhancedShadow, size_t count) {
		for (size_t i = 0; i < count; i++) {
			Utils::MemoryState s = getMemoryState<T>(po_EnhancedShadow, i);
			if (s != Utils::MemoryState::DESTROYED) return s;
		}
		return Utils::MemoryState::DESTROYED;
	}



	template<typename T>
	bool KERBECS init(ESHP po_EnhancedShadow, void* p_Memory, size_t v_BlockSize, size_t count = 1) {
		size_t fullSize = MemoryZone::computeEnhancedShadowHeapSize<T>(count);
		if (v_BlockSize < fullSize) return false;

		size_t payloadSize = count * sizeof(T);
		uintptr_t base = reinterpret_cast<uintptr_t>(p_Memory);

		// --- Leading Metadata ---
		// Start after leading redzone, align for EnhancedMetaData
		uintptr_t unaligned = base + MemoryZone::REDZONE_SIZE;
		uintptr_t aligned = (unaligned + alignof(MemoryZone::EnhancedMetaData) - 1) & ~(alignof(MemoryZone::EnhancedMetaData) - 1);

		po_EnhancedShadow->m_Alignment = alignof(T);
		po_EnhancedShadow->m_Offsets.m_RedzoneOffsetLeading = 0;

		po_EnhancedShadow->m_Offsets.m_MetaDataOffsetLeading = aligned - base;
		po_EnhancedShadow->m_Offsets.m_CanaryOffsetLeading = po_EnhancedShadow->m_Offsets.m_MetaDataOffsetLeading + sizeof(MemoryZone::EnhancedMetaData);

		// --- User Payload ---
		// Start after leading canary, align for T
		unaligned = base + po_EnhancedShadow->m_Offsets.m_CanaryOffsetLeading + MemoryZone::CANARY_SIZE;
		aligned = (unaligned + alignof(T) - 1) & ~(alignof(T) - 1);

		po_EnhancedShadow->m_RawPtr = std::bit_cast<void*>(aligned);
		po_EnhancedShadow->m_Offsets.m_UserDataOffset = aligned - base;
		po_EnhancedShadow->m_Offsets.m_CanaryOffsetTrailing = po_EnhancedShadow->m_Offsets.m_UserDataOffset + payloadSize;

		// --- Init Shadowzone pointer ---
		po_EnhancedShadow->m_ShadowzoneMappingPtr = MemoryZone::mapToShadow(po_EnhancedShadow->m_RawPtr, payloadSize);
		if (!po_EnhancedShadow->m_ShadowzoneMappingPtr) return false;

		// --- Trailing Metadata ---
		// Start after trailing canary, align for EnhancedMetaData
		unaligned = po_EnhancedShadow->m_Offsets.m_CanaryOffsetTrailing + MemoryZone::CANARY_SIZE;
		aligned = (unaligned + alignof(MemoryZone::EnhancedMetaData) - 1) & ~(alignof(MemoryZone::EnhancedMetaData) - 1);

		po_EnhancedShadow->m_Offsets.m_MetaDataOffsetTrailing = aligned - base;
		po_EnhancedShadow->m_Offsets.m_RedzoneOffsetTrailing = po_EnhancedShadow->m_Offsets.m_MetaDataOffsetTrailing + sizeof(MemoryZone::EnhancedMetaData);

		// --- Poison Payload ---
		poisonRange(po_EnhancedShadow, 0, payloadSize);

		// --- Apply Redzones ---
		Utils::rawRedzone(p_Memory,
			0,
			po_EnhancedShadow->m_Offsets.m_MetaDataOffsetLeading);
		Utils::rawRedzone(p_Memory,
			po_EnhancedShadow->m_Offsets.m_RedzoneOffsetTrailing,
			v_BlockSize - po_EnhancedShadow->m_Offsets.m_RedzoneOffsetTrailing);

		// --- Apply Canaries ---
		Utils::rawCanary(p_Memory,
			po_EnhancedShadow->m_Offsets.m_CanaryOffsetLeading,
			po_EnhancedShadow->m_Offsets.m_UserDataOffset - po_EnhancedShadow->m_Offsets.m_CanaryOffsetLeading);
		Utils::rawCanary(p_Memory,
			po_EnhancedShadow->m_Offsets.m_CanaryOffsetTrailing,
			po_EnhancedShadow->m_Offsets.m_MetaDataOffsetTrailing - po_EnhancedShadow->m_Offsets.m_CanaryOffsetTrailing);

		void* loc = static_cast<std::byte*>(p_Memory) + po_EnhancedShadow->m_Offsets.m_MetaDataOffsetLeading;
		::new (loc) MemoryZone::EnhancedMetaData();

		loc = static_cast<std::byte*>(p_Memory) + po_EnhancedShadow->m_Offsets.m_MetaDataOffsetTrailing;
		::new (loc) MemoryZone::EnhancedMetaData();

		po_EnhancedShadow->m_TotalSize = v_BlockSize;
		return true;
	}

	template<typename T, typename...Args>
	bool KERBECS construct(ESHP po_EnhancedShadow, Args&&...u_Args) {
		if (!po_EnhancedShadow) return false;
		::new(po_EnhancedShadow->m_RawPtr) T(std::forward<Args>(u_Args)...);
		return true;
	}

	template<typename T>
	bool KERBECS destroy(
		ESHP po_EnhancedShadow,
		size_t expectedAllocatorID,
		size_t expectedThreadID,
		Utils::ThreadPolicy policy = Utils::ThreadPolicy::Flexible,
		size_t v_Idx = 0) {
		if (!po_EnhancedShadow || !po_EnhancedShadow->m_RawPtr) return false;

		// 1. Metadata check
		if (!verifyMetadata(po_EnhancedShadow, expectedAllocatorID, expectedThreadID, policy)) {
			return false;
		}

		// 2. State resolution
		Utils::MemoryState state = getMemoryState<T>(po_EnhancedShadow, v_Idx);
		if (state == Utils::MemoryState::UNINITIALIZED) return false;
		if (state == Utils::MemoryState::DESTROYED)     return false;
		if (state == Utils::MemoryState::CORRUPTED)     return false;

		// 3. Call destructor
		void* loc = static_cast<std::byte*>(po_EnhancedShadow->m_RawPtr) + v_Idx * sizeof(T);
		static_cast<T*>(loc)->~T();

		// 4. Overwrite + shadow poison
		tombstoneRange(po_EnhancedShadow, v_Idx * sizeof(T), sizeof(T));
		MemoryZone::shadowPoison(static_cast<std::byte*>(po_EnhancedShadow->m_RawPtr) + v_Idx * sizeof(T),sizeof(T));
		return true;
	}

	template<typename T>
	bool KERBECS poisonObject(ESHP po_EnhancedShadow, size_t v_Index = 0) {
		return poisonRange(po_EnhancedShadow, v_Index * sizeof(T), sizeof(T));
	}

	template<typename T>
	bool KERBECS unPoisonObject(ESHP po_EnhancedShadow, size_t v_Index = 0) {
		return unPoisonRange(po_EnhancedShadow, v_Index * sizeof(T), sizeof(T));
	}

	template<typename T>
	bool KERBECS redzoneObject(ESHP po_EnhancedShadow, size_t v_Index) {
		return redzoneRange(po_EnhancedShadow, v_Index * sizeof(T), sizeof(T));
	}

	template<typename T>
	bool KERBECS deRedzoneObject(ESHP po_EnhancedShadow, size_t v_Index) {
		return deRedzoneRange(po_EnhancedShadow, v_Index * sizeof(T), sizeof(T));
	}

	template<typename T>
	bool KERBECS tombstoneObject(ESHP po_EnhancedShadow, size_t v_Index) {
		return tombstoneRange(po_EnhancedShadow, v_Index * sizeof(T), sizeof(T));
	}
}
