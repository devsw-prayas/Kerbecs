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
#include <memory>

#include "Kerbecs.h"
#include "MemoryZone.h"
#include "ShadowUtils.h"

namespace Kerbecs::Shadow {
	typedef MemoryZone::Shadow* SHP;

	bool KERBECS poison(SHP po_Shadow, size_t v_Offset);
	bool KERBECS unPoison(SHP po_Shadow, size_t v_Offset);
	bool KERBECS poisonRange(SHP po_Shadow, size_t v_Offset, size_t v_Length);
	bool KERBECS unPoisonRange(SHP po_Shadow, size_t v_Offset, size_t v_Length);
	bool KERBECS redzone(SHP po_Shadow, size_t v_Offset);
	bool KERBECS deRedzone(SHP po_Shadow, size_t v_Offset);
	bool KERBECS redzoneRange(SHP po_Shadow, size_t v_Offset, size_t v_Length);
	bool KERBECS deRedzoneRange(SHP po_Shadow, size_t v_Offset, size_t v_Length);
	bool KERBECS verifyRedzone(SHP po_Shadow);
	bool KERBECS tombstone(SHP po_Shadow, size_t v_Offset);
	bool KERBECS tombstoneRange(SHP po_Shadow, size_t v_Offset, size_t v_Length);
	bool KERBECS initMetadata(SHP po_Shadow, size_t v_AllocatorID);
	size_t KERBECS countShadowPoisons(SHP po_Shadow, size_t v_Offset, size_t v_Length);
	bool KERBECS verifyTombstone(SHP po_Shadow, size_t v_Offset, size_t v_Length);

	bool KERBECS verifyMetadata(SHP po_Shadow, size_t v_ExpectedAllocatorID);
	template<typename T>
	Utils::MemoryState KERBECS getMemoryState(SHP po_Shadow, size_t v_Idx = 0) {
		if (!po_Shadow || !po_Shadow->m_RawPtr) return Utils::MemoryState::CORRUPTED;

		size_t offset = v_Idx * sizeof(T);

		// Shadow poison check
		size_t poisoned = countShadowPoisons(po_Shadow, offset, sizeof(T));
		if (poisoned == sizeof(T)) return Utils::MemoryState::UNINITIALIZED;
		if (poisoned > 0 && poisoned < sizeof(T)) return Utils::MemoryState::CORRUPTED;

		// Tombstone check
		if (verifyTombstone(po_Shadow, offset, sizeof(T))) return Utils::MemoryState::DESTROYED;

		// Redzone check
		if (!verifyRedzone(po_Shadow)) return Utils::MemoryState::CORRUPTED;

		return Utils::MemoryState::CONSTRUCTED;
	}

	template<typename T>
	Utils::MemoryState KERBECS verifyBlockState(SHP po_Shadow, size_t count) {
		for (size_t i = 0; i < count; i++) {
			Utils::MemoryState s = getMemoryState<T>(po_Shadow, i);
			if (s != Utils::MemoryState::DESTROYED) return s;
		}
		return Utils::MemoryState::DESTROYED;
	}

	template<typename T>
	bool KERBECS init(SHP po_Shadow, void* p_Memory, size_t v_BlockSize, size_t count = 1) {
		size_t fullSize = MemoryZone::computeShadowHeapSize<T>(count);
		if (v_BlockSize < fullSize) return false; // block too small

		size_t payloadSize = count * sizeof(T);
		uintptr_t base = reinterpret_cast<uintptr_t>(p_Memory);

		// --- Alignment ---
		uintptr_t unaligned = base + MemoryZone::REDZONE_SIZE;
		uintptr_t aligned = (unaligned + alignof(T) - 1) & ~(alignof(T) - 1);

		// --- Payload pointer ---
		po_Shadow->m_Alignment = alignof(T);
		po_Shadow->m_RawPtr = std::bit_cast<void*>(aligned);

		// --- Init Shadowzone pointer ---
		po_Shadow->m_ShadowzoneMappingPtr = MemoryZone::mapToShadow(po_Shadow->m_RawPtr, payloadSize);
		if (!po_Shadow->m_ShadowzoneMappingPtr) return false;

		// --- Offsets (all start markers) ---
		po_Shadow->m_Offsets.m_RedzoneOffsetLeading = 0;              // leading redzone start
		po_Shadow->m_Offsets.m_UserDataOffset = aligned - base; // payload start
		po_Shadow->m_Offsets.m_RedzoneOffsetTrailing = po_Shadow->m_Offsets.m_UserDataOffset + payloadSize;
		po_Shadow->m_Offsets.m_MetaDataOffset =
			(v_BlockSize - sizeof(MemoryZone::NormalMetaData)) & ~(alignof(MemoryZone::NormalMetaData) - 1);

		// --- Poison payload ---
		poisonRange(po_Shadow, 0, payloadSize);

		// --- Apply redzones ---
		Utils::rawRedzone(p_Memory,
			po_Shadow->m_Offsets.m_RedzoneOffsetLeading,
			po_Shadow->m_Offsets.m_UserDataOffset - po_Shadow->m_Offsets.m_RedzoneOffsetLeading);

		Utils::rawRedzone(p_Memory,
			po_Shadow->m_Offsets.m_RedzoneOffsetTrailing,
			MemoryZone::REDZONE_SIZE);

		// --- Init Metadata ---
		void* loc = static_cast<std::byte*>(p_Memory) + po_Shadow->m_Offsets.m_MetaDataOffset;
		::new (loc) MemoryZone::NormalMetaData();

		po_Shadow->m_TotalSize = v_BlockSize;
		return true;
	}

	template<typename T, typename...Args>
	bool KERBECS construct(SHP po_Shadow, Args&&...u_Args) {
		if (!po_Shadow)	return false;
		::new (po_Shadow->m_RawPtr) T(std::forward<Args>(u_Args)...);
		return true;
	}

	template<typename T, typename...Args>
	bool KERBECS construct(SHP po_Shadow, size_t v_Idx, Args&&...u_Args) {
		if (!po_Shadow) return false;
		void* loc = static_cast<T*>(po_Shadow->m_RawPtr) + v_Idx;
		::new (loc) T(std::forward<Args>(u_Args)...);
		return true;
	}

	template<typename T>
	bool KERBECS destroy(SHP po_Shadow, size_t expectedAllocatorID, size_t v_Idx = 0) {
		if (!po_Shadow || !po_Shadow->m_RawPtr) return false;

		// 1. Metadata check
		if (!verifyMetadata(po_Shadow, expectedAllocatorID)) return false;

		// 2. State resolution
		Utils::MemoryState state = getMemoryState<T>(po_Shadow, v_Idx);
		if (state == Utils::MemoryState::UNINITIALIZED) return false; // never constructed
		if (state == Utils::MemoryState::DESTROYED)     return false; // double free
		if (state == Utils::MemoryState::CORRUPTED)     return false; // invalid/corrupted

		// 3. Call destructor
		void* loc = static_cast<std::byte*>(po_Shadow->m_RawPtr) + v_Idx * sizeof(T);
		static_cast<T*>(loc)->~T();

		// 4. Overwrite + shadow poison
		tombstoneRange(po_Shadow, v_Idx * sizeof(T), sizeof(T));
		MemoryZone::shadowPoison(static_cast<std::byte*>(po_Shadow->m_RawPtr) + v_Idx * sizeof(T), sizeof(T));
		return true;
	}

	template<typename T>
	bool KERBECS poisonObject(SHP po_Shadow, size_t v_Index = 0) {
		return poisonRange(po_Shadow, v_Index * sizeof(T), sizeof(T));
	}

	template<typename T>
	bool KERBECS unPoisonObject(SHP po_Shadow, size_t v_Index = 0) {
		return unPoisonRange(po_Shadow, v_Index * sizeof(T), sizeof(T));
	}

	template<typename T>
	bool KERBECS redzoneObject(SHP po_Shadow, size_t v_Index) {
		return redzoneRange(po_Shadow, v_Index * sizeof(T), sizeof(T));
	}

	template<typename T>
	bool KERBECS deRedzoneObject(SHP po_Shadow, size_t v_Index) {
		return deRedzoneRange(po_Shadow, v_Index * sizeof(T), sizeof(T));
	}

	template<typename T>
	bool KERBECS tombstoneObject(SHP po_Shadow, size_t v_Index) {
		return tombstoneRange(po_Shadow, v_Index * sizeof(T), sizeof(T));
	}
}
