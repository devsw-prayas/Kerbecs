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
#include "../../../Corium/src/Public/CoriumAtomics.h"

namespace Kerbecs::Shadow {
	typedef MemoryZone::Shadow* SHP;
	typedef MemoryZone::EnhancedShadow* ESHP;
	enum class KERBECS ShadowMode : uint8_t {
		NORMAL, ENHANCED
	};

	bool KERBECS rawPoison(void* p_Memory, size_t v_Start, size_t v_Length);
	bool KERBECS rawRedzone(void* p_Memory, size_t v_Start, size_t v_Length);
	bool KERBECS rawUnPoison(void* p_Memory, size_t v_Start, size_t v_Length);
	bool KERBECS rawDeRedzone(void* p_Memory, size_t v_Start, size_t v_Length);
	bool KERBECS rawCanary(void* p_Memory, size_t v_Start, size_t v_Length);
	bool KERBECS rawRemoveCanary(void* p_Memory, size_t v_Start, size_t v_Length);
	bool KERBECS rawTombstone(void* p_Memory, size_t v_Start, size_t v_Length);

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

		// --- Offsets (all start markers) ---
		po_Shadow->m_Offsets.m_RedzoneOffsetLeading = 0;              // leading redzone start
		po_Shadow->m_Offsets.m_UserDataOffset = aligned - base; // payload start
		po_Shadow->m_Offsets.m_RedzoneOffsetTrailing = po_Shadow->m_Offsets.m_UserDataOffset + payloadSize;
		po_Shadow->m_Offsets.m_MetaDataOffset =
			(v_BlockSize - sizeof(MemoryZone::NormalMetaData)) & ~(alignof(MemoryZone::NormalMetaData) - 1);

		// --- Poison payload ---
		poisonRange(po_Shadow, 0, payloadSize);

		// --- Apply redzones ---
		rawRedzone(p_Memory,
			po_Shadow->m_Offsets.m_RedzoneOffsetLeading,
			po_Shadow->m_Offsets.m_UserDataOffset - po_Shadow->m_Offsets.m_RedzoneOffsetLeading);

		rawRedzone(p_Memory,
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
	bool KERBECS destroy(SHP po_Shadow) {
		if (!po_Shadow) return false;
		static_cast<T*>(po_Shadow->m_RawPtr)->~T();
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

	bool KERBECS poison(ESHP po_EnhancedShadow, size_t v_Offset);
	bool KERBECS unPoison(ESHP po_EnhancedShadow, size_t v_Offset);
	bool KERBECS poisonRange(ESHP po_EnhancedShadow, size_t v_Offset, size_t v_Length);
	bool KERBECS unPoisonRange(ESHP po_EnhancedShadow, size_t v_Offset, size_t v_Length);
	bool KERBECS redzone(ESHP po_EnhancedShadow, size_t v_Offset);
	bool KERBECS deRedzone(ESHP po_EnhancedShadow, size_t v_Offset);
	bool KERBECS redzoneRange(ESHP po_EnhancedShadow, size_t v_Offset, size_t v_Length);
	bool KERBECS deRedzoneRange(ESHP po_EnhancedShadow, size_t v_Offset, size_t v_Length);
	bool KERBECS verifyRedzone(ESHP po_EnhancedShadow);
	bool KERBECS tombstone(ESHP po_EnhancedShadow, size_t v_Offset);
	bool KERBECS tombstoneRange(ESHP po_EnhancedShadow, size_t v_Offset, size_t v_Length);
	bool KERBECS initMetadata(ESHP po_Shadow, size_t v_AllocatorID, size_t v_ThreadID);

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

		po_EnhancedShadow->m_Offsets.m_UserDataOffset = aligned - base;
		po_EnhancedShadow->m_Offsets.m_CanaryOffsetTrailing = po_EnhancedShadow->m_Offsets.m_UserDataOffset + payloadSize;

		// --- Trailing Metadata ---
		// Start after trailing canary, align for EnhancedMetaData
		unaligned = po_EnhancedShadow->m_Offsets.m_CanaryOffsetTrailing + MemoryZone::CANARY_SIZE;
		aligned = (unaligned + alignof(MemoryZone::EnhancedMetaData) - 1) & ~(alignof(MemoryZone::EnhancedMetaData) - 1);

		po_EnhancedShadow->m_Offsets.m_MetaDataOffsetTrailing = aligned - base;
		po_EnhancedShadow->m_Offsets.m_RedzoneOffsetTrailing = po_EnhancedShadow->m_Offsets.m_MetaDataOffsetTrailing + sizeof(MemoryZone::EnhancedMetaData);

		// --- Poison Payload ---
		poisonRange(po_EnhancedShadow, 0, payloadSize);

		// --- Apply Redzones ---
		rawRedzone(p_Memory,
			0,
			po_EnhancedShadow->m_Offsets.m_MetaDataOffsetLeading);
		rawRedzone(p_Memory,
			po_EnhancedShadow->m_Offsets.m_RedzoneOffsetTrailing,
			v_BlockSize - po_EnhancedShadow->m_Offsets.m_RedzoneOffsetTrailing);

		// --- Apply Canaries ---
		rawCanary(p_Memory,
			po_EnhancedShadow->m_Offsets.m_CanaryOffsetLeading,
			po_EnhancedShadow->m_Offsets.m_UserDataOffset - po_EnhancedShadow->m_Offsets.m_CanaryOffsetLeading);
		rawCanary(p_Memory,
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
	bool KERBECS destroy(ESHP po_EnhancedShadow) {
		if (!po_EnhancedShadow) return false;
		static_cast<T*>(po_EnhancedShadow->m_RawPtr)->~T();
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
