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
#include <cstdint>
#include "Kerbecs.h"
#include "Memory.h"

namespace Kerbecs::MemoryZone {
	typedef void* RAW;

	constexpr uintptr_t MEMORY_ZONE_ADDRESS = 0x0000100000000000; //Preferred by Kerbecs
	constexpr size_t POISONED = 0xfa;
	constexpr size_t UNPOISONED = 0x0a;
	constexpr size_t REDZONE = 0xfe;
	constexpr size_t TOMBSTONE = 0xdd;
	constexpr size_t GUARD_CANARY = 0xDEADBEEFCAFEBABEULL;
	constexpr size_t SHADOW_SCALE = 3;

	constexpr size_t REDZONE_SIZE = 16;
	constexpr size_t CANARY_SIZE = 8;

	constexpr size_t MASK_1 = 1;
	constexpr size_t MASK_2 = MASK_1 << 1;
	constexpr size_t MASK_4 = MASK_1 << 2;
	constexpr size_t MASK_8 = MASK_1 << 3;
	constexpr size_t MASK_16 = MASK_1 << 4;
	constexpr size_t MASK_32 = MASK_1 << 5;
	constexpr size_t MASK_64 = MASK_1 << 6;
	constexpr size_t MASK_128 = MASK_1 << 7;

	// [Size in Bytes]: 32
	struct KERBECS alignas(32) NormalMetaData final {
		size_t m_TotalSize;
		size_t m_TotalCommitted;
		size_t m_TotalPoisoned;
		size_t m_AllocatorHash;
	};

	// [Size in Bytes]: 48
	struct KERBECS alignas(64) EnhancedMetaData final {
		size_t m_TotalSize;
		size_t m_TotalCommitted;
		size_t m_TotalPoisoned;
		size_t m_AllocatorHash;
		size_t m_ThreadHash;
		size_t m_Checksum;
	};

	// [Size in Bytes]: 25
	struct KERBECS KerbecsMemoryZone final {
		void* m_MemoryZone;
		void* m_ShadowZone;
		void* m_GlobalZone;
		bool m_Initialized;
		bool m_Shutdown;

		[[nodiscard]] bool init();
	};

	// [Size in Bytes]: 32
	struct KERBECS alignas(32) NormalOffsets {
		size_t m_RedzoneOffsetLeading;
		size_t m_UserDataOffset;
		size_t m_RedzoneOffsetTrailing;
		size_t m_MetaDataOffset;
	};

	// [Size in Bytes]: 56
	struct KERBECS alignas(64) EnhancedOffsets {
		size_t m_RedzoneOffsetLeading;
		size_t m_MetaDataOffsetLeading;
		size_t m_CanaryOffsetLeading;
		size_t m_UserDataOffset;
		size_t m_CanaryOffsetTrailing;
		size_t m_MetaDataOffsetTrailing;
		size_t m_RedzoneOffsetTrailing;
	};

	// [Size in Bytes]: 64
	struct KERBECS alignas(64) Shadow final {
		RAW m_RawPtr;
		RAW m_ShadowzoneMappingPtr;
		size_t m_Alignment;
		NormalOffsets m_Offsets;
		size_t m_TotalSize;
	};

	// [Size in Bytes]: 88
	struct KERBECS alignas(128) EnhancedShadow final {
		RAW m_RawPtr;
		RAW m_ShadowzoneMappingPtr;
		size_t m_Alignment;
		EnhancedOffsets m_Offsets;
		size_t m_TotalSize;
	};

	inline KERBECS KerbecsMemoryZone& instance() {
		static KerbecsMemoryZone instance;
		return instance;
	}

	template<size_t Alignment>
	void KERBECS initializeShadow(Shadow& ro_Shadow) {
		ro_Shadow.m_Alignment = Alignment;
		ro_Shadow.m_Offsets.m_MetaDataOffset = 0;
		ro_Shadow.m_Offsets.m_RedzoneOffsetLeading = 0;
		ro_Shadow.m_Offsets.m_RedzoneOffsetTrailing = 0;
		ro_Shadow.m_Offsets.m_UserDataOffset = 0;
		ro_Shadow.m_ShadowzoneMappingPtr = nullptr;
		ro_Shadow.m_RawPtr = nullptr;
	}

	template<size_t Alignment>
	void KERBECS initializeEnhancedShadow(EnhancedShadow& ro_EnhancedShadow) {
		ro_EnhancedShadow.m_Alignment = Alignment;
		ro_EnhancedShadow.m_Offsets.m_RedzoneOffsetTrailing = 0;
		ro_EnhancedShadow.m_Offsets.m_CanaryOffsetLeading = 0;
		ro_EnhancedShadow.m_Offsets.m_CanaryOffsetTrailing = 0;
		ro_EnhancedShadow.m_Offsets.m_MetaDataOffsetLeading = 0;
		ro_EnhancedShadow.m_Offsets.m_MetaDataOffsetTrailing = 0;
		ro_EnhancedShadow.m_Offsets.m_RedzoneOffsetLeading = 0;
		ro_EnhancedShadow.m_Offsets.m_UserDataOffset = 0;
		ro_EnhancedShadow.m_RawPtr = nullptr;
		ro_EnhancedShadow.m_ShadowzoneMappingPtr = nullptr;
	}

	template<typename T>
	size_t KERBECS computeShadowHeapSize(size_t v_Payload) {
		return REDZONE_SIZE          // leading redzone
			+ v_Payload              // user payload
			+ (alignof(T) - 1)       // alignment slop
			+ REDZONE_SIZE           // trailing redzone
			+ sizeof(NormalMetaData)
			+ alignof(NormalMetaData) - 1;
	}

	template<typename T>
	size_t KERBECS computeEnhancedShadowHeapSize(size_t v_Payload) {
		return REDZONE_SIZE               // leading redzone
			+ sizeof(EnhancedMetaData)    // leading metadata
			+ CANARY_SIZE                 // leading canary (qword)
			+ v_Payload                   // user payload
			+ (alignof(T) - 1)            // alignment slop
			+ CANARY_SIZE                 // trailing canary
			+ sizeof(EnhancedMetaData)    // trailing metadata
			+ alignof(EnhancedMetaData) - 1 // alignment slop
			+ REDZONE_SIZE;		          // trailing redzone
	}

	inline uint64_t splitMix64(uint64_t v_Input) noexcept {
		v_Input += 0x9e3779b97f4a7c15ULL;
		v_Input = (v_Input ^ (v_Input >> 30)) * 0xbf58476d1ce4e5b9ULL;
		v_Input = (v_Input ^ (v_Input >> 27)) * 0x94d049bb133111ebULL;
		return v_Input ^ (v_Input >> 31);
	}

	KERBECS void* mapToShadow(void* p_User, size_t v_Size) noexcept;

	struct KERBECS UserRange final {
		void* start;
		void* end; // inclusive
	};

	KERBECS UserRange mapToUser(void* p_Shadow) noexcept;
	KERBECS bool shadowPoison(void* userPtr, size_t size);
	KERBECS bool shadowUnpoison(void* userPtr, size_t size);

	inline bool KERBECS initShadowzone() {
		return instance().init();
	}

	inline bool KERBECS teardownShadowzone() {
		auto& zone = instance();
		if (zone.m_Shutdown) return false;

		Memory::release(zone.m_MemoryZone, (SHADOWZONE_SIZE + GLOBALZONE_SIZE) * Memory::GIBI_BYTE);

		zone.m_MemoryZone = nullptr;
		zone.m_ShadowZone = nullptr;
		zone.m_GlobalZone = nullptr;
		zone.m_Initialized = false;
		zone.m_Shutdown = true;									 

		return true;
	}
}
