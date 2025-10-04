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

namespace Kerbecs::MemoryZone {

	typedef void* RAW;

	constexpr uintptr_t MEMORY_ZONE_ADDRESS = 0x0000100000000000; //Preferred by Kerbecs
	constexpr size_t POISON_NON_HEAP = 0xfa;
	constexpr size_t POISON_HEAP = 0xfb;
	constexpr size_t UNPOISONED_NON_HEAP = 0x0a;
	constexpr size_t UNPOISONED_HEAP = 0x0b;
	constexpr size_t REDZONE = 0xfe;
	constexpr size_t TOMBSTONE = 0xdd;
	constexpr size_t GUARD_CANARY = 0xdead;

	// [Size in Bytes]: 32
	struct NormalMetaData final {
		size_t m_TotalSize;
		size_t m_TotalCommitted;
		size_t m_TotalPoisoned;
		size_t m_AllocatorHash;
	};

	// [Size in Bytes]: 48
	struct EnhancedMetaData final {
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

		[[nodiscard]] bool init();
	};

	// [Size in Bytes]: 32
	struct NormalOffsets {
		size_t m_RedzoneOffsetLeading;
		size_t m_UserDataOffset;
		size_t m_RedzoneOffsetTrailing;
		size_t m_MetaDataOffset;
	};

	// [Size in Bytes]: 56
	struct EnhancedOffsets {
		size_t m_RedzoneOffsetLeading;
		size_t m_MetaDataOffsetLeading;
		size_t m_CanaryOffsetLeading;
		size_t m_UserDataOffset;
		size_t m_CanaryOffsetTrailing;
		size_t m_MetaDataOffsetTrailing;
		size_t m_RedzoneOffsetTrailing;
	};

	// [Size in Bytes]: 56 
	struct Shadow final {
		RAW m_RawPtr;
		RAW m_ShadowzoneMappingPtr;
		size_t m_Alignment;
		NormalOffsets m_Offsets;
	};

	// [Size in Bytes]: 80
	struct EnhancedShadow final {
		RAW m_RawPtr;
		RAW m_ShadowzoneMappingPtr;
		size_t m_Alignment;
		EnhancedOffsets m_Offsets;
	};

	inline KERBECS KerbecsMemoryZone& instance() {
		static KerbecsMemoryZone instance;
		return instance;
	}

	template<size_t Alignment>
	void initializeShadow(Shadow& ro_Shadow) {
		ro_Shadow.m_Alignment = Alignment;
		ro_Shadow.m_Offsets.m_MetaDataOffset = 0;
		ro_Shadow.m_Offsets.m_RedzoneOffsetLeading = 0;6
		ro_Shadow.m_Offsets.m_RedzoneOffsetTrailing = 0;
		ro_Shadow.m_Offsets.m_UserDataOffset = 0;
		ro_Shadow.m_ShadowzoneMappingPtr = nullptr;
		ro_Shadow.m_RawPtr = nullptr;
	}

	template<size_t Alignment>
	void initializeEnhancedShadow(EnhancedShadow& ro_EnhancedShadow) {
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
}
